"""Event-driven AVSS with CHECKED over reliable broadcast.

Output does not stop this service. The caller owns cancellation.
"""
import asyncio
import pickle
from collections import defaultdict
from functools import partial
from pypairing import ZR
from GoSSamer.util.misc import subscribe_recv, wrap_send
from .bdecs import BDECS, canonical, MODULUS
from .broadcast import broadcast
from .privsend_adapter import PrivSend
from .recovery import Recovery


class AVSS:
    def __init__(self, parameters, sid, dealer, node, send, recv, record=None):
        self.p, self.sid, self.dealer, self.node = parameters, sid, dealer, node
        self.b = BDECS(parameters, sid, dealer)
        self.send = send
        self.record = record or (lambda *args: None)
        self.events = asyncio.Queue()
        self.output_queue = asyncio.Queue()
        self.tasks, self.priv = [], {}
        self.checked_senders = defaultdict(set)
        self.parts = defaultdict(dict)
        self.parts_sent = False
        self.com = self.opening = self.digest = self.com_id = self.local = None
        self.checked = self.output = False
        self.complaint = self.rec1_sent = self.rec2_sent = False
        self.accuse_recipients = None
        self.dispersed = set()
        self.delivered = {}
        self.delivery_checks = {}
        self.early_rec1, self.early_rec2 = {}, {}
        self.early_reveal = {}
        self.recovery = None
        self.shares = None
        self.frozen_targets = None
        self.recovery_targets = {}
        self.dealer_openings = {}
        self.checked_input = asyncio.Future()
        self.batch_input = asyncio.Future()
        self.router_task, self.subscribe = subscribe_recv(recv)
        self.tasks.append(self.router_task)
        self.broadcast = partial(broadcast, sid, parameters, node, send=send,
                                 subscribe=self.subscribe, events=self.events)

    def _send_data(self, destination, message):
        self.send(destination, ('DATA', (self.sid, self.dealer, message)))

    async def _data(self):
        receive = self.subscribe('DATA')
        while True:
            sender, outer = await receive()
            if isinstance(outer, (list, tuple)) and len(outer) == 3 and tuple(outer[:2]) == (self.sid, self.dealer):
                self.events.put_nowait(('DATA', sender, outer[2]))

    async def run(self, values=None):
        for leader in range(self.p.n):
            self.tasks.append(asyncio.create_task(self.broadcast('CHECKED', leader, self.checked_input)))
        self.tasks.append(asyncio.create_task(self.broadcast('BATCH', self.dealer, self.batch_input)))
        self.tasks.append(asyncio.create_task(self._data()))
        self._share(values)
        while True:
            kind, sender, payload = await self.events.get()
            if kind == 'CHECKED':
                self.checked_senders[payload].add(sender)
            elif kind == 'BATCH':
                self._start_privsend(payload)
            elif kind == 'PRIV':
                action, instance, target, content = payload
                d, q = instance[2], instance[3]
                if action == 'Dispersed':
                    for k in target:
                        self.dispersed.add((d, k, q))
                elif action == 'Delivered':
                    self.delivered[(d, q)] = content
                    self.delivery_checks.pop((d, q), None)
                elif action == 'Reveal':
                    self.early_reveal[(d, target, q)] = content
            elif kind == 'DATA':
                self._message(sender, payload)
            self._advance()

    def _share(self, values):
        if self.node != self.dealer:
            return
        com, self.key = self.b.commit(self.b.pack(values))
        for k in range(self.p.n):
            self._send_data(k, ('SHARE', com, self._dealer_opening(k)))

    def _dealer_opening(self, target):
        # Reuse a column across SHARE and all t+1 private point deliveries.
        if target not in self.dealer_openings:
            self.dealer_openings[target] = self.b.poly_open(target + 1, self.key)
        return self.dealer_openings[target]

    def _start_privsend(self, payload):
        d, targets = pickle.loads(payload)
        # Every node obtains the same target set from the dealer's BATCH RBC.
        self.recovery_targets[d] = targets
        for q in range(1, self.p.t + 2):
            instance = (self.sid, self.dealer, d, q, targets)
            if instance in self.priv:
                continue
            send = wrap_send(('PRIVSEND', instance), self.send)
            recv = self.subscribe(('PRIVSEND', instance))
            adapter = PrivSend(instance, self.p.n, self.p.t, self.node, self.dealer,
                targets, send, recv, lambda event: self.events.put_nowait(('PRIV', -1, event)))
            messages = None
            if self.node == self.dealer:
                messages = {}
                for k in targets:
                    m, f, m0 = self.b.point_from_opening(self._dealer_opening(k), q)
                    messages[k] = (f, m, m0)
            self.priv[instance] = adapter
            if self.node == self.dealer:
                self.record('privsend_layout', self.node, dict(adapter.layout_stats, q=q,
                    targets=list(targets)))
            adapter.start(messages)

    def _message(self, sender, msg):
        if not 0 <= sender < self.p.n or not isinstance(msg, (tuple, list)) or not msg:
            return
        try:
            if msg[0] == 'SHARE' and sender == self.dealer and self.opening is None:
                _, com, opening = msg
                if self.b.poly_verify(com, self.node + 1, opening):
                    self.com, self.opening = com, opening
                    self.digest = self.b.commitment_id(com)
                    self.checked_input.set_result(self.digest)
            elif msg[0] == 'PART':
                _, d, dest, local = msg
                if dest == self.node and sender != self.node and isinstance(d, bytes) and len(d) == 32 and self.b.local_valid(local, self.node + 1):
                    self.parts[d][sender] = local
            elif msg[0] == 'REC1':
                _, d, dest, f, m, m0 = msg
                if (dest == self.node and self.b.vector(f, self.p.l) and self.b.vector(m, self.p.r)
                        and self.b.vector((m0,), 1)):
                    self.early_rec1[(d, sender)] = (f, m, m0)
            elif msg[0] == 'REC2':
                _, d, dest, f = msg
                if dest == self.node and self.b.vector(f, self.p.l):
                    self.early_rec2.setdefault((d, sender), f)
        except (ValueError, TypeError, IndexError):
            return

    def _valid_point(self, local, q, k, payload):
        return (isinstance(payload, (tuple, list)) and len(payload) == 3
                and self.b.local_point_verify(local, q, k + 1, payload[1], payload[0], payload[2]))

    def _advance(self):
        if self.com_id is None:
            for d, senders in self.checked_senders.items():
                if len(senders) >= self.p.n - self.p.t:
                    self.com_id = d
                    break
        d = self.com_id
        if d is None:
            return
        self._send_missing_parts(d)
        if self.node == self.dealer and self.frozen_targets is None:
            self.frozen_targets = tuple(k for k in range(self.p.n) if k not in self.checked_senders[d])
            if self.frozen_targets:
                self.batch_input.set_result(pickle.dumps((d, self.frozen_targets)))
        self._accept_commitment(d)
        if self.recovery is None:
            return
        self._check_delivery(d)
        if not all(k in self.checked_senders[d] or all(
                (d, k, q) in self.dispersed for q in range(1, self.p.t + 2))
                for k in range(self.p.n)):
            return
        if self.checked and not self.output:
            self._output(self.shares)
        self._advance_recovery(d)

    def _send_missing_parts(self, d):
        # Rechecked on every event: the full opening may arrive after CHECKED.
        # An honest node without a full commitment never sends CHECKED, so it
        # remains a target in every holder's local view. No dealer list needed.
        if (self.parts_sent or self.digest != d
                or len(self.checked_senders[d]) < self.p.n - self.p.t):
            return
        self.parts_sent = True
        for j in range(self.p.n):
            if j != self.node and j not in self.checked_senders[d]:
                self._send_data(j, ('PART', d, j,
                    self.b.extract_local_commitment(self.com, j + 1)))

    def _accept_commitment(self, d):
        if self.recovery is not None:
            return
        if self.digest == d:
            self.local = self.b.extract_local_commitment(self.com, self.node + 1)
        else:
            groups = defaultdict(list)
            for sender, local in self.parts[d].items():
                if sender in self.checked_senders[d]:
                    groups[canonical(local)].append(local)
            for matching_parts in groups.values():
                if len(matching_parts) >= self.p.t + 1:
                    self.local = matching_parts[0]
                    break
        if self.local is not None:
            self.recovery = Recovery(self.b, self.node + 1, self.local)

    def _check_delivery(self, d):
        if self.checked:
            return
        if self.digest == d:
            self.shares = tuple(int(self.b.poly(list(c))(ZR(q))) for c in self.opening[1]
                                for q in range(1, self.p.t + 2))
            self.checked = True
            return

        good = {}
        for q in range(1, self.p.t + 2):
            if (d, q) not in self.delivered:
                continue
            payload = self.delivered[(d, q)]
            if self._delivery_valid(d, q, payload):
                good[q] = payload[0]
            else:
                self._accuse(d, q)
        if len(good) == self.p.t + 1:
            self.shares = tuple(good[q][a] for a in range(self.p.l)
                                for q in range(1, self.p.t + 2))
            self.checked = True

    def _accuse(self, d, q):
        if self.complaint:
            return
        # Freeze 2t+1 confirmed holders; at least t+1 can supply honest REC1 points.
        candidates = sorted(self.checked_senders[d])
        if len(candidates) < 2 * self.p.t + 1:
            return
        self.accuse_recipients = tuple(candidates[:2 * self.p.t + 1])
        self.complaint = True
        for instance, adapter in self.priv.items():
            if instance[2] == d and instance[3] == q and self.node in instance[4]:
                for j in self.accuse_recipients:
                    adapter.reveal(j)
        self.record('accuse', self.node, {'q': q,
                    'recipients': list(self.accuse_recipients)})

    def _delivery_valid(self, d, q, payload):
        # A damaged recipient stays unchecked during recovery. Unrelated
        # events must not reverify the same authenticated private points.
        # Delivered events invalidate even the same object; retaining object
        # references also detects replacement by callers before the next event.
        if self.local is None:
            return self._valid_point(self.local, q, self.node, payload)
        cached = self.delivery_checks.get((d, q))
        if cached is None or cached[0] is not self.local or cached[1] is not payload:
            cached = (self.local, payload, self._valid_point(self.local, q, self.node, payload))
            self.delivery_checks[(d, q)] = cached
        return cached[2]

    def _advance_recovery(self, d):
        if self.digest == d and not self.rec1_sent:
            for (dd, target, q), payload in self.early_reveal.items():
                if dd != d:
                    continue
                local = self.b.extract_local_commitment(self.com, target + 1)
                if not self._valid_point(local, q, target, payload):
                    self.record('valid_accuse', self.node, {'target': target, 'q': q})
                    self.rec1_sent = True
                    for j in range(self.p.n):
                        m, f, m0 = self.b.point_from_opening(self.opening, j + 1)
                        self._send_data(j, ('REC1', d, j, f, m, m0))
                    break
        for (dd, sender), (f, m, m0) in self.early_rec1.items():
            if dd == d and self.recovery.add_rec1(sender, f, m, m0):
                self.record('rec1_valid', self.node, {'sender': sender})
        if (self.recovery.row is not None and not self.rec2_sent
                and d in self.recovery_targets):
            self.rec2_sent = True
            for j in self.recovery_targets[d]:
                f = tuple(int(p(ZR(j + 1))) for p in self.recovery.row)
                self._send_data(j, ('REC2', d, j, f))
                self.record('rec2_sent', self.node, {'target': j})
        for key, f in list(self.early_rec2.items()):
            dd, sender = key
            if dd == d:
                del self.early_rec2[key]
                result = self.recovery.add_rec2(sender, f)
                if result is not None:
                    self.record('oec_success', self.node, {'support': self.recovery.support,
                                'inputs': len(self.recovery.rec2)})
                    if not self.output:
                        self._output(tuple(int(p(ZR(q))) for p in result for q in range(1, self.p.t + 2)))

    def _output(self, shares):
        self.output = True
        self.record('output', self.node, {})
        self.output_queue.put_nowait(tuple(shares))

    async def close(self):
        for adapter in self.priv.values():
            await adapter.close()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
