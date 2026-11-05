"""Target-only PrivSend over the shared n-member SMD engine.

Each q has one batch and only its target ciphertexts. Committee members keep
and authenticate erasure-code strips; non-targets receive no private output.
"""
import asyncio
from pypairing import ZR
from GoSSamer.distribute.smd_batch_rust_lk import SMD_SS24


class PrivSend:
    def __init__(self, sid, n, t, node, dealer, targets, send, recv, event):
        self.sid, self.n, self.t = sid, n, t
        self.node, self.dealer = node, dealer
        self.targets = tuple(targets)
        if (not self.targets or tuple(sorted(set(targets))) != self.targets
                or any(type(k) is not int or not 0 <= k < n for k in targets)):
            raise ValueError('invalid target set')
        self.send, self.recv, self.event = send, recv, event
        self.smd_queue = asyncio.Queue()
        self.smd = SMD_SS24(sid, n, t, node, dealer, None,
            lambda dest, msg: send(dest, ('SMD', msg)), self.smd_queue.get, ZR,
            list(range(n)), batch_count=1, target_ids=self.targets)
        self.layout_stats = dict(self.smd.layout_stats, placeholder_slots=0,
                                 point_items=len(self.targets))
        self.tasks = []
        self.roots = None
        self.roots_ready = asyncio.Event()
        self.dispersed = self.delivered = False
        self.revealed = set()
        self.pending = {}

    def start(self, messages=None):
        data = None
        if self.node == self.dealer:
            if messages is None or set(messages) != set(self.targets):
                raise ValueError('target payloads mismatch')
            data = [[('BDECS-PAYLOAD-v1', self.sid, self.targets, k, messages[k])
                     for k in self.targets]]
        self.tasks = [asyncio.create_task(self.smd.distribute(data)),
                      asyncio.create_task(self._watch_output()),
                      asyncio.create_task(self._run()),
                      asyncio.create_task(self._watch_available())]

    async def _watch_available(self):
        await self.smd.available.wait()
        self.roots = self.smd.available_roots
        self.roots_ready.set()
        self.dispersed = True
        self.event(('Dispersed', self.sid, self.targets, self.roots))
        for sender, proof in self.pending.items():
            self._reveal_received(sender, proof)
        self.pending.clear()

    async def _watch_output(self):
        if self.node not in self.targets:
            return
        await self.smd.output_flag.wait()
        await self.roots_ready.wait()
        raw, _ = self.smd.output_queue[0]
        self.delivered = True
        self.event(('Delivered', self.sid, self.node, self._parse(raw, self.node)))

    def _parse(self, raw, target):
        if (isinstance(raw, (tuple, list)) and len(raw) == 5
                and tuple(raw[:4]) == ('BDECS-PAYLOAD-v1', self.sid, self.targets, target)):
            return raw[4]
        return None

    def reveal(self, destination):
        if not self.delivered or self.node not in self.targets:
            raise ValueError('Reveal requires private delivery to this target')
        self.send(destination, ('REVEAL', self.smd.export_target_proof(0)))

    def _reveal_received(self, sender, proof):
        if sender not in self.targets or sender in self.revealed:
            return
        if self.roots is None:
            self.pending[sender] = proof
            return
        authenticated, raw = self.smd.verify_target_proof(proof, sender, 0, self.roots)
        if not authenticated:
            return
        self.revealed.add(sender)
        self.event(('Reveal', self.sid, sender, self._parse(raw, sender)))

    async def _run(self):
        while True:
            sender, message = await self.recv()
            if not 0 <= sender < self.n or not isinstance(message, (tuple, list)) or len(message) != 2:
                continue
            kind, payload = message
            if kind == 'SMD':
                self.smd_queue.put_nowait((sender, payload))
            elif kind == 'REVEAL':
                self._reveal_received(sender, payload)

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
