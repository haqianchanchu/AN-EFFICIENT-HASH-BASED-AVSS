import asyncio
from collections import defaultdict
import re
from GoSSamer.crypto.polynomial import polynomials_over, get_omega
from GoSSamer.crypto.polynomial_bi import polynomials_over_bi
from GoSSamer.crypto.symmetric_crypto import SymmetricCrypto
from GoSSamer.util.misc import wrap_send, subscribe_recv
from GoSSamer.distribute.smd_ss24 import SMD_SS24
from GoSSamer.distribute.optqrbc import optqrbc
from GoSSamer.util.serilization import Serial
from GoSSamer.distribute.encode import encode, decode, merkle_tree, get_merkle_branch, hash, merkle_verify, hash_to_field
from GoSSamer.distribute.tylerba import tylerba
import logging
import time
from math import ceil
import numpy as np
from GoSSamer.util.misc import print_exception_callback
from GoSSamer.util.bitmap import Bitmap


from comparisons.protocols.GoSSamer_acss_rust_optimizedealer import Gossamer_acss, BadDealer
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)

class ADKGMsgType:
    ACSS = "ACSS"
    RBC = "RBC"
    ABA = "ABA"
    PREKEY = "P"
    KEY = "K"
    SEED = "S"
    SCRIPTSHARE = "SCS"
    SCRIPT = "SC"
    H = "H"

class Gossamer_dpss:
    def __init__(self, old_committee, new_committee, my_id, send, recv, field, batch_size, high_threshold=None, fault=False):
        #init
        self.old_com, self.new_com, self.my_id = old_committee, new_committee, my_id
        self.batch_size = batch_size
        self.batch_size_rand = ceil(batch_size / (len(self.old_com['ids']) - (2 * self.old_com['t'])))
        self.batch_size_rand_pad = self.batch_size_rand + 1 + ((self.batch_size_rand + 1) % (self.old_com['t'] + 1))
    
        
        self.sessionvars = {}

        self.field = field
        self.shares = None

        self.serial = Serial(self.field)

        self.poly = polynomials_over(self.field)

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        print(1)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send


        if my_id in new_committee['ids']:
            self.output_queue = asyncio.Queue()
            self.acss_outputs = {}
            self.acss_signal = asyncio.Event()

        if my_id in old_committee['ids']:
            self.output_signal = asyncio.Event()
            

        self.logger = logging.LoggerAdapter(
            logging.getLogger(f'In DPSS: Node-[{self.my_id}]'), {'prefix': f'Node-[{self.my_id}]'}
        )
        self.logger.setLevel(logging.INFO)

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        self.acss_tasks = []
        self.tasks = []

        self.logger.debug(f"batch size = {self.batch_size}, batch_size_rand={self.batch_size_rand}, self.batch_size_rand_pad={self.batch_size_rand_pad}")

        self.high_threshold = high_threshold

        self.fault = fault




    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self
    
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.task.cancel()
        except Exception:
            logging.info("ADPSS task finished")
        
    

    async def derive_key(self, acss_outputs, acss_signal, rbc_values, rbc_signal, com):
        await rbc_signal.wait()
        rbc_signal.clear()

        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= com['n'] - com['t']:
                    break

        for id in self.mks:
            while id not in acss_outputs.keys():
                await acss_signal.wait()
                acss_signal.clear()
        
        return self.mks
    
    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in, aba_out, com):
        assert len(rbc_out) == self.old_com['n'] + self.new_com['n']
        assert len(aba_in) == self.old_com['n'] + self.new_com['n']
        assert len(aba_out) == self.old_com['n'] + self.new_com['n']

        aba_inputted = [False]*(self.old_com['n'] + self.new_com['n'])
        aba_values = [0]*(self.old_com['n'] + self.new_com['n'])

        async def _recv_rbc(j):
            # rbc_values[j] = await rbc_out[j]
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.old_com['n'] + self.new_com['n'], rbcl)
            rbc_values[j] = []
            for i in com['ids']:
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
                    
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in com['ids']]
        

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in com['ids']:
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in com['ids']])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in com['ids']:
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        rbc_signal.set()
    
    async def agreement(self, key_proposal, acss_outputs, acss_signal, com):
        n_2com = self.old_com['n'] + self.new_com['n']
        aba_inputs = [asyncio.Queue() for _ in range(n_2com)]
        aba_outputs = [asyncio.Queue() for _ in range(n_2com)]
        rbc_outputs = [asyncio.Queue() for _ in range(n_2com)]
        
        coin_keys = [asyncio.Queue() for _ in range(n_2com)]

        async def predicate(_key_proposal):
            kp = Bitmap(self.old_com['n'] + self.new_com['n'], _key_proposal)
            kpl = []
            for ii in com['ids']:
                if kp.get_bit(ii):
                    kpl.append(ii)
            if len(kpl) < com['n'] - com['t']:
                return False
        
            while True:
                subset = True
                for kk in kpl:
                    if kk not in acss_outputs.keys():
                        subset = False
                if subset:
                    acss_signal.clear()    
                    return True
                acss_signal.clear()
                await acss_signal.wait()

        async def _setup(j):
            
            # starting RBC
            rbctag = f'{ADKGMsgType.RBC}-{str(j)}' # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                riv = Bitmap(self.old_com['n'] + self.new_com['n'])
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)

            self.logger.debug(f'begin mvba, tag = {rbctag}')
 
            asyncio.create_task(
                optqrbc(
                    rbctag,
                    self.my_id,
                    com['ids'],
                    com['t'],
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv
                )
            )

            abatag = ADKGMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in com['ids']:
                    abasend(i, o)

            # self.logger.debug(f'begin ABA, tag = {abatag}')
                
            aba_task = asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    com['n'],
                    com['t'],
                    coin_keys[j].get,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
            return aba_task
        
        # self.logger.debug(f'begin setup')

        work_tasks = await asyncio.gather(*[_setup(j) for j in com['ids']])
        rbc_signal = asyncio.Event()
        rbc_values = [None for i in range(com['n'])]

        return (
            self.commonsubset(
                rbc_outputs,
                acss_outputs,
                acss_signal,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
                com
            ),
            self.derive_key(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
                com
            ),
            work_tasks,
        )
    
    
    
    async def consistency_check(self, dpss_id, acss_id, shares, share_blind, signal, signal_event):

        output_queue = asyncio.Queue()
        committee_map = {
            True: (self.old_com, self.new_com),
            False: (self.new_com, self.old_com)
        }
        committee, committee_other = committee_map[self.my_id in self.old_com['ids']]

        cons_start = time.time()

        tag_seed = f"{dpss_id}-{acss_id}-BEACON"
        
        send, recv = self.get_send(tag_seed), self.subscribe_recv(tag_seed)
        send(committee['beacon_dealer_id'], "req")

        self.logger.debug(f"send beacon request to dealer {committee['beacon_dealer_id']}")

        sender, seed = await recv()
        self.logger.debug(f"got beacon value {seed}")

        tag = f"{dpss_id}-{acss_id}-CON"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        for i in committee_other['ids']:
            send(
                i,
                (
                    ADKGMsgType.SEED,
                    seed
                )
            )

        


        seed2_set = set()
        seed2_counter = defaultdict(lambda: 0)
        script_shares = []
        script2_set = set()
        script2_counter = defaultdict(lambda: 0)
        local_script = None
        script_recv = None
        while True:
            sender, msg = await recv()

            if script_recv is not None and local_script is not None:
                if script_recv == local_script:
                    signal.set()
                    signal_event.set()
                    self.logger.debug(f'consistency verification pass, sid = {tag}')
                    return True
                else:
                    self.logger.error(f'consistency verification fail, script = {local_script}, script2_msg = {script2_msg}, acss dealer = {acss_id}')
                    return False

            if msg[0] == ADKGMsgType.SEED:
                if sender in seed2_set:
                    continue
                seed2_set.add(sender)

                seed2 = msg[1]
                seed2_counter[str(seed2)] += 1

                if seed2_counter[str(seed2)] == committee_other['t'] + 1:
                    self.logger.debug(f'collect enough beacon {seed2} from another committee, sid = {tag}')
                    self.logger.info(f'beacon collect time {time.time() - cons_start}')
                    # generate challenge
                    
                    challenge = []

                    if self.my_id in self.old_com['ids']:
                        prefix = (seed, seed2)
                    else:
                        prefix = (seed2, seed)

                    for i in range(len(shares)):
                        data = b''.join([str(prefix[0]).encode(), str(prefix[1]).encode(), str(i).encode()])
                        challenge.append(self.field.hash(data))

                    self.logger.debug(f"consistency check: challenge={challenge}, sid = {tag}, shares={shares}")

                    # generate and distribute script share

                    wi = share_blind
                    for i in range(len(shares)):
                        wi = wi + shares[i] * challenge[i]

                    self.logger.debug(f"consistency check: wi={wi}, sid = {tag}")
                    
                    for i in committee['ids']:
                        send(
                            i,
                            (
                                ADKGMsgType.SCRIPTSHARE,
                                wi
                            )
                        )

            elif msg[0] == ADKGMsgType.SCRIPTSHARE:
                if sender in self.new_com['ids']:
                    script_shares.append([self.new_com['ids'].index(sender) + 1, msg[1]])
                else:
                    script_shares.append([sender + 1, msg[1]])
                self.logger.debug(f"script shares = {script_shares}")

                if len(script_shares) == committee['t'] + 1:
                    script = self.poly.interpolate_at(script_shares, 0)
                    local_script = script
                    self.logger.debug(f"calculate local script = {script}, acss dealer = {acss_id}")
                    # TODO: Implement the fallback path

                    for i in committee_other['ids']:
                        send(
                            i,
                            (
                                ADKGMsgType.SCRIPT,
                                script
                            )
                        )

            elif msg[0] == ADKGMsgType.SCRIPT:
                if sender in script2_set:
                    self.logger.error(f"[{tag}] Redundant script2")
                    continue
                script2_set.add(sender)

                script2_msg = msg[1]
                script2_counter[str(script2_msg)] += 1

                if script2_counter[str(script2_msg)] >= committee_other['t'] + 1:
                    script_recv = script2_msg
                    
    
    async def acss_step_old(self, dpss_id, values, outputs, signal):

        if self.my_id in self.old_com['ids']:

            tag_acss_old = f"{dpss_id}-OLDCOM-ACSS"
            acss_send_old, acss_recv_old = self.get_send(tag_acss_old), self.subscribe_recv(tag_acss_old)

            if self.fault and self.my_id < self.old_com['t']:
                acss_old = BadDealer(
                    self.old_com['n'],
                    self.old_com['t'],
                    self.my_id,
                    acss_send_old,
                    acss_recv_old,
                    self.field,
                    None,
                    self.old_com['ids'],
                    self.batch_size_rand_pad
                )
            else:
                acss_old = Gossamer_acss(
                    self.old_com['n'],
                    self.old_com['t'],
                    self.my_id,
                    acss_send_old,
                    acss_recv_old,
                    self.field,
                    None,
                    self.old_com['ids'],
                    self.batch_size_rand_pad
                )
            
            task_acss_old = [] 
            for i in self.old_com['ids']:
                if i == self.my_id:
                    _task_acss_old = asyncio.create_task(acss_old.acss(self.my_id, values=values))
                else:
                    _task_acss_old = asyncio.create_task(acss_old.acss(i, dealer_id=i))
                _task_acss_old.add_done_callback(print_exception_callback)
                task_acss_old.append(_task_acss_old)
            
            self.acss_tasks.extend(task_acss_old)
            
            cons_check_task = [None] * self.old_com['n']
            con_signal_queue = [asyncio.Event() for _ in range(self.old_com['n'] + self.new_com['n'])]
            con_signal_event = asyncio.Event()


            shares_acss = None
            share_blind_acss = None
            share_get = {}
            async def process_acss_output():
                while True:
                    (dealer_id, acss_id, msg, _) = await acss_old.output_queue.get()
                    self.logger.debug(f"acss_old output = {msg}, msg[self.batch_size_rand:]={msg[self.batch_size_rand:]}, self.batch_size_rand={self.batch_size_rand}")
                    shares_acss = msg[:self.batch_size_rand]
                    share_blind_acss = msg[-1]
                    share_get[dealer_id] = {'shares': shares_acss, 'share_blind': share_blind_acss}

                    self.logger.debug(f'acss output for dealer = {dealer_id}, shares = {shares_acss}')

                    task = asyncio.create_task(self.consistency_check(
                        dpss_id, dealer_id, shares_acss, share_blind_acss, con_signal_queue[acss_id], con_signal_event
                    ))
                    task.add_done_callback(print_exception_callback)
                    cons_check_task[acss_id] = task
                    
                    if len(outputs) == self.old_com['n']:
                        break
            
            conscheck_time_start = time.time()

            output_task = asyncio.create_task(process_acss_output())

            while True:
                ready_count = sum(event.is_set() for event in con_signal_queue)

                if ready_count >= self.old_com['n'] - self.old_com['t']:
                    self.logger.debug(f'receive shares and check consistency from {ready_count} acss done')
                    conscheck_time_end = time.time()
                    self.logger.info(f'consistency check time {conscheck_time_end - conscheck_time_start}')
                    for i in range(len(con_signal_queue)):
                        if con_signal_queue[i].is_set():
                            outputs[i] = share_get[i]
                    
                if len(outputs) >= self.old_com['n'] - self.old_com['t']:
                    self.logger.debug(f'receive shares from n-t acss and consistency checked, proceed')
                    signal.set()
                if len(outputs) == self.old_com['n']:
                    self.logger.debug(f'receive shares from all acss and consistency checked')
                    return

                await con_signal_event.wait()
                con_signal_event.clear()          
            
        else:
            return

    async def acss_step_new(self, dpss_id, outputs, signal, acss):

        if self.my_id in self.new_com['ids']:

            acss_recv_tasks = [asyncio.create_task(acss.acss(id, dealer_id=id)) for id in self.old_com['ids']]
            _ = [task.add_done_callback(print_exception_callback) for task in acss_recv_tasks]

            self.acss_tasks.extend(acss_recv_tasks)


            cons_check_task = [None] * self.new_com['n']
            con_signal_queue = [asyncio.Event() for _ in range(self.old_com['n'] + self.new_com['n'])]
            con_signal_event = asyncio.Event()
            share_get = {}

            async def process_acss_output():
                while True:
                    (dealer_id, acss_id, msg, _) = await acss.output_queue.get()

                    shares_acss = msg[:self.batch_size_rand]
                    share_blind_acss = msg[-1]
                    share_get[dealer_id] = {'shares': shares_acss, 'share_blind': share_blind_acss}

                    self.logger.debug(f'acss output for dealer = {dealer_id}, shares = {shares_acss}')

                    task = asyncio.create_task(self.consistency_check(
                        dpss_id, dealer_id, shares_acss, share_blind_acss, con_signal_queue[acss_id], con_signal_event
                    ))
                    task.add_done_callback(print_exception_callback)
                    cons_check_task[acss_id] = task
                    
                    if len(outputs) == self.new_com['n']:
                        break

            output_task = asyncio.create_task(process_acss_output())

            while True:
                ready_count = sum(event.is_set() for event in con_signal_queue)
                if ready_count >= self.old_com['n'] - self.old_com['t']:
                    self.logger.debug(f'receive shares and check consistency from {ready_count} acss done')
                    for i in range(len(con_signal_queue)):
                        if con_signal_queue[i].is_set():
                            outputs[self.old_com['ids'][i]] = share_get[i]
                    
                if len(outputs) >= self.old_com['n'] - self.old_com['t']:
                    self.logger.debug(f'receive shares from n-t acss and consistency checked, proceed')
                    signal.set()
                if len(outputs) == self.old_com['n']:
                    self.logger.debug(f'receive shares from all acss and consistency checked')
                    return

                await con_signal_event.wait()
                con_signal_event.clear()
    
    async def _mask_distribute(self, shares, dpss_id, send):
        if self.my_id in self.old_com['ids']:
            # grouped shares
            group_size = self.old_com['t'] + 1
            num_groups = len(shares) // group_size

            assert len(shares) % group_size == 0, (
                f"Shares length {len(shares)} is not divisible by group size {group_size}"
            )

            grouped = [
                shares[i * group_size: (i + 1) * group_size]
                for i in range(num_groups)
            ]

            for idx, group in enumerate(grouped):
                self.logger.debug(f"group {idx}: {group}")

            # interpolate into polynomials
            polys = []
            for _shares in grouped:
                polys.append(
                    self.poly.interpolate([(x + 1, y) for x, y in enumerate(_shares)])
                )
            
            self.logger.debug(f"polys = {polys}")

            # distribute points
            tag_fij = f"{dpss_id}-DPSS-FIJ"
            send_fij, recv_fij = self.get_send(tag_fij), self.subscribe_recv(tag_fij)
            for i in self.old_com['ids']:
                send_fij(
                    i,
                    [poly(i + 1) for poly in polys]
                )
            
            self.logger.debug(f"send points to old com, tag = {tag_fij}")
            
            # collect points
            fijs_collect = []
            fij_sender_list = []
            fi0 = []
            while True:
                sender, fij_recv = await recv_fij()
                if sender in fij_sender_list:
                    self.logger.debug(f"[{tag_fij}] Redundant fij")
                fijs_collect.append((sender + 1, fij_recv))

                if len(fijs_collect) >= self.old_com['t'] + 1:
                    for i in range(len(fijs_collect[0][1])):
                        fij = []
                        for idx in range(len(fijs_collect)):
                            fij.append((fijs_collect[idx][0], fijs_collect[idx][1][i]))

                        fi0.append(self.poly.interpolate_at(fij, 0))
                    break
            
            self.logger.debug(f'fi0 = {fi0}')

            # multicast to new com
            for i in self.new_com['ids']:
                send(i, fi0)

            self.output_signal.set()

        return
    
    async def adpss(self, dpss_id, shares=None):

        self.logger.debug(f'initialize adpss')

        dpss_start_time = time.time()

        # initialize new com acss

        tag_acss = f"{dpss_id}-NEWCOM-ACSS"
        acss_send, acss_recv = self.get_send(tag_acss), self.subscribe_recv(tag_acss)

        if self.fault and self.my_id < self.old_com['t']:
            acss = BadDealer(
                self.new_com['n'],
            self.new_com['t'],
            self.my_id,
            acss_send,
            acss_recv,
            self.field,
            None,
            self.new_com['ids'],
            self.batch_size_rand_pad
        )
        else:   
            acss = Gossamer_acss(
                self.new_com['n'],
                self.new_com['t'],
                self.my_id,
                acss_send,
                acss_recv,
                self.field,
                None,
                self.new_com['ids'],
                self.batch_size_rand_pad
            )

        mvba_tag = f"{dpss_id}-MVBA2OTH"
        mvba_send, mvba_recv = self.get_send(mvba_tag), self.subscribe_recv(mvba_tag)

        fi0_tag = f"{dpss_id}-FI02OTH"
        fi0_send, fi0_recv = self.get_send(fi0_tag), self.subscribe_recv(fi0_tag)

        if self.my_id in self.old_com['ids']:

            rand = [self.field.random() for _ in range(self.batch_size_rand_pad)]

            self.logger.debug(f'rand = {rand}')
            self.shares = shares

            # acss to new com
            acss_task = asyncio.create_task(acss.acss(self.my_id, values=rand, dealer_id=self.my_id))
            acss_task.add_done_callback(print_exception_callback)

            # acss to old com
            acss_outputs_old = {}
            acss_signal_old = asyncio.Event()

            acss_start_time_old = time.time()

            task_acss_old = asyncio.create_task(self.acss_step_old(dpss_id, rand, acss_outputs_old, acss_signal_old))
            task_acss_old.add_done_callback(print_exception_callback)

            

            self.task = task_acss_old

            await acss_signal_old.wait()
            acss_signal_old.clear()

            acss_time_old = time.time() - acss_start_time_old

            self.benchmark_logger.info(f"ACSS time old: {(acss_time_old)}")

            # consensus in old com, use htadkg's MVBA
            # TODO: better alternative?
            mvba_start_time_old = time.time()
            proposal = list(acss_outputs_old.keys())
            create_acs_task = asyncio.create_task(self.agreement(proposal, acss_outputs_old, acss_signal_old, self.old_com))
            acs, set_mvba_task, work_tasks = await create_acs_task
            await acs
            await asyncio.gather(*work_tasks)
            set_mvba = await set_mvba_task
            self.logger.debug(f'mvba output = {set_mvba}')

            mvba_time_old = time.time() - mvba_start_time_old
            self.benchmark_logger.info(f"MVBA time old: {(mvba_time_old)}")

            phase2_start_time = time.time()

            # multicast mvba set to new com

            for i in self.new_com['ids']:
                mvba_send(
                    i,
                    self.serial.serialize_int_set(set_mvba)
                )

            self.logger.debug(f'mvba set sent to new com, tag = {mvba_tag}')

            # get rand shares

            self.logger.debug(f'calculating rand shares, dpss_id = {dpss_id}, acss_outputs_old={acss_outputs_old}, batch_size_rand = {self.batch_size_rand}')
            rand_shares = {}

            for idx in range(self.batch_size_rand):
                rand_shares[idx] = []
                for i in list(set_mvba)[:self.old_com['n'] - self.old_com['t']]:
                    rand_shares[idx].append(acss_outputs_old[i]['shares'][idx])

            self.logger.debug(f'rand_shares = {rand_shares}')
            
            u_shares = []
            matrix = self.old_com['matrix']  # List[List[GFElement]], shape: (n-2t) x (n-t)

            for idx in range(self.batch_size_rand):
                result = np.matmul(matrix, rand_shares[idx])
                u_shares.extend(result.tolist())

            self.logger.debug(f'u_shares = {u_shares}, s_shares = {shares}, type: {type(shares[0])}')

            s_add_u_shares = [x + y for x, y in zip(shares, u_shares)]
            self.logger.debug(f's_add_u_shares = {s_add_u_shares}')

            asyncio.create_task(self._mask_distribute(s_add_u_shares, dpss_id, fi0_send)).add_done_callback(print_exception_callback)

            await self.output_signal.wait()

            phase2_time = time.time() - phase2_start_time
            self.benchmark_logger.info(f"Phase2 time: {(phase2_time)}")

            dpss_time = time.time() - dpss_start_time
            self.benchmark_logger.info(f"old com DPSS time: {(dpss_time)}")

            return

        # acss to new com
        acss_outputs_new = {}
        acss_signal_new = asyncio.Event()

        acss_start_time = time.time()

        task_acss_new = asyncio.create_task(self.acss_step_new(dpss_id, acss_outputs_new, acss_signal_new, acss))
        task_acss_new.add_done_callback(print_exception_callback)

        self.task = task_acss_new

        await acss_signal_new.wait()

        acss_signal_new.clear()

        acss_time = time.time() - acss_start_time
        self.logger.debug(f'acss new com runtime = {acss_time}, acss_outputs_new.keys = {acss_outputs_new.keys()}')
        self.benchmark_logger.info(f"ACSS time new: {(acss_time)}")
        mvba_set_sender = set()
        mvba_set_collector = defaultdict(lambda: 0)
        set_mvba_new = None

        phase3_start_time = time.time()

        while True:
            sender, mvba_set_bytes = await mvba_recv()

            if sender in mvba_set_sender:
                self.logger.error(f"[{mvba_tag}] Redundant mvba set")
                continue

            mvba_set_sender.add(sender)
            mvba_set_collector[mvba_set_bytes] += 1

            if mvba_set_collector[mvba_set_bytes] >= self.new_com['t'] + 1:
                set_mvba_new = self.serial.deserialize_int_set(mvba_set_bytes)
                self.logger.debug(f'collect enough mvba set {set_mvba_new} from another committee, sid = {mvba_tag}')
                
                break

        

        # refresh shares
        fi0_sender_list = []
        fi0s_list = []
        fx0 = []
        while True:
            self.logger.debug(f'waiting for fi0 from old com, tag = {fi0_tag}')
            sender, fi0_recv_msg = await fi0_recv()
            self.logger.debug(f'receive fi0 from {sender}, fi0_recv = {fi0_recv_msg}')

            if sender in fi0_sender_list:
                self.logger.debug(f"[{fi0_tag}] Redundant fi0")
                continue

            fi0_sender_list.append(sender)
            fi0s_list.append((sender + 1, fi0_recv_msg))

            if len(fi0s_list) >= self.old_com['t'] + 1:
                self.logger.debug(f'collect enough fi0 from old com, tag = {fi0_tag}')

                
                for i in range(len(fi0s_list[0][1])):
                    fi0 = []
                    for idx in range(len(fi0s_list)):
                        fi0.append((fi0s_list[idx][0], fi0s_list[idx][1][i]))
                    fx0.append(self.poly.interpolate(fi0))

                self.logger.debug(f'fx0 = {fx0}')
                break

        
        s_add_u = []
        for _fx0 in fx0:
            for i in range(self.old_com['t'] + 1):
                s_add_u.append(_fx0(i + 1))


        

        self.logger.debug(f"s_add_u = {s_add_u}")

        rand_shares = {}
        for idx in range(self.batch_size_rand):
            rand_shares[idx] = []
            for i in list(set_mvba_new)[:self.old_com['n'] - self.old_com['t']]:
                rand_shares[idx].append(acss_outputs_new[i]['shares'][idx])

        self.logger.debug(f'rand_shares = {rand_shares}')
        
        u_shares = []
        matrix = self.old_com['matrix']  # List[List[GFElement]], shape: (n-2t) x (n-t)

        for idx in range(self.batch_size_rand):
            result = np.matmul(matrix, rand_shares[idx])
            u_shares.extend(result.tolist())

        self.logger.debug(f'u_shares = {u_shares}')

        shares_new = []
        for i in range(self.batch_size):
            shares_new.append(s_add_u[i] - u_shares[i])

        # high-threshold DPSS
        if self.high_threshold is not None:
            
            shares_lt = shares_new

            l = self.high_threshold
            total_elements = len(shares_new)
            elements_per_batch = l + 1
            B = total_elements // elements_per_batch

            assert total_elements % elements_per_batch == 0, f"shares_ly length {total_elements} cannot be divided by {elements_per_batch}"

            shares_batches = []
            for i in range(B):
                start_idx = i * elements_per_batch
                end_idx = start_idx + elements_per_batch
                batch = shares_lt[start_idx:end_idx]
                shares_batches.append(batch)

            poly_Hxi = []
            for batch in shares_batches:
                points = []
                for j, share in enumerate(batch):
                    x = j + 1  # x values: 1, 2, ..., l+1
                    points.append((x, share))
                
                # Perform polynomial interpolation to get a degree-l polynomial
                poly = self.poly.interpolate(points)
                poly_Hxi.append(poly)

            self.logger.debug(f'poly_Hxi = {poly_Hxi}')

            # calculate H(i)
            point_Hxi = []
            for i in self.new_com['ids']:
                point_Hxi.append([poly(self.new_com['ids'].index(i) + 1) for poly in poly_Hxi])

            self.logger.debug(f'point_Hxi = {point_Hxi}')


            tag_H = f"{dpss_id}-DPSS-H"
            send, recv = self.get_send(tag_H), self.subscribe_recv(tag_H)

            for i in self.new_com['ids']:
                send(
                        i, 
                        (
                            ADKGMsgType.H,
                            point_Hxi[self.new_com['ids'].index(i)]
                        )
                    )

            self.logger.debug(f'send poly_Hxi to new com, tag = {dpss_id}-DPSS-H')

            Hji_recv_list = []
            Hi0 = None
            while True:
                sender, Hji_recv = await recv()

                if Hji_recv[0] == ADKGMsgType.H:

                    Hji_recv_list.append((self.new_com['ids'].index(sender) + 1, Hji_recv[1]))
                    if len(Hji_recv_list) == self.new_com['t'] + 1:
                        
                        Hi0 = []
                        for idx in range(len(Hji_recv_list[0][1])):
                            points = []
                            for j, share in Hji_recv_list:
                                points.append((j, share[idx]))

                            Hi0.append(self.poly.interpolate_at(points, 0))

                        self.logger.debug(f'Hi0 = {Hi0}')
                        break
            
            shares_new = Hi0
        

        self.output_queue.put_nowait(shares_new)

        self.logger.debug(f'output shares_new = {shares_new}')

        phase3_time = time.time() - phase3_start_time
        self.benchmark_logger.info(f"Phase3 time: {(phase3_time)}")

        dpss_time = time.time() - dpss_start_time
        self.benchmark_logger.info(f"new com DPSS time: {(dpss_time)}")

        return



        

        

