import time
from GoSSamer.crypto.polynomial import polynomials_over
from GoSSamer.util.misc import wrap_send, subscribe_recv
from GoSSamer.crypto.symmetric_crypto import SymmetricCrypto
from GoSSamer.distribute.encode import encode, decode, merkle_tree, get_merkle_branch, hash, merkle_verify
from GoSSamer.util.serilization import Serial
from collections import defaultdict
import asyncio
import logging
from hashlib import sha256
from pickle import UnpicklingError
from zfec import Error as ErasureDecodeError
from GoSSamer.crypto.field import GFElement
from GoSSamer.util.serializer import serialize as dumps, deserialize as loads


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# logger.setLevel(logging.ERROR)


def _load_authenticated_plaintext(plaintext):
    """Content failure after proof verification/decryption, never proof failure.

    Keep the authenticated ciphertext's forwarding evidence even when its
    plaintext is not a serialized message. None is the existing failure value
    consumed by the protocol/PrivSend content checks.
    """
    try:
        return loads(plaintext)
    except (ValueError, TypeError, IndexError, KeyError, EOFError, UnpicklingError):
        return None

class SMDMessageType:
    SEND = "SEND"
    ECHO = "ECHO"
    VOTE = "VOTE"
    FORWARD = "FORWARD"
    EXFORWARD = "EXFORWARD"

class SMD_SS24:
    def __init__(
            self, sid, n, f, my_id, dealer_id, output, send, recv, field, receiver_ids,
            batch_count=None, target_ids=None
    ):
        # GF & GFElement is tested
        self.n, self.f, self.dealer_id = n, f, dealer_id
        self.my_id = my_id
        self.sid = sid
        self.batch_count = n if batch_count is None else batch_count
        if type(self.batch_count) is not int or self.batch_count < 1:
            raise ValueError('invalid batch count')
        self.subset_mode = target_ids is not None
        if self.subset_mode and self.batch_count != 1:
            raise ValueError('subset SMD supports one batch per instance')
        self.target_ids = tuple(receiver_ids if target_ids is None else target_ids)
        if (not self.target_ids or len(set(self.target_ids)) != len(self.target_ids)
                or any(type(i) is not int or i not in receiver_ids for i in self.target_ids)):
            raise ValueError('invalid target identities')
        self.target_count = len(self.target_ids)
        self.layout = ('SMD-subset-v1', self.batch_count, self.target_ids)
        self.available = asyncio.Event()
        self.available_roots = None
        self.layout_stats = dict(committee_size=n, batch_count=self.batch_count,
                                 target_count=self.target_count,
                                 ciphertext_slots=self.batch_count * self.target_count)
        

        self.recv = recv
        # Only the opt-in subset extension carries a layout envelope. Default
        # GoSSamer messages retain the original three-field wire format.
        self.send = (lambda dest, msg: send(dest, (msg[0], msg[1], (self.layout, msg[2])))) if self.subset_mode else send

        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = [None for _ in range(self.batch_count)]
        self.sr = Serial(self.field)
        self.tagvars = {}
        self.receiver_ids = receiver_ids

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
        self.output_flag = asyncio.Event()

        self.forward_output = {}
        self.forward_output_flag = defaultdict(lambda: asyncio.Event())
        self.forward_msg_from_others = [None for _ in range(self.n)]
        self.forward_output_flag_event = asyncio.Event()
        self.forward_output_queue = asyncio.Queue()
        self.deal_challenge = asyncio.Queue()

    def kill(self):
        self.subscribe_recv_task.cancel()
        


    
    def _get_dealer_msg(self, m, withKey = False):
        # m is a list of messages [m1, ..., mn]
        start_time=time.time()
        target_count = getattr(self, 'target_count', self.n)
        assert len(m) == target_count
        s = []
        f = []
        send_data = []
        merkle_tree_data = []
        k_f = []
        roots = []
        

        if withKey:
            self.kpoly = [None for _ in range(target_count)]
        
        for i in range(target_count):
            si = []
            ki = []

            if withKey:
                self.kpoly[i] = self.poly.random(self.f)
            poly = self.kpoly[i]

            logger.info(f"{i}-cycle time-1 {time.time()-start_time}")

            # step 1 - enc
            # The secret is at zero; committee shares use coordinates 1..n.
            key = sha256(int(poly(0)).to_bytes(32, byteorder="big")).digest()

            # logger.debug(f'key_origin for node {i}, data: {key}')

            logger.info(f"{i}-cycle time-12 {time.time()-start_time}")
            dmi = dumps(m[i])

            logger.info(f"{i}-cycle time-123 {time.time()-start_time}")

            ci = SymmetricCrypto.encrypt(key, dmi)

            logger.info(f"{i}-cycle time-2 {time.time()-start_time}, len: {len(ci)}")

            # logger.debug(f'ci = {ci}')

            for j in range(self.n):
                point = poly(j + 1)
                si.append(point)
                ki.append(hash(f'{j}-{hash(str(point))}'))
            # logger.debug(f'ki_origin for node {i}, data: {ki}')
            # logger.debug(f'si_origin for node {i}, data: {si}')

            logger.info(f"{i}-cycle time-3 {time.time()-start_time}")
            
            # step 2 - encode
            fi = encode(self.f + 1, self.n, ci)
            # logger.debug(f'ci_original for node {i}, data: {ci} ')
            # logger.debug(f'fi_original for node {i}, data: {fi} ')
            logger.info(f"{i}-cycle time-4 {time.time()-start_time}")
            ki_fi = []
            for j in range(self.n):
                # logger.debug(
                #         f'kij_fij_1. Id: {self.my_id}, Dealer Id: {self.dealer_id}, receiver: {j}, sequence: {i}, msg: {ki[j]+fi[j]}'
                #     )
                ki_fi.append((ki[j]+fi[j]))
            k_f.append(ki_fi)
            # logger.debug(f'ki_fi_origin for node {i}, data: {ki_fi}')  

            
            merkle_tree_data.append(merkle_tree(ki_fi))
            roots.append(merkle_tree_data[i][1])
            # for j in range(self.n):
                
            #     if not merkle_verify(self.n, ki_fi[j], merkle_tree_data[i][1], get_merkle_branch(j, merkle_tree_data[i]), j):
            #         logger.error(
            #             f'Failed to verify from dealer. Id: {self.my_id}, Dealer Id: {self.dealer_id}, receiver: {j}, sequence: {i}'
            #         )
            f.append(fi)
            s.append(si)

        # logger.debug(
        #     f'Calculating distribute message (phase 1 + phase 2). Id: {self.my_id}, Dealer Id: {self.dealer_id}, message: {m}')

        # step 3 - organize data
        data = [] # data[j] is data for node j 
        for j in range(self.n):
            dataj = []
            for i in range(target_count):
                if withKey:
                    dataji = (merkle_tree_data[i][1], get_merkle_branch(j, merkle_tree_data[i]), s[i][j], f[i][j])
                else:
                    dataji = (merkle_tree_data[i][1], get_merkle_branch(j, merkle_tree_data[i]), None, f[i][j])
                dataj.append(dataji)
                # logger.debug(
                #     f'Node-[{self.my_id}]: Calculating distribute message (phase 3). Id: {self.my_id}, Dealer Id: {self.dealer_id}, {j}-receiver-{i}-msg, dataji: {dataji}')   
            data.append(dataj)
        logger.info(f"time-5 {time.time()-start_time}")
        # for j in range(self.n):
        #     for i in range(self.n):
        #         if not merkle_verify(self.n, k_f[i][j], merkle_tree_data[i][1], get_merkle_branch(j, merkle_tree_data[i]), j):
        #             logger.error(
        #                 f'Node-[{self.my_id}]: Failed to verify from dealer -2. Id: {self.my_id}, Dealer Id: {self.dealer_id}, receiver: {j}, sequence: {i}'
        #             )
        logger.debug(f'Node-[{self.my_id}]: Final dealer message get. sid = {self.sid}')

        total_root = merkle_tree([self.target_leaf(r, i) for i, r in enumerate(roots)])[1]
        self.deal_challenge.put_nowait(total_root)
        # logger.debug(f'total root: {total_root}')
        return data, total_root
    
    # async def forward(self, receiver_id=None):
    #     forward_msg = self.tagvars[self.sid]['forward_msg']
    #     self.send(
    #         receiver_id,
    #         (
    #             self.sid, 
    #             SMDMessageType.FORWARD,
    #             forward_msg
    #         )
    #     )
    #     return
    
    def forward_in_batch(self, receiver_id=None, k=None, msg_type=None):
        if self.subset_mode or self.batch_count != self.n:
            raise ValueError('legacy forwarding requires n batches; use export_target_proof/verify_target_proof')
        forward_msg = self.tagvars[self.sid]['forward_msg'][k]
        self.send(
            receiver_id,
            (
                self.sid, 
                SMDMessageType.FORWARD, 
                (
                    msg_type,
                    forward_msg
                )
            )
        )
        logger.debug(f'Node-[{self.my_id}]: forward_in_batch, receiver_id = {receiver_id}, msg_type = {msg_type}')

    def exforward_in_batch(self, receiver_id, msg_type, forward_id):
        if self.subset_mode or self.batch_count != self.n:
            raise ValueError('legacy forwarding requires n batches; use export_target_proof/verify_target_proof')
        '''
        forward_id: forward whose msg
        '''
        self.send(
            receiver_id,
            (
                self.sid, 
                SMDMessageType.EXFORWARD, 
                (
                    msg_type,
                    forward_id,
                    self.forward_msg_from_others[forward_id]
                )
            )
        )

        logger.debug(f'Node-[{self.my_id}]: exforward_in_batch, receiver_id = {receiver_id}, msg_type = {msg_type}, forward_id = {forward_id}')
    def target_leaf(self, root, slot):
        if not getattr(self, 'subset_mode', False):
            return root
        return hash(dumps(('SMD-TARGET-v1', self.sid, self.layout, self.target_ids[slot], root)))

    def export_target_proof(self, batch=0):
        if not self.output_flag.is_set() or not 0 <= batch < self.batch_count:
            raise ValueError('proof requires a delivered batch')
        return self.tagvars[self.sid]['forward_msg'][batch]

    def _valid_target_fragment(self, item, target, batch, roots):
        try:
            source, root, branch, inner_root, inner, share, stripe = item
            if (source not in self.receiver_ids or type(source) is not int
                    or target not in self.target_ids or not isinstance(share, self.field)
                    or not isinstance(stripe, bytes) or root != roots[batch]):
                return False
            slot = self.target_ids.index(target)
            index = self.receiver_ids.index(source)
            return (merkle_verify(self.target_count, self.target_leaf(inner_root, slot), root, branch, slot)
                    and merkle_verify(self.n, hash('{}-{}'.format(index, hash(str(share)))) + stripe,
                                      inner_root, inner, index))
        except (ValueError, TypeError, IndexError, KeyError, AssertionError):
            return False

    def verify_target_proof(self, proof, target, batch, roots):
        """(authenticated, value): None is content failure, False is forgery.

        Every provided fragment is authenticated first. Exactly f+1 distinct
        fragments define the candidate, and re-encoding binds it to all n
        committed strips/shares; higher-degree dealer polynomials cannot pass.
        """
        if (not isinstance(proof, (tuple, list)) or not self.f + 1 <= len(proof) <= self.n
                or type(batch) is not int or not 0 <= batch < self.batch_count):
            return False, None
        seen, inner_root = set(), None
        for item in proof:
            if not self._valid_target_fragment(item, target, batch, roots):
                return False, None
            source, _, _, rj, _, _, _ = item
            if source in seen or (inner_root is not None and rj != inner_root):
                return False, None
            seen.add(source)
            inner_root = rj
        chosen = sorted(proof, key=lambda item: self.receiver_ids.index(item[0]))[:self.f + 1]
        strips = [None] * self.n
        points = []
        for source, _, _, _, _, share, stripe in chosen:
            index = self.receiver_ids.index(source)
            strips[index] = stripe
            points.append((index + 1, share))
        # These failures describe authenticated dealer content, not packet
        # authenticity. The same computation is repeated for public Reveal.
        try:
            cipher = decode(self.f + 1, self.n, strips)
            regenerated = encode(self.f + 1, self.n, cipher)
            shares = [self.poly.interpolate_at(points, i + 1) for i in range(self.n)]
            leaves = [hash('{}-{}'.format(i, hash(str(shares[i])))) + regenerated[i]
                      for i in range(self.n)]
            if merkle_tree(leaves)[1] != inner_root:
                return True, None
            key = hash(int(self.poly.interpolate_at(points, 0)).to_bytes(32, 'big'))
            return True, _load_authenticated_plaintext(SymmetricCrypto.decrypt(key, cipher))
        except (ErasureDecodeError, ValueError, TypeError, IndexError, OverflowError):
            # Includes zfec's native decoder error on authenticated invalid
            # stripe lengths. No exception is converted before proof checking.
            return True, None

    def _subset_output(self, collected):
        if self.my_id not in self.target_ids or self.available_roots is None or self.output_flag.is_set():
            return
        for batch in range(self.batch_count):
            if self.output_queue[batch] is not None:
                continue
            valid = {}
            for row in collected:
                item = row[batch]
                if self._valid_target_fragment(item, self.my_id, batch, self.available_roots):
                    valid.setdefault(item[0], item)
            if len(valid) < self.f + 1:
                continue
            proof = [valid[k] for k in sorted(valid)[:self.f + 1]]
            authenticated, value = self.verify_target_proof(proof, self.my_id, batch, self.available_roots)
            if authenticated:
                self.output_queue[batch] = (value, self.available_roots[batch])
                self.tagvars[self.sid]['forward_msg'][batch] = proof
        if all(row is not None for row in self.output_queue):
            self.output_flag.set()

    # async def forward_multicast(self):
    #     return
    
    def _verify_echo_msg(self, pid, _echo_msg_collector):
        (sender_i, r, pij, rj, piji, sji, fji) = _echo_msg_collector

        echo_msg_val = []
        fji_val = [None for _ in range(self.n)]
        sji_val = []
        val_flag = False
        rj_val = None
        pij_val = None
        if rj_val is None and pij_val is None:
            if merkle_verify(
                self.n,
                rj,
                r,
                pij,
                pid
            ):
                rj_val = rj
                pij_val = pij
                val_flag = True

        if val_flag == True and rj_val == rj and pij_val == pij:
            kji = hash(f"{sender_i}-{hash(sji)}")
            kji_fji = kji + fji
            if merkle_verify(
                self.n,
                kji_fji,
                rj,
                piji,
                sender_i
            ):
                echo_msg_val.append((sender_i, r, pij, rj, piji, sji, fji))
                fji_val[sender_i] = fji
                sji_val.append((sender_i, GFElement.from_bytes(sji, self.field)))
        
        return echo_msg_val, rj_val, pij_val, fji_val, sji_val


    async def distribute(self, m=None, client_mode=False):
        """
        Implementation of Secure Message Distribution - distribution phase
        :param int pid: current member id
        :param int m: the list of message
            for each party from 1 to n from the dealer
        """
        distribute_start_time = time.time()
        logger.debug(f"Node-[{self.my_id}]: init distribute, sid = {self.sid}")

        echo_threshold = self.n - self.f
        vote_threshold_1 = self.f + 1
        vote_threshold_2 = self.n - self.f
        rec_threshold = self.f + 1

        leader = self.dealer_id
        sid = self.sid
        

        if not self.my_id == self.dealer_id:
            pid = self.receiver_ids.index(self.my_id)
        else:
            pid = self.dealer_id

        def broadcast(o):
            for i in range(self.n):
                self.send(self.receiver_ids[i], o)

        logger.debug(f"Node-[{self.my_id}]: init distribute, pid = {pid}")

        if self.my_id == leader:
            if not isinstance(m, (tuple, list)) or len(m) != self.batch_count:
                raise ValueError('batch count mismatch')
            
            # logger.debug(
            #     f'Node-[{self.my_id}]: Calculating distribute message. sid = {self.sid}')
            distribute_msg = []
            total_root = []
            for i in range(len(m)):
                if i == 0:
                    _distribute_msg, _total_root = self._get_dealer_msg(m[i], withKey = True)
                else:
                    _distribute_msg, _total_root = self._get_dealer_msg(m[i], withKey = False)
                distribute_msg.append(_distribute_msg)
                total_root.append(_total_root)

            logger.debug(f'distribute_msg for node {self.my_id}')
            logger.debug(f'total_root for node {self.my_id}, data: {total_root}')
            
            # 使用 zip 转置
            distribute_msg = [list(x) for x in zip(*distribute_msg)]
            

            # logger.debug(
            #     f'Node-[{self.my_id}]: Sending distribute message. sid = {self.sid}')
            
            for j in range(self.n):
                logger.debug(f'Node-[{self.my_id}]: Sending distribute message to {self.receiver_ids[j]}. sid = {self.sid}, msg = {distribute_msg[j]}')
                self.send(
                    self.receiver_ids[j],
                    (
                        sid,
                        SMDMessageType.SEND,
                        distribute_msg[j]
                    )
                )
            distribute_end_time = time.time()
            logger.info(f"Node-[{self.my_id}]: smd dealer distribute stage time cost: {distribute_end_time - distribute_start_time}")
            logger.debug(
                f'Node-[{self.my_id}]: All distribute message sent. sid = {self.sid}, my id = {self.my_id}, receiver_id = {self.receiver_ids}')
            
            if self.my_id == self.dealer_id and not self.my_id in self.receiver_ids:
                logger.debug(
                f'Node-[{self.my_id}]: output as exernal distributor = {self.sid}')
                self.output_flag.set()
                for k in range(self.batch_count):
                    self.output_queue[k] = (None, total_root[k])
                return 
            

        
        from_leader = False
        echo_set = set()
        echo_msg_collector = []
        echo_counter = defaultdict(lambda: 0)
        vote_sent = False
        vote_set = set()
        vote_counter = defaultdict(lambda: 0)

        vote_threshold_1_flag = False
        vote_threshold_2_flag = False

        output_process_flag = False

        self.tagvars[sid] = {}
        self.tagvars[sid]['forward_msg'] = [None for _ in range(self.batch_count)]
        self.tagvars[sid]['root'] = [None for _ in range(self.batch_count)]
        pending_forwards = []
        stored_votes, ready_votes = defaultdict(set), defaultdict(set)
        store_senders, ready_senders = set(), set()
        subset_ready = None


        while True:
            
            if self.output_flag.is_set() and pending_forwards:
                sender, msg = pending_forwards.pop(0)
            else:
                sender, msg = await self.recv()
            incoming_sender = sender
            if self.subset_mode:
                if (sender not in self.receiver_ids or not isinstance(msg, (tuple, list))
                        or len(msg) != 3 or msg[0] != sid or not isinstance(msg[2], (tuple, list))
                        or len(msg[2]) != 2 or msg[2][0] != self.layout):
                    continue
                msg = (sid, msg[1], msg[2][1])
                self._subset_output(echo_msg_collector)
                if msg[1] in ('STORE', SMDMessageType.VOTE):
                    roots = msg[2]
                    if (not isinstance(roots, (tuple, list)) or len(roots) != self.batch_count
                            or not all(isinstance(r, bytes) and len(r) == 32 for r in roots)):
                        continue
                    roots = tuple(roots)
                    identities = store_senders if msg[1] == 'STORE' else ready_senders
                    counts = stored_votes if msg[1] == 'STORE' else ready_votes
                    if sender in identities:
                        continue
                    identities.add(sender)
                    counts[roots].add(sender)
                    if subset_ready is None and (len(stored_votes[roots]) >= self.n - self.f
                                                 or len(ready_votes[roots]) >= self.f + 1):
                        subset_ready = roots
                        broadcast((sid, SMDMessageType.VOTE, roots))
                    if self.available_roots is None and len(ready_votes[roots]) >= self.n - self.f:
                        self.available_roots = roots
                        self.tagvars[sid]['root'] = list(roots)
                        self.available.set()
                        self._subset_output(echo_msg_collector)
                    continue
            # self.benchmark_logger.info(f"Node-[{self.my_id}]: receive message {msg[1]} from {sender} time cost: {time.time() - distribute_start_time}")
            logger.debug(
                f"Node-[{self.my_id}]: receive message {msg[1]}. sender: {sender}, sid = {self.sid}"
            )
            # if msg[1] == SMDMessageType.FORWARD:
            #     (_, _, forward_msg) = msg
            #     for _forward_msg in forward_msg:
            #         self._verify_echo_msg(_forward_msg)

            if not self.subset_mode and output_process_flag == True and len(echo_msg_collector) >= self.f + 1:
                # unpack
                echo_msg_same_root = [[] for _ in range(self.batch_count)]
                sj = [None for _ in range(self.n)]
                for i in range(len(echo_msg_collector)):
                    for k in range(self.batch_count):
                        (sender, r, pij, rj, piji, sji, fji) = echo_msg_collector[i][k]
                        if k == 0:
                            sj[self.receiver_ids.index(sender)] = sji
                        else:
                            sji = sj[self.receiver_ids.index(sender)]
                        if r == root[k]:
                            echo_msg_same_root[k].append(echo_msg_collector[i][k])
                logger.debug(
                    f"Node-[{self.my_id}]: message unpacked. sid = {self.sid}"
                )
                

                logger.debug(
                    f"Node-[{self.my_id}]: echo_msg_same_root sid = {self.sid}"
                )
                echo_msg_val = [[] for _ in range(self.batch_count)]
                fji_val = [[None for _ in range(self.n)] for _ in range(self.batch_count)]
                sji_val = [[] for _ in range(self.batch_count)]
                val_flag = [False for _ in range(self.batch_count)]
                rj_val = [None for _ in range(self.batch_count)]
                pij_val = [None for _ in range(self.batch_count)]
                output_flag = [False for _ in range(self.batch_count)]

                logger.debug(f"Node-[{self.my_id}]: Starting to process echo_msg_same_root. sid = {self.sid}")
                start_time = time.time()
                for k in range(self.batch_count):
                    logger.debug(f"Node-[{self.my_id}]: Processing k={k}. sid = {self.sid}")
                    output_msg = []

                    for _echo_msg_collector in echo_msg_same_root[k]:
                        logger.debug(f"Node-[{self.my_id}]: Processing echo_msg_collector. sid = {self.sid}")
                        (sender_i, r, pij, rj, piji, sji, fji) = _echo_msg_collector
                        if k != 0:
                            sji = sj[self.receiver_ids.index(sender_i)]
                        
                        if rj_val[k] is None and pij_val[k] is None:
                            if merkle_verify(
                                self.n,
                                rj,
                                r,  
                                pij,
                                pid
                            ):
                                rj_val[k] = rj
                                pij_val[k] = pij
                                val_flag[k] = True
                            else:
                                logger.error(f"Node-[{self.my_id}]: merkle_verify echo fail, sid = {self.sid}")

                        logger.debug(
                                f"Node-[{self.my_id}]: 1"
                            )

                        if val_flag[k] == True and rj_val[k] == rj and pij_val[k] == pij:
                            map_sender_id = self.receiver_ids.index(sender_i)
                            kji = hash(f"{map_sender_id}-{hash(str(sji))}")
                            kji_fji = kji + fji
                            if merkle_verify(
                                self.n,
                                kji_fji,
                                rj,
                                piji,
                                map_sender_id
                            ):  
                                echo_msg_val[k].append((sender_i, r, pij, rj, piji, sji, fji))
                                logger.debug(
                                    f"Node-[{self.my_id}]: sid = {sid}, sender_i = {sender_i}"
                                )
                                fji_val[k][self.receiver_ids.index(sender_i)] = fji
                                sji_val[k].append((map_sender_id + 1, sji))
                            else:
                                logger.error(f"Node-[{self.my_id}]: merkle_verify( \
                                    self.n, \
                                    kji_fji, \
                                    rj, \
                                    piji, \
                                    map_sender_id \
                                ) fail, sid = {self.sid}")
                        else:
                            logger.error(f"Node-[{self.my_id}]: val_flag == True and rj_val == rj and pij_val == pij fail, sid = {self.sid}")

                        logger.debug(
                                f"Node-[{self.my_id}]: 2"
                            )

                        if len(echo_msg_val[k]) >= rec_threshold:
                            self.tagvars[sid]["forward_msg"][k] = echo_msg_val[k]
                            

                            logger.debug(
                                f"Node-[{self.my_id}]: smd n-t"
                            )

                            if not self.output_flag.is_set():

                                cj = decode(self.f + 1, self.n, fji_val[k])
                                logger.debug(f'cj_decode for node {self.my_id}')  

                                fj_out = encode(self.f + 1, self.n, cj)
                                logger.debug(f'fj_out for node {self.my_id}')  
                                # logger.debug(f'sji_val for node {self.my_id}, data: {sji_val}') 

                                kj_out = [None for _ in range(self.n)]
                                kj_fj_out = [None for _ in range(self.n)]
                                sj_out = []
                                
                                for i in range(self.n):
                                    sji_out = self.poly.interpolate_at(sji_val[k], i + 1)
                                    sj_out.append(sji_out)
                                    kj_out[i] = hash(f'{i}-{hash(str(sji_out))}')
                                    kj_fj_out[i] = kj_out[i] + fj_out[i]
                                
                                # logger.debug(f'kj_out for node {self.my_id}, data: {kj_out}')
                                # logger.debug(f'sj_out for node {self.my_id}, data: {sj_out}')
                                # logger.debug(f'kj_fj_out for node {self.my_id}, data: {kj_fj_out}')
                                merkle_tree_out_data = merkle_tree(kj_fj_out)
                                logger.debug(f'root of merkle_tree_out_data for node {self.my_id}')
                                logger.debug(f'111')
                                
                                if merkle_tree_out_data[1] == rj_val[k]:
                                    key = sha256(int(self.poly.interpolate_at(sji_val[k], 0)).to_bytes(32, byteorder="big")).digest()
                                    # logger.debug(f'key for node {self.my_id}, data: {key}')
                                    mj = SymmetricCrypto.decrypt(key, cj)
                                    mj = _load_authenticated_plaintext(mj)
                                    # logger.debug(f'Node-[{self.my_id}]: output mj as node {self.my_id}, dealer: {self.dealer_id}, data: {mj}')
                                    self.output_queue[k] = (mj, root[k])
                                    self.tagvars[sid]['root'][k] = root[k]
                                    logger.debug(f"Node-[{self.my_id}]: output mj as node {self.my_id}, dealer: {self.dealer_id}, k={k}")
                                    output_flag[k] = True
                                    # self.benchmark_logger.info(f"Node-[{self.my_id}]: output_flag = {output_flag}")
                                    if all(output_flag):
                                        end_time = time.time()
                                        self.output_flag.set()
                                        output_process_flag = False
                                        # self.benchmark_logger.info(f"Node-[{self.my_id}]: final time cost: {end_time - distribute_start_time}")
                                    break
                                else:
                                    logger.error(
                                        f'Failed to verify final message. Id: {self.my_id}, Dealer Id: {self.dealer_id}'
                                    )
            
            # The decode loop above uses `sender` as a local loop variable.
            # Restore the authenticated sender of the message being handled.
            sender = incoming_sender
            if msg[1] in (SMDMessageType.FORWARD, SMDMessageType.EXFORWARD) and not self.output_flag.is_set():
                # Cross-process scheduling can deliver recovery evidence before
                # this node has decoded/installed its authenticated root list.
                # Validate the original evidence after local SMD completion.
                pending_forwards.append((sender, msg))
                continue
            if msg[1] == SMDMessageType.SEND and from_leader is False:
                # Transport identity, not valid Merkle data, binds the dealer.
                # Reject before unpacking or installing any attacker material.
                if sender != self.dealer_id:
                    continue
                logger.info(
                    f"Node-[{self.my_id}]: receive send message. sender: {sender}, sid = {self.sid}"
                )
                # Validation
                (_, _, distribute_msg) = msg
                if self.subset_mode and (not isinstance(distribute_msg, (tuple, list))
                        or len(distribute_msg) != self.batch_count
                        or any(not isinstance(row, (tuple, list)) or len(row) != self.target_count
                               for row in distribute_msg)):
                    continue
                if self.subset_mode:
                    valid_shape = all(
                        isinstance(item, (tuple, list)) and len(item) == 4
                        and isinstance(item[0], bytes) and len(item[0]) == 32
                        and isinstance(item[1], (tuple, list)) and len(item[1]) == (self.n - 1).bit_length()
                        and all(isinstance(x, bytes) and len(x) in (0, 32) for x in item[1])
                        and isinstance(item[2], self.field) and isinstance(item[3], bytes)
                        for row in distribute_msg for item in row)
                    if not valid_shape:
                        continue

                # logger.debug(
                #         f'Node-[{self.my_id}]: dealer verification success: {self.my_id}, Dealer Id: {self.dealer_id}'
                #     )

                send_recv_start_time = time.time()
                # self.benchmark_logger.info(f"Node-[{self.my_id}]: send_recv time cost: {send_recv_start_time - distribute_start_time}")

                # merkle tree verification
                validation_fail_flag = False
                roots = [[] for _ in range(self.batch_count)]
                merkle_tree_root_data = []

                ki = [None for _ in range(self.target_count)]
                
                for k in range(self.batch_count): 
                    for i in range(self.target_count):
                        (root, branch, sij, fij) = distribute_msg[k][i]

                        logger.debug(
                            f'Node-[{self.my_id}]: unpack message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, sid = {self.sid}, k={k}, i={i}'
                        )
                        roots[k].append(root)

                        if k == 0:
                            ki[i] = hash(f"{pid}-{hash(str(sij))}")
                        # else:
                        #     ki[i] = hash(f"{pid}-{hash(str(sij))}")
                        
                        kij = ki[i]
                        kij_fij = kij + fij

                        # logger.debug(
                        #     f'Node-[{self.my_id}]: kij_fij. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, sequence: {i},sid = {self.sid}'
                        # )
                        if not merkle_verify(
                            self.n,
                            kij_fij,
                            root,
                            branch,
                            pid
                        ):
                            logger.error(f"Node-[{self.my_id}]: Failed to validate VAL message, sid = {self.sid}")
                            validation_fail_flag = True
                            break
                    if validation_fail_flag:
                        break

                    logger.debug(f"Node-[{self.my_id}]: verification kij_fij success for {k}-th message")
                    
                    # build root merkle tree
                    
                    merkle_tree_root_data.append(merkle_tree([self.target_leaf(r, slot)
                                                             for slot, r in enumerate(roots[k])]))
                    # logger.debug(f"Node-[{self.my_id}]: total_root = {merkle_tree_root_data[1]}, roots = {roots}")
                send_recv_end_time = time.time()
                if validation_fail_flag:
                    continue
                # self.benchmark_logger.info(f"Node-[{self.my_id}]: before echo sent time cost: {send_recv_end_time - distribute_start_time}")
                
                echo_msg_start_time = time.time()
                for i in range(self.target_count):
                    msg_echo = []
                    for k in range(self.batch_count):
                        (root, branch, sij, fij) = distribute_msg[k][i]
                        msg_echo.append((
                            merkle_tree_root_data[k][1],
                            get_merkle_branch(i, merkle_tree_root_data[k]),
                            root,
                            branch,
                            sij,
                            fij
                        ))
                    self.send(
                        self.target_ids[i],
                        (
                            sid,
                            SMDMessageType.ECHO,
                            msg_echo
                        )
                    )
                    logger.info(f"Node-[{self.my_id}]: send echo to {self.receiver_ids[i]}")
                
                
                from_leader = True
                if self.subset_mode:
                    # All target ECHOs precede STORE. Honest storage therefore
                    # implies reliable future delivery of this member's strips.
                    broadcast((sid, 'STORE', tuple(tree[1] for tree in merkle_tree_root_data)))

                

            elif msg[1] == SMDMessageType.ECHO:
                logger.info(
                    f'Node-[{self.my_id}]: receive echo message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}' 
                )
                if sender in echo_set:
                    logger.info(f"Node-[{self.my_id}]: Redundant ECHO")
                    continue
                # Update
                echo_set.add(sender)
               

                msg_echo = msg[2]
                if self.subset_mode and (self.my_id not in self.target_ids
                        or not isinstance(msg_echo, (tuple, list)) or len(msg_echo) != self.batch_count
                        or any(not isinstance(row, (tuple, list)) or len(row) != 6 for row in msg_echo)):
                    continue
                _echo_msg_collector = []
                root = []
                for k in range(self.batch_count):
                    (r, pij, rj, piji, sji, fji) = msg_echo[k]
                    _echo_msg_collector.append((sender, r, pij, rj, piji, sji, fji))

                    root.append(r)
                    echo_counter[r] = echo_counter[r] + 1

                echo_msg_collector.append(_echo_msg_collector)
                if self.subset_mode:
                    self._subset_output(echo_msg_collector)
                    continue

                if not vote_sent:
                    # if [echo_counter[r] >= echo_threshold for r in root]:
                    if all(echo_counter[r] >= echo_threshold for r in root):
                        logger.debug(
                            f'Node-[{self.my_id}]: send vote message. Id: {self.my_id}, Dealer Id: {self.dealer_id}' 
                        )
                        vote_sent = True
                        vote_msg_start_time = time.time()
                        # self.benchmark_logger.info(f"Node-[{self.my_id}]: before vote msg sent time cost: {vote_msg_start_time - distribute_start_time}")
                        broadcast((sid, SMDMessageType.VOTE, root))
                    
                

            elif msg[1] == SMDMessageType.VOTE and not self.output_flag.is_set():
                root = msg[2]
                if sender in vote_set:
                    logger.info("[{pid}] Redundant VOTE")
                    continue
                vote_set.add(sender)
                for r in root:
                    vote_counter[r] = vote_counter[r] + 1

                if not vote_threshold_1_flag:
                    vote_threshold_1_flag = all(vote_counter[r] >= vote_threshold_1 for r in root)
                if not vote_threshold_2_flag:
                    vote_threshold_2_flag = all(vote_counter[r] >= vote_threshold_2 for r in root)

                if not vote_sent and vote_threshold_1_flag:
                    vote_sent = True
                    vote_threshold_1_time = time.time()
                    # self.benchmark_logger.info(f"Node-[{self.my_id}]: t+1 vote recv time cost: {vote_threshold_1_time - distribute_start_time}")
                    broadcast((sid, SMDMessageType.VOTE, root))

                
                if vote_threshold_2_flag:
                    # self.benchmark_logger.info(f"Node-[{self.my_id}]: vote_counter: {vote_counter}")
                    vote_end_time = time.time()
                    # mark_logger.info(f"Node-[{self.my_id}]: n-t vote receive time cost: {vote_end_time - distribute_start_time}")
                    logger.debug(
                        f"Node-[{self.my_id}]: receive n-t vote message, verify and output. sid = {self.sid}"
                    )

                    if not output_process_flag:
                        # Decoding runs at the top of the next receive iteration.
                        # With exactly n-f live senders there may be no next
                        # network packet; explicitly schedule that iteration.
                        self.send(self.my_id, (sid, "LOCAL_DECODE_WAKE", None))
                    output_process_flag = True

                    

            elif msg[1] == SMDMessageType.FORWARD:
                logger.debug(f"Node-[{self.my_id}]: receive forward message. sid = {self.sid}")

                (_, _, recv_msg) = msg
                (msg_type, forward_msg) = recv_msg


                logger.debug(f'Node-[{self.my_id}]: msg_type = {msg_type}, sender = {sender}')

                r_mem, pij_mem, rj_mem = None, None, None
                
                fji_val = [None for _ in range(self.n)]
                sji_val = []
                for _forward_msg in forward_msg:
                    (sender_i, r, pij, rj, piji, sji, fji) = _forward_msg

                    logger.debug(f"Node-[{self.my_id}]: sji = {sji}, sender_i = {sender_i}")
                    
                    if r_mem is None:
                        r_mem = r
                        pij_mem = pij
                        rj_mem = rj
                        assert self.tagvars[sid]['root'][self.receiver_ids.index(self.my_id)] == r, f"Node-[{self.my_id}]: root[k] != r, sid = {self.sid}"
                        assert merkle_verify(
                            self.n,
                            rj,
                            r,
                            pij,
                            self.receiver_ids.index(sender)
                        ), f"Node-[{self.my_id}]: merkle_verify fail 1, sid = {self.sid}"
                    else:
                        assert r_mem == r, f"Node-[{self.my_id}]: r_mem != r, sid = {self.sid}"
                        assert pij_mem == pij, f"Node-[{self.my_id}]: pij_mem != pij, sid = {self.sid}"
                        assert rj_mem == rj, f"Node-[{self.my_id}]: rj_mem != rj, sid = {self.sid}"
                    

                    # verify piij rj
                    map_sender_i = self.receiver_ids.index(sender_i)
                    kji = hash(f"{map_sender_i}-{hash(str(sji))}")
                    kji_fji = kji + fji
                    assert merkle_verify(
                        self.n,
                        kji_fji,
                        rj,
                        piji,
                        map_sender_i
                    ), f"Node-[{self.my_id}]: merkle_verify fail 2, sid = {self.sid}"

                    fji_val[map_sender_i] = fji
                    sji_val.append((map_sender_i + 1, sji))

                # 
                logger.debug(f'Node-[{self.my_id}]: fji_val')
                cj = decode(self.f + 1, self.n, fji_val)
                fj_out = encode(self.f + 1, self.n, cj) 

                kj_out = [None for _ in range(self.n)]
                kj_fj_out = [None for _ in range(self.n)]
                sj_out = []
                
                for i in range(self.n):
                    sji_out = self.poly.interpolate_at(sji_val, i + 1)
                    sj_out.append(sji_out)
                    kj_out[i] = hash(f'{i}-{hash(str(sji_out))}')
                    kj_fj_out[i] = kj_out[i] + fj_out[i]

                merkle_tree_out_data = merkle_tree(kj_fj_out)
                assert merkle_tree_out_data[1] == rj_mem, f"Node-[{self.my_id}]: merkle_tree_out_data[1] != rj_mem, sid = {self.sid}"

                key = sha256(int(self.poly.interpolate_at(sji_val, 0)).to_bytes(32, byteorder="big")).digest()
                mj = _load_authenticated_plaintext(SymmetricCrypto.decrypt(key, cj))

                self.forward_output[msg_type] = (mj, self.receiver_ids.index(self.my_id), self.receiver_ids.index(sender), sender)
                self.forward_output_flag[msg_type].set()
                self.forward_msg_from_others[self.receiver_ids.index(sender)] = forward_msg
                self.forward_output_queue.put_nowait((msg_type, mj, self.receiver_ids.index(self.my_id), self.receiver_ids.index(sender), sender))
                logger.debug(f'Node-[{self.my_id}]: output forward')

            elif msg[1] == SMDMessageType.EXFORWARD:
                logger.debug(f"Node-[{self.my_id}]: receive exforward message. sid = {self.sid}")

                (_, _, recv_msg) = msg
                (msg_type, forward_id, forward_msg) = recv_msg

                logger.debug(f'Node-[{self.my_id}]: msg_type = {msg_type}, sender = {sender}')

                r_mem, pij_mem, rj_mem = None, None, None
                
                fji_val = [None for _ in range(self.n)]
                sji_val = []
                for _forward_msg in forward_msg:
                    (sender_i, r, pij, rj, piji, sji, fji) = _forward_msg
                    logger.debug(f"Node-[{self.my_id}]: r={r}")
                for _forward_msg in forward_msg:
                    (sender_i, r, pij, rj, piji, sji, fji) = _forward_msg

                    
                    
                    if r_mem is None:
                        r_mem = r
                        pij_mem = pij
                        rj_mem = rj
                        assert self.tagvars[sid]['root'][self.receiver_ids.index(sender)] == r, f"Node-[{self.my_id}]: root[k]={self.tagvars[sid]['root'][self.receiver_ids.index(sender)]}, r={r}, sid = {self.sid}, sender={sender}, root_all = {self.tagvars[sid]['root']}, index ={self.receiver_ids.index(sender)}, ids = {self.receiver_ids}"
                        assert merkle_verify(
                            self.n,
                            rj,
                            r,
                            pij,
                            forward_id
                        ), f"Node-[{self.my_id}]: merkle_verify fail 1, sid = {self.sid}"
                    else:
                        assert r_mem == r, f"Node-[{self.my_id}]: r_mem != r, sid = {self.sid}"
                        assert pij_mem == pij, f"Node-[{self.my_id}]: pij_mem != pij, sid = {self.sid}"
                        assert rj_mem == rj, f"Node-[{self.my_id}]: rj_mem != rj, sid = {self.sid}"
                    

                    # verify piij rj
                    map_sender_i = self.receiver_ids.index(sender_i)
                    kji = hash(f"{map_sender_i}-{hash(str(sji))}")
                    kji_fji = kji + fji
                    assert merkle_verify(
                        self.n,
                        kji_fji,
                        rj,
                        piji,
                        map_sender_i
                    ), f"Node-[{self.my_id}]: merkle_verify fail 2, sid = {self.sid}"

                    fji_val[map_sender_i] = fji
                    sji_val.append((map_sender_i + 1, sji))

                # 
                cj = decode(self.f + 1, self.n, fji_val)
                fj_out = encode(self.f + 1, self.n, cj) 

                kj_out = [None for _ in range(self.n)]
                kj_fj_out = [None for _ in range(self.n)]
                sj_out = []
                
                for i in range(self.n):
                    sji_out = self.poly.interpolate_at(sji_val, i + 1)
                    sj_out.append(sji_out)
                    kj_out[i] = hash(f'{i}-{hash(str(sji_out))}')
                    kj_fj_out[i] = kj_out[i] + fj_out[i]

                merkle_tree_out_data = merkle_tree(kj_fj_out)
                assert merkle_tree_out_data[1] == rj_mem, f"Node-[{self.my_id}]: merkle_tree_out_data[1] != rj_mem, sid = {self.sid}"

                key = sha256(int(self.poly.interpolate_at(sji_val, 0)).to_bytes(32, byteorder="big")).digest()
                mj = SymmetricCrypto.decrypt(key, cj)
                mj = _load_authenticated_plaintext(mj)

                self.forward_output[msg_type] = (mj, self.receiver_ids.index(sender), forward_id, sender)
                self.forward_output_flag[msg_type].set()
                # self.forward_msg_from_others[forward_id] = forward_msg
                self.forward_output_queue.put_nowait((msg_type, mj, self.receiver_ids.index(sender), forward_id, sender))





                    
                    
                            
                            
                    



