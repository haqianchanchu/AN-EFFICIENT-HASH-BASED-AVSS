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
from GoSSamer.crypto.field import GFElement

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# logger.setLevel(logging.ERROR)

class SMDMessageType:
    SEND = "SEND"
    ECHO = "ECHO"
    VOTE = "VOTE"
    FORWARD = "FORWARD"

class SMD_SS24:
    def __init__(
            self, sid, n, f, my_id, dealer_id, output, send, recv, field, receiver_ids
    ):
        # GF & GFElement is tested
        self.n, self.f, self.dealer_id = n, f, dealer_id
        self.my_id = my_id
        self.sid = sid
        

        self.recv = recv
        self.send = send

        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = output
        self.sr = Serial(self.field)
        self.tagvars = {}
        self.receiver_ids = receiver_ids

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        logger.debug(f'create smd task')
    
    def _get_dealer_msg(self, m):
        # m is a list of messages [m1, ..., mn]
        assert len(m) == self.n
        s = []
        f = []
        send_data = []
        merkle_tree_data = []
        k_f = []
        roots = []
        
        for i in range(self.n):
            poly = self.poly.random(self.f)
            si = []
            ki = []

            # step 1 - enc
            key = sha256(int(poly(1)).to_bytes(32, byteorder="big")).digest()

            # logger.debug(f'key_origin for node {i}, data: {key}')

            ci = SymmetricCrypto.encrypt(key, m[i])

            # logger.debug(f'ci = {ci}')

            for j in range(self.n):
                point = poly(j + 1).to_bytes()
                si.append(point)
                ki.append(hash(f'{j}-{hash(point)}'))
            # logger.debug(f'ki_origin for node {i}, data: {ki}')
            # logger.debug(f'si_origin for node {i}, data: {si}')
            
            # step 2 - encode
            fi = encode(self.f, self.n, ci)
            # logger.debug(f'ci_original for node {i}, data: {ci} ')
            # logger.debug(f'fi_original for node {i}, data: {fi} ')
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
            for i in range(self.n):
                dataji = (merkle_tree_data[i][1], get_merkle_branch(j, merkle_tree_data[i]), s[i][j], f[i][j])
                dataj.append(dataji)
                # logger.debug(
                #     f'Node-[{self.my_id}]: Calculating distribute message (phase 3). Id: {self.my_id}, Dealer Id: {self.dealer_id}, {j}-receiver-{i}-msg, dataji: {dataji}')   
            data.append(dataj)

        for j in range(self.n):
            for i in range(self.n):
                if not merkle_verify(self.n, k_f[i][j], merkle_tree_data[i][1], get_merkle_branch(j, merkle_tree_data[i]), j):
                    logger.error(
                        f'Node-[{self.my_id}]: Failed to verify from dealer -2. Id: {self.my_id}, Dealer Id: {self.dealer_id}, receiver: {j}, sequence: {i}'
                    )
        logger.debug(f'Node-[{self.my_id}]: Final dealer message get. sid = {self.sid}')

        total_root = merkle_tree(roots)[1]
        # logger.debug(f'total root: {total_root}')
        return data, total_root
    
    async def forward(self, receiver_id=None):
        forward_msg = self.tagvars[self.sid]['forward_msg']
        self.send(
            receiver_id,
            (
                self.sid, 
                SMDMessageType.FORWARD,
                forward_msg
            )
        )
        return
        
    async def forward_multicast(self):
        return
    
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
            
            # logger.debug(
            #     f'Node-[{self.my_id}]: Calculating distribute message. sid = {self.sid}')

            distribute_msg, total_root = self._get_dealer_msg(m)

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
            logger.debug(
                f'Node-[{self.my_id}]: All distribute message sent. sid = {self.sid}, my id = {self.my_id}, receiver_id = {self.receiver_ids}')
            
            if self.my_id == self.dealer_id and not self.my_id in self.receiver_ids:
                logger.debug(
                f'Node-[{self.my_id}]: output as exernal distributor = {self.sid}')
                self.output_queue((None, total_root))
                return 
            

        
        from_leader = None
        echo_set = set()
        echo_msg_collector = []
        echo_counter = defaultdict(lambda: 0)
        vote_sent = False
        vote_set = set()
        vote_counter = defaultdict(lambda: 0)

        self.tagvars[sid] = {}


        while True:
            
            sender, msg = await self.recv()
            logger.debug(
                f"Node-[{self.my_id}]: receive message. sender: {sender}, sid = {self.sid}"
            )
            # if msg[1] == SMDMessageType.FORWARD:
            #     (_, _, forward_msg) = msg
            #     for _forward_msg in forward_msg:
            #         self._verify_echo_msg(_forward_msg)

            
            
            if msg[1] == SMDMessageType.SEND and from_leader is None:
                logger.debug(
                    f"Node-[{self.my_id}]: receive send message. sender: {sender}, sid = {self.sid}"
                )
                # Validation
                (_, _, distribute_msg) = msg
                # if sender != self.dealer_id:
                #     logger.warning(
                #         "[%d] VAL message from other than leader: %d", pid, sender
                #     )
                #     continue

                # logger.debug(
                #         f'Node-[{self.my_id}]: dealer verification success: {self.my_id}, Dealer Id: {self.dealer_id}'
                #     )

                # merkle tree verification
                validation_fail_flag = False
                roots = []
                for i in range(self.n):
                    (root, branch, sij, fij) = distribute_msg[i]

                    logger.debug(
                        f'Node-[{self.my_id}]: unpack message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, sid = {self.sid}'
                    )
                    roots.append(root)
                    kij = hash(f"{pid}-{hash(sij)}")
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
                    continue

                logger.debug(f"verification kij_fij success")
                
                # build root merkle tree
                
                merkle_tree_root_data = merkle_tree(roots)
                # logger.debug(f"Node-[{self.my_id}]: total_root = {merkle_tree_root_data[1]}, roots = {roots}")
                for i in range(self.n):
                    (root, branch, sij, fij) = distribute_msg[i]
                    self.send(
                        self.receiver_ids[i],
                        (
                            sid,
                            SMDMessageType.ECHO,
                            merkle_tree_root_data[1],
                            get_merkle_branch(i, merkle_tree_root_data),
                            root,
                            branch,
                            sij,
                            fij
                        )
                    )
                
                from_leader = pid

                

            elif msg[1] == SMDMessageType.ECHO:
                logger.debug(
                    f'Node-[{self.my_id}]: receive echo message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, root: {msg[2]}' 
                )
                root = msg[2]
                # Validation
                if sender in echo_set:
                    logger.info("[{pid}] Redundant ECHO")
                    continue
                # Update
                echo_set.add(sender)
                echo_counter[root] = echo_counter[root] + 1

                # collect message
                (_, _, r, pij, rj, piji, sji, fji) = msg
                echo_msg_collector.append((sender, r, pij, rj, piji, sji, fji))


                if echo_counter[root] >= echo_threshold and not vote_sent:
                    logger.debug(
                        f'Node-[{self.my_id}]: send vote message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, root: {root}' 
                    )
                    vote_sent = True
                    broadcast((sid, SMDMessageType.VOTE, root))

            elif msg[1] == SMDMessageType.VOTE:
                root = msg[2]
                if sender in vote_set:
                    logger.info("[{pid}] Redundant VOTE")
                    continue
                vote_set.add(sender)
                vote_counter[root] = vote_counter[root] + 1
                if vote_counter[root] >= vote_threshold_1 and not vote_sent:
                    vote_sent = True
                    broadcast((sid, SMDMessageType.VOTE, root))

                
                if vote_counter[root] >= vote_threshold_2:
                    logger.debug(
                        f"Node-[{self.my_id}]: receive n-t vote message, verify and output. sid = {self.sid}"
                    )
                    # unpack
                    echo_msg_same_root = []
                    for _echo_msg_collector in echo_msg_collector:
                        (sender, r, pij, rj, piji, sji, fji) = _echo_msg_collector
                        if r == root:
                            echo_msg_same_root.append(_echo_msg_collector)
                    logger.debug(
                        f"Node-[{self.my_id}]: message unpacked. sid = {self.sid}"
                    )
                    
                    echo_msg_val = []
                    fji_val = [None for _ in range(self.n)]
                    sji_val = []
                    val_flag = False
                    rj_val = None
                    pij_val = None

                    logger.debug(
                        f"Node-[{self.my_id}]: echo_msg_same_root = {echo_msg_same_root}. sid = {self.sid}"
                    )
                    
                    for _echo_msg_collector in echo_msg_same_root:


                        (sender_i, r, pij, rj, piji, sji, fji) = _echo_msg_collector
                        
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
                            else:
                                logger.error(f"Node-[{self.my_id}]: merkle_verify( \
                                    self.n, \
                                    rj, \
                                    r, \
                                    pij, \
                                    pid \
                                ) fail, sid = {self.sid}")

                        logger.debug(
                                f"Node-[{self.my_id}]: 1"
                            )

                        if val_flag == True and rj_val == rj and pij_val == pij:
                            map_sender_id = self.receiver_ids.index(sender_i)
                            kji = hash(f"{map_sender_id}-{hash(sji)}")
                            kji_fji = kji + fji
                            if merkle_verify(
                                self.n,
                                kji_fji,
                                rj,
                                piji,
                                map_sender_id
                            ):  
                                echo_msg_val.append((sender_i, r, pij, rj, piji, sji, fji))
                                logger.debug(
                                    f"Node-[{self.my_id}]: sid = {sid}, fji_val = {fji_val}, sender_i = {sender_i}"
                                )
                                fji_val[self.receiver_ids.index(sender_i)] = fji
                                sji_val.append((map_sender_id, GFElement.from_bytes(sji, self.field)))
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

                        if len(echo_msg_val) >= rec_threshold:
                            self.tagvars[sid]["forward_msg"] = echo_msg_val

                            logger.debug(
                                f"Node-[{self.my_id}]: 3"
                            )

                            logger.debug(f'fji_val: {fji_val}')
                            cj = decode(self.f, self.n, fji_val)
                            # logger.debug(f'cj_decode for node {self.my_id}, data: {cj}')  

                            fj_out = encode(self.f, self.n, cj)
                            # logger.debug(f'fj_out for node {self.my_id}, data: {fj_out}')  
                            # logger.debug(f'sji_val for node {self.my_id}, data: {sji_val}') 

                            kj_out = [None for _ in range(self.n)]
                            kj_fj_out = [None for _ in range(self.n)]
                            sj_out = []
                            start_time = time.time()
                            for i in range(self.n):
                                sji_out = self.poly.interpolate_at(sji_val, i).to_bytes()
                                sj_out.append(sji_out)
                                kj_out[i] = hash(f'{i}-{hash(sji_out)}')
                                kj_fj_out[i] = kj_out[i] + fj_out[i]
                            time_cost = time.time() - start_time
                            self.benchmark_logger.info(f"interpolate time cost: {time_cost}")
                            # logger.debug(f'kj_out for node {self.my_id}, data: {kj_out}')
                            # logger.debug(f'sj_out for node {self.my_id}, data: {sj_out}')
                            # logger.debug(f'kj_fj_out for node {self.my_id}, data: {kj_fj_out}')
                            merkle_tree_out_data = merkle_tree(kj_fj_out)
                            logger.debug(f'root of merkle_tree_out_data for node {self.my_id}, data: {merkle_tree_out_data[1]}, root_val: {rj_val}')
                            
                            if merkle_tree_out_data[1] == rj_val:
                                key = sha256(int(self.poly.interpolate_at(sji_val, 0)).to_bytes(32, byteorder="big")).digest()
                                # logger.debug(f'key for node {self.my_id}, data: {key}')
                                mj = SymmetricCrypto.decrypt(key, cj)
                                # logger.debug(f'Node-[{self.my_id}]: output mj as node {self.my_id}, dealer: {self.dealer_id}, data: {mj}')
                                self.output_queue((mj, root))
                                # logger.debug(f'Node-[{self.my_id}]: output root as node {self.my_id}, dealer: {self.dealer_id}, root: {root}')
                                logger.debug(f'Node-[{self.my_id}]: output in smd, tag = {sid}')

                                return
                            else:
                                logger.error(
                                    f'Failed to verify final message. Id: {self.my_id}, Dealer Id: {self.dealer_id}'
                                )
                                return

                        
                    

