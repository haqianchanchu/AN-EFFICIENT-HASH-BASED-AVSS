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
from GoSSamer.util.serializer import serialize as dumps, deserialize as loads


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# logger.setLevel(logging.ERROR)

class SMDMessageType:
    SEND = "SEND"
    ECHO = "ECHO"
    VOTE = "VOTE"
    FORWARD = "FORWARD"
    EXFORWARD = "EXFORWARD"

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
        self.output_queue = [None for _ in range(self.n)]
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

            ci = SymmetricCrypto.encrypt(key, dumps(m[i]))

            # logger.debug(f'ci = {ci}')

            for j in range(self.n):
                point = poly(j + 1)
                si.append(point)
                ki.append(hash(f'{j}-{hash(str(point))}'))
            # logger.debug(f'ki_origin for node {i}, data: {ki}')
            # logger.debug(f'si_origin for node {i}, data: {si}')
            
            # step 2 - encode
            fi = encode(self.f + 1, self.n, ci)
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
            
            # logger.debug(
            #     f'Node-[{self.my_id}]: Calculating distribute message. sid = {self.sid}')
            distribute_msg = []
            total_root = []
            for _m in m:
                _distribute_msg, _total_root = self._get_dealer_msg(_m)
                distribute_msg.append(_distribute_msg)
                total_root.append(_total_root)

            logger.debug(f'distribute_msg for node {self.my_id}, data: {distribute_msg}')
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
            self.benchmark_logger.info(f"Node-[{self.my_id}]: smd dealer distribute stage time cost: {distribute_end_time - distribute_start_time}")
            logger.debug(
                f'Node-[{self.my_id}]: All distribute message sent. sid = {self.sid}, my id = {self.my_id}, receiver_id = {self.receiver_ids}')
            
            if self.my_id == self.dealer_id and not self.my_id in self.receiver_ids:
                logger.debug(
                f'Node-[{self.my_id}]: output as exernal distributor = {self.sid}')
                self.output_flag.set()
                for k in range(self.n):
                    self.output_queue[k] = (None, total_root[k])
                return 
            

        
        from_leader = None
        echo_set = set()
        echo_msg_collector = []
        echo_counter = defaultdict(lambda: 0)
        vote_sent = False
        vote_set = set()
        vote_counter = defaultdict(lambda: 0)

        vote_threshold_1_flag = False
        vote_threshold_2_flag = False

        self.tagvars[sid] = {}
        self.tagvars[sid]['forward_msg'] = [None for _ in range(self.n)]
        self.tagvars[sid]['root'] = [None for _ in range(self.n)]


        while True:
            
            sender, msg = await self.recv()
            # self.benchmark_logger.info(f"Node-[{self.my_id}]: receive message {msg[1]} from {sender} time cost: {time.time() - distribute_start_time}")
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

                send_recv_start_time = time.time()
                # self.benchmark_logger.info(f"Node-[{self.my_id}]: send_recv time cost: {send_recv_start_time - distribute_start_time}")

                # merkle tree verification
                validation_fail_flag = False
                roots = [[] for _ in range(self.n)]
                merkle_tree_root_data = []


                
                for k in range(self.n): 
                    for i in range(self.n):
                        (root, branch, sij, fij) = distribute_msg[k][i]

                        logger.debug(
                            f'Node-[{self.my_id}]: unpack message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, sid = {self.sid}'
                        )
                        roots[k].append(root)
                        kij = hash(f"{pid}-{hash(str(sij))}")
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

                    logger.debug(f"Node-[{self.my_id}]: verification kij_fij success for {k}-th message")
                    
                    # build root merkle tree
                    
                    merkle_tree_root_data.append(merkle_tree(roots[k]))
                    # logger.debug(f"Node-[{self.my_id}]: total_root = {merkle_tree_root_data[1]}, roots = {roots}")
                send_recv_end_time = time.time()
                # self.benchmark_logger.info(f"Node-[{self.my_id}]: before echo sent time cost: {send_recv_end_time - distribute_start_time}")
                
                echo_msg_start_time = time.time()
                for i in range(self.n):
                    msg_echo = []
                    for k in range(self.n):
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
                        self.receiver_ids[i],
                        (
                            sid,
                            SMDMessageType.ECHO,
                            msg_echo
                        )
                    )
                
             
                from_leader = pid

                

            elif msg[1] == SMDMessageType.ECHO:
                logger.debug(
                    f'Node-[{self.my_id}]: receive echo message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, msg = {msg}' 
                )
                if sender in echo_set:
                    logger.info("[{pid}] Redundant ECHO")
                    continue
                # Update
                echo_set.add(sender)
               

                msg_echo = msg[2]
                _echo_msg_collector = []
                root = []
                for k in range(self.n):
                    (r, pij, rj, piji, sji, fji) = msg_echo[k]
                    _echo_msg_collector.append((sender, r, pij, rj, piji, sji, fji))

                    root.append(r)
                    echo_counter[r] = echo_counter[r] + 1

                echo_msg_collector.append(_echo_msg_collector)

                if not vote_sent:
                    if [echo_counter[r] >= echo_threshold for r in root]:
                        logger.debug(
                            f'Node-[{self.my_id}]: send vote message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, root: {root}' 
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
                    # unpack
                    echo_msg_same_root = [[] for _ in range(self.n)]
                    for _echo_msg_collector in echo_msg_collector:
                        for k in range(self.n):
                            (sender, r, pij, rj, piji, sji, fji) = _echo_msg_collector[k]
                            if r == root[k]:
                                echo_msg_same_root[k].append(_echo_msg_collector[k])
                    logger.debug(
                        f"Node-[{self.my_id}]: message unpacked. sid = {self.sid}, echo_msg_same_root = {echo_msg_same_root}"
                    )
                    

                    logger.debug(
                        f"Node-[{self.my_id}]: echo_msg_same_root = {echo_msg_same_root}. sid = {self.sid}"
                    )
                    echo_msg_val = [[] for _ in range(self.n)]
                    fji_val = [[None for _ in range(self.n)] for _ in range(self.n)]
                    sji_val = [[] for _ in range(self.n)]
                    val_flag = [False for _ in range(self.n)]
                    rj_val = [None for _ in range(self.n)]
                    pij_val = [None for _ in range(self.n)]
                    output_flag = [False for _ in range(self.n)]

                    logger.debug(f"Node-[{self.my_id}]: Starting to process echo_msg_same_root. sid = {self.sid}")
                    start_time = time.time()
                    for k in range(self.n):
                        logger.debug(f"Node-[{self.my_id}]: Processing k={k}. sid = {self.sid}")
                        output_msg = []

                        for _echo_msg_collector in echo_msg_same_root[k]:
                            logger.debug(f"Node-[{self.my_id}]: Processing echo_msg_collector. sid = {self.sid}")
                            (sender_i, r, pij, rj, piji, sji, fji) = _echo_msg_collector
                            
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
                                        f"Node-[{self.my_id}]: sid = {sid}, fji_val = {fji_val[k]}, sender_i = {sender_i}"
                                    )
                                    fji_val[k][self.receiver_ids.index(sender_i)] = fji
                                    sji_val[k].append((map_sender_id, sji))
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
                                logger.debug(f'Node-[{self.my_id}]: self.tagvars[sid]["forward_msg"] = {self.tagvars[sid]["forward_msg"]}')

                                logger.debug(
                                    f"Node-[{self.my_id}]: 3"
                                )

                                if not self.output_flag.is_set():

                                    logger.debug(f'fji_val: {fji_val[k]}')
                                    cj = decode(self.f + 1, self.n, fji_val[k])
                                    logger.debug(f'cj_decode for node {self.my_id}, data: {cj}')  

                                    fj_out = encode(self.f + 1, self.n, cj)
                                    logger.debug(f'fj_out for node {self.my_id}, data: {fj_out}')  
                                    # logger.debug(f'sji_val for node {self.my_id}, data: {sji_val}') 

                                    kj_out = [None for _ in range(self.n)]
                                    kj_fj_out = [None for _ in range(self.n)]
                                    sj_out = []
                                    
                                    for i in range(self.n):
                                        sji_out = self.poly.interpolate_at(sji_val[k], i)
                                        sj_out.append(sji_out)
                                        kj_out[i] = hash(f'{i}-{hash(str(sji_out))}')
                                        kj_fj_out[i] = kj_out[i] + fj_out[i]
                                    
                                    # logger.debug(f'kj_out for node {self.my_id}, data: {kj_out}')
                                    # logger.debug(f'sj_out for node {self.my_id}, data: {sj_out}')
                                    # logger.debug(f'kj_fj_out for node {self.my_id}, data: {kj_fj_out}')
                                    merkle_tree_out_data = merkle_tree(kj_fj_out)
                                    logger.debug(f'root of merkle_tree_out_data for node {self.my_id}, data: {merkle_tree_out_data[1]}, root_val: {rj_val}, k={k}')
                                    
                                    if merkle_tree_out_data[1] == rj_val[k]:
                                        key = sha256(int(self.poly.interpolate_at(sji_val[k], 0)).to_bytes(32, byteorder="big")).digest()
                                        # logger.debug(f'key for node {self.my_id}, data: {key}')
                                        mj = SymmetricCrypto.decrypt(key, cj)
                                        mj = loads(mj)
                                        # logger.debug(f'Node-[{self.my_id}]: output mj as node {self.my_id}, dealer: {self.dealer_id}, data: {mj}')
                                        self.output_queue[k] = (mj, root[k])
                                        self.tagvars[sid]['root'][k] = root[k]
                                        logger.debug(f"Node-[{self.my_id}]: output mj as node {self.my_id}, dealer: {self.dealer_id}, data: {mj}, k={k}")
                                        output_flag[k] = True
                                        # self.benchmark_logger.info(f"Node-[{self.my_id}]: output_flag = {output_flag}")
                                        if all(output_flag):
                                            end_time = time.time()
                                            self.output_flag.set()
                                            # self.benchmark_logger.info(f"Node-[{self.my_id}]: final time cost: {end_time - distribute_start_time}")
                                        break
                                    else:
                                        logger.error(
                                            f'Failed to verify final message. Id: {self.my_id}, Dealer Id: {self.dealer_id}'
                                        )

            elif msg[1] == SMDMessageType.FORWARD:
                logger.debug(f"Node-[{self.my_id}]: receive forward message. sid = {self.sid}")

                (_, _, recv_msg) = msg
                (msg_type, forward_msg) = recv_msg


                logger.debug(f'Node-[{self.my_id}]: msg_type = {msg_type}, sender = {sender}, forward_msg = {forward_msg}')

                r_mem, pij_mem, rj_mem = None, None, None
                
                fji_val = [None for _ in range(self.n)]
                sji_val = []
                for _forward_msg in forward_msg:
                    (sender_i, r, pij, rj, piji, sji, fji) = _forward_msg
                    
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
                    sji_val.append((map_sender_i, sji))

                # 
                logger.debug(f'Node-[{self.my_id}]: fji_val forward = {fji_val}')
                cj = decode(self.f + 1, self.n, fji_val)
                fj_out = encode(self.f + 1, self.n, cj) 

                kj_out = [None for _ in range(self.n)]
                kj_fj_out = [None for _ in range(self.n)]
                sj_out = []
                
                for i in range(self.n):
                    sji_out = self.poly.interpolate_at(sji_val, i)
                    sj_out.append(sji_out)
                    kj_out[i] = hash(f'{i}-{hash(str(sji_out))}')
                    kj_fj_out[i] = kj_out[i] + fj_out[i]

                merkle_tree_out_data = merkle_tree(kj_fj_out)
                assert merkle_tree_out_data[1] == rj_mem, f"Node-[{self.my_id}]: merkle_tree_out_data[1] != rj_mem, sid = {self.sid}"

                key = sha256(int(self.poly.interpolate_at(sji_val, 0)).to_bytes(32, byteorder="big")).digest()
                mj = loads(SymmetricCrypto.decrypt(key, cj))

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
                    sji_val.append((map_sender_i, sji))

                # 
                cj = decode(self.f + 1, self.n, fji_val)
                fj_out = encode(self.f + 1, self.n, cj) 

                kj_out = [None for _ in range(self.n)]
                kj_fj_out = [None for _ in range(self.n)]
                sj_out = []
                
                for i in range(self.n):
                    sji_out = self.poly.interpolate_at(sji_val, i)
                    sj_out.append(sji_out)
                    kj_out[i] = hash(f'{i}-{hash(str(sji_out))}')
                    kj_fj_out[i] = kj_out[i] + fj_out[i]

                merkle_tree_out_data = merkle_tree(kj_fj_out)
                assert merkle_tree_out_data[1] == rj_mem, f"Node-[{self.my_id}]: merkle_tree_out_data[1] != rj_mem, sid = {self.sid}"

                key = sha256(int(self.poly.interpolate_at(sji_val, 0)).to_bytes(32, byteorder="big")).digest()
                mj = SymmetricCrypto.decrypt(key, cj)
                mj = loads(mj)

                self.forward_output[msg_type] = (mj, self.receiver_ids.index(sender), forward_id, sender)
                self.forward_output_flag[msg_type].set()
                # self.forward_msg_from_others[forward_id] = forward_msg
                self.forward_output_queue.put_nowait((msg_type, mj, self.receiver_ids.index(sender), forward_id, sender))





                    
                    
                            
                            
                    


