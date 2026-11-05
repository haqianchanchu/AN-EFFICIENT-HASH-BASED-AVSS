import time


from GoSSamer.crypto.polynomial import polynomials_over
from GoSSamer.util.misc import wrap_send, subscribe_recv
from GoSSamer.crypto.symmetric_crypto import SymmetricCrypto
from GoSSamer.distribute.encode import encode, decode, merkle_tree, get_merkle_branch, hash, merkle_verify
from GoSSamer.util.serilization import Serial
from collections import defaultdict, deque
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
        self.n, self.f, self.dealer_id = n, f, dealer_id  # f为最大故障数
        self.my_id = my_id  # 当前节点ID
        self.sid = sid  # 协议实例ID

        self.recv = recv  # 消息接收函数
        self.send = send  # 消息发送函数

        self.field = field  # 有限域（用于多项式运算）
        self.poly = polynomials_over(self.field)  # 多项式类
        self.poly.clear_cache()
        self.output_queue = output  # 结果输出队列
        self.sr = Serial(self.field)
        self.tagvars = {}
        self.receiver_ids = receiver_ids  # 接收方ID列表
        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
        self.output_flag = asyncio.Event()
        self.mj=None
        self.forward_output = {}
        self.forward_output_flag = defaultdict(lambda: asyncio.Event())
        self.forward_msg_from_others = [None for _ in range(self.n)]
        self.forward_output_flag_event = asyncio.Event()
        self.forward_output_queue = asyncio.Queue()
        self.deal_challenge = asyncio.Queue()

        logger.debug(f'create smd task')

    def _get_dealer_msg(self, m):  # 发送方生成分发消息，包括加密消息、多项式份额、验证数据
        # m is a list of messages [m1, ..., mn]
        start_time = time.time()
        s = []
        f = []
        send_data = []
        merkle_tree_data = []
        k_f = []
        roots = []
        for i in range(self.n):
            poly = self.poly.random(self.f)  # 生成随机多项式（次数为f）
            si = []
            ki = []

            logger.info(f"{i}-cycle time-1 {time.time()-start_time}")

            # step 1 - enc
            key = sha256(int(poly(1)).to_bytes(32, byteorder="big")).digest()  # 用多项式在x=1处的值生成加密密钥
            #logger.debug(f'key_origin for node {i}, data: {key}')

            logger.info(f"{i}-cycle time-12 {time.time()-start_time}")
            dmi = dumps(m[i])

            logger.info(f"{i}-cycle time-123 {time.time()-start_time}")

            ci = SymmetricCrypto.encrypt(key, dmi)  # 加密消息Encrypt(ki0, mi)
            #logger.debug(f'serialization is {dumps(m[i])},ci = {ci}')

            logger.info(f"{i}-cycle time-2 {time.time()-start_time}, len: {len(ci)}")

            for j in range(self.n):
                point = poly(j + 1)
                si.append(point)
                ki.append(hash(f'{j}-{hash(str(point))}'))
            # logger.debug(f'ki_origin for node {i}, data: {ki}')
            # logger.debug(f'si_origin for node {i}, data: {si}')

            logger.info(f"{i}-cycle time-3 {time.time()-start_time}")

            # step 2 - encode
            fi = encode(self.f +1, self.n, ci)
            #logger.debug(f'ci_original for node {i}, data: {ci} ')
            #logger.debug(f'fi_original for node {i}, data: {fi} ')
            logger.info(f"{i}-cycle time-4 {time.time()-start_time}")
            ki_fi = []
            for j in range(self.n):
                # logger.debug(
                #         f'kij_fij_1. Id: {self.my_id}, Dealer Id: {self.dealer_id}, receiver: {j}, sequence: {i}, msg: {ki[j]+fi[j]}'
                #     )
                ki_fi.append((ki[j] + fi[j]))  # 为(k_i1,f_i1)……构造merkle树
            k_f.append(ki_fi)
            # logger.debug(f'ki_fi_origin for node {i}, data: {ki_fi}')

            merkle_tree_data.append(merkle_tree(ki_fi))
            roots.append(merkle_tree_data[i][1])  # merkle_tree_data[][1]存的是根哈希
            # for j in range(self.n):  # 验证Merkle分支（确保数据完整性）


            #     if not merkle_verify(self.n, ki_fi[j], merkle_tree_data[i][1],
            #                          get_merkle_branch(j, merkle_tree_data[i]), j):
            #         logger.error(
            #             f'Failed to verify from dealer. Id: {self.my_id}, Dealer Id: {self.dealer_id}, receiver: {j}, sequence: {i}'
            #         )
            f.append(fi)
            s.append(si)

        # logger.debug(
        #     f'Calculating distribute message (phase 1 + phase 2). Id: {self.my_id}, Dealer Id: {self.dealer_id}, message: {m}')
        # step 3 - organize data
        data = []  # data[j] is data for node j
        for j in range(self.n):  # 构造分发给每个接收方的数,外层循环：遍历所有接收方 j（0 到 n-1）
            dataj = []
            for i in range(self.n):  # 内层循环：为每个接收方 j 准备所有消息 i 的验证数据
                dataji = (merkle_tree_data[i][1], get_merkle_branch(j, merkle_tree_data[i]), s[i][j], f[i][j])
                dataj.append(dataji)
                # logger.debug(
                #     f'Node-[{self.my_id}]: Calculating distribute message (phase 3). Id: {self.my_id}, Dealer Id: {self.dealer_id}, {j}-receiver-{i}-msg, dataji: {dataji}')
            data.append(dataj)
        logger.info(f"time-5 {time.time()-start_time}")
        #logger.debug(f'---data is {data}')
        # for j in range(self.n):  # 验证数据完整性,使用 k_f[i][j] 和验证路径计算根哈希
        #     for i in range(self.n):
        #         if not merkle_verify(self.n, k_f[i][j], merkle_tree_data[i][1],
        #                              get_merkle_branch(j, merkle_tree_data[i]), j):
        #             logger.error(
        #                 f'Node-[{self.my_id}]: Failed to verify from dealer -2. Id: {self.my_id}, Dealer Id: {self.dealer_id}, receiver: {j}, sequence: {i}'
        #             )
        # logger.debug(f'Node-[{self.my_id}]: Final dealer message get. sid = {self.sid}')

        total_root = merkle_tree(roots)[1]
        # logger.debug(f'total root: {total_root}')
        return data, total_root

    def _decode_forward_payload(self, sid, owner, proof):
        """Verify the full fragment list for one original message (paper Sec. 4.3)."""
        if type(owner) is not int or not 0 <= owner < self.n:
            raise ValueError('invalid original owner')
        if not isinstance(proof, (tuple, list)) or not self.f + 1 <= len(proof) <= self.n:
            raise ValueError('invalid fragment count')
        fragments = [None] * self.n
        points, seen = [], set()
        root = self.tagvars[sid]['root']
        owner_root = None
        for provider, r, branch, rj, leaf_branch, share, fragment in proof:
            index = self.receiver_ids.index(provider)
            if index in seen:
                raise ValueError('duplicate fragment provider')
            seen.add(index)
            if r != root or not merkle_verify(self.n, rj, root, branch, owner):
                raise ValueError('wrong root or original owner')
            if owner_root is not None and owner_root != rj:
                raise ValueError('mixed message roots')
            owner_root = rj
            leaf = hash(f"{index}-{hash(str(share))}") + fragment
            if not merkle_verify(self.n, leaf, rj, leaf_branch, index):
                raise ValueError('invalid fragment proof')
            fragments[index] = fragment
            points.append((index, share))
        ciphertext = decode(self.f + 1, self.n, fragments)
        encoded = encode(self.f + 1, self.n, ciphertext)
        leaves = [hash(f"{i}-{hash(str(self.poly.interpolate_at(points, i)))}") + encoded[i]
                  for i in range(self.n)]
        if merkle_tree(leaves)[1] != owner_root:
            raise ValueError('inconsistent reconstruction')
        key = sha256(int(self.poly.interpolate_at(points, 0)).to_bytes(32, 'big')).digest()
        return loads(SymmetricCrypto.decrypt(key, ciphertext))

    def forward(self, receiver_id=None,msg_type=None):
        forward_msg = self.tagvars[self.sid]['forward_msg']
        logger.debug(f'5555555Node [{self.my_id}] and sid is [{self.sid}]receiver id is {receiver_id} :forward_msg is {forward_msg}')
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
        logger.debug(f'Node-[{self.my_id}]: forward, receiver_id = {receiver_id}, msg_type = {msg_type}')
    def exforward(self, receiver_id, msg_type, forward_id):
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
    async def forward_multicast(self):  # 消息广播
        return

    def _verify_echo_msg(self, pid, _echo_msg_collector):  # 验证 ECHO 消息
        (sender_i, r, pij, rj, piji, sji, fji) = _echo_msg_collector

        echo_msg_val = []
        fji_val = [None for _ in range(self.n)]  # 存储有效编码消息，用于后续解码
        sji_val = []  # 存储有效多项式份额
        val_flag = False
        rj_val = None
        pij_val = None
        if rj_val is None and pij_val is None:  # 第一阶段验证：验证 π_ij（即代码中的 pij）是否是 (H(j, s_ij), f_ij) 在根 r_i（代码中 rj）下的正确验证路径，且进一步关联到全局根 r
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

        if val_flag == True and rj_val == rj and pij_val == pij:  # 第二阶段验证：验证 (H(i, s_ij), f_ij) 是否属于 r_j
            kji = hash(f"{sender_i}-{hash(sji)}")  # 对应H(i, s_ij)
            kji_fji = kji + fji  # 待验证的数据块 = H(i, s_ij) || f_ij
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

        echo_threshold = self.n - self.f  # 需要收集的 ECHO 消息数量（n-f），确保多数节点确认
        vote_threshold_1 = self.f + 1  # 触发 VOTE 消息的最小数量（f+1）
        vote_threshold_2 = self.n - self.f  # 达成共识所需的 VOTE 消息数量（n-f）
        rec_threshold = self.f + 1  # 恢复原始消息所需的最小有效份额数（f+1）

        leader = self.dealer_id
        sid = self.sid

        if not self.my_id == self.dealer_id:
            pid = self.receiver_ids.index(self.my_id)  # 接收方从 receiver_ids 中查找自身索引作为进程 ID
        else:
            pid = self.dealer_id  # 发送方直接使用 dealer_id 作为进程 ID

        def broadcast(o):
            for i in range(self.n):
                self.send(self.receiver_ids[i], o)

        logger.debug(f"Node-[{self.my_id}]: init distribute, pid = {pid}")

        if self.my_id == leader:  # 发送方逻辑

            # logger.debug(
            #     f'Node-[{self.my_id}]: Calculating distribute message. sid = {self.sid}')
            distribute_msg, total_root = self._get_dealer_msg(
                m)  # distribute_msg是一个长度为 n 的列表，其中每个元素对应一个接收方 j 的数据包(root, branch, sij, fij)
            #logger.debug(f'Node-[{self.my_id}]: Sending distribute message. sid = {self.sid}, distribution message is {distribute_msg}')

            for j in range(self.n):
                #logger.debug(f'Node-[{self.my_id}]: Sending distribute message to {self.receiver_ids[j]}. sid = {self.sid}, msg = {distribute_msg[j]}')
                self.send(  # 向每个接收方发送包含多项式份额、Merkle 树路径的消息
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

            if self.my_id == self.dealer_id and not self.my_id in self.receiver_ids:  # 若发送方不参与接收（my_id 不在 receiver_ids 中），直接输出全局根哈希并退出
                logger.debug(
                    f'Node-[{self.my_id}]: output as exernal distributor = {self.sid}')
                self.output_flag.set()
                self.output_queue((None, total_root))
                return

        from_leader = None
        echo_set = set()  # 已接收的 ECHO 消息发送方集合
        echo_msg_collector = []
        echo_counter = defaultdict(lambda: 0)  # 按根哈希分组的 ECHO 消息计数器
        vote_sent = False  # 是否已发送 VOTE 消息的标志
        vote_set = set()
        vote_counter = defaultdict(lambda: 0)  # 按根哈希分组的 VOTE 消息计数器

        vote_threshold_1_flag = False
        vote_threshold_2_flag = False

        self.tagvars[sid] = {}
        self.tagvars[sid]['forward_msg'] = None
        self.tagvars[sid]['root'] = None
        pending_forwards = deque()

        while True:

            if pending_forwards and self.output_flag.is_set():
                sender, msg = pending_forwards.popleft()
            else:
                sender, msg = await self.recv()
            # Other receivers may finish SMD and forward before our root is
            # committed. Authenticate against our root once it is available.
            if msg[1] in (SMDMessageType.FORWARD, SMDMessageType.EXFORWARD) and not self.output_flag.is_set():
                pending_forwards.append((sender, msg))
                continue
            logger.debug(
                f"Node-[{self.my_id}]: receive message. sender: {sender}, sid = {self.sid},and message type is {msg[1]}"
            )
            # if msg[1] == SMDMessageType.FORWARD:
            #     (_, _, forward_msg) = msg
            #     for _forward_msg in forward_msg:
            #         self._verify_echo_msg(_forward_msg)

            if msg[1] == SMDMessageType.SEND and from_leader is None:  # msg[1]是消息类型
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
                roots = []  # 存的是协议中的所有ri
                for i in range(self.n):
                    (root, branch, sij, fij) = distribute_msg[i]

                    logger.debug(
                        f'Node-[{self.my_id}]: unpack message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, sid = {self.sid}'
                    )
                    roots.append(root)
                    kij = hash(f"{pid}-{hash(str(sij))}")  # kij=H(j, sij )
                    kij_fij = kij + fij

                    # logger.debug(
                    #     f'Node-[{self.my_id}]: kij_fij. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, sequence: {i},sid = {self.sid}'
                    # )
                    if not merkle_verify(  # 验证 kij_fij 是否属于 rj，这里的root是rj
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

                merkle_tree_root_data = merkle_tree(roots)  # 将所有消息的根哈希 roots 作为叶子节点，构建以 merkle_tree_root_data[1] 为根的树
                # logger.debug(f"Node-[{self.my_id}]: total_root = {merkle_tree_root_data[1]}, roots = {roots}")
                for i in range(self.n):
                    (root, branch, sij, fij) = distribute_msg[
                        i]  # 发送方为接收方 i 准备的数据包,包含接收方 i 的局部 Merkle 树根哈希（r_i）、叶子到ri的验证路径、多项式份额和编码后的消息分片
                    self.send(
                        self.receiver_ids[i],
                        (
                            sid,
                            SMDMessageType.ECHO,
                            merkle_tree_root_data[1],  # 全局根哈希r
                            get_merkle_branch(i, merkle_tree_root_data),  # r_i的验证路径，验证局部根哈希 r_i 是否属于全局根哈希 r
                            root,  # 局部根哈希r_i
                            branch,  # 局部验证路径pi_ij，用于验证叶子节点数据（如 (H(i, s_ij), f_ij)）是否属于局部根哈希 r_i
                            sij,
                            fij
                        )
                    )

                from_leader = pid



            elif msg[1] == SMDMessageType.ECHO:
                logger.debug(
                    f'Node-[{self.my_id}]: receive echo message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, sender: {sender}, root: {msg[2]}'
                )
                root = msg[2]  # 全局 Merkle 树的根哈希
                # Validation
                if sender in echo_set:  # 忽略重复的 ECHO 消息
                    logger.info("[{pid}] Redundant ECHO")
                    continue
                # Update
                echo_set.add(sender)
                echo_counter[root] = echo_counter[root] + 1  # 统计每个根哈希的 ECHO 消息数量

                # collect message
                (_, _, r, pij, rj, piji, sji, fji) = msg
                echo_msg_collector.append((sender, r, pij, rj, piji, sji, fji))
                receive_echo_time = time.time()
                logger.info(f"receive echo time:{receive_echo_time-distribute_start_time}")

                if echo_counter[
                    root] >= echo_threshold and not vote_sent:  # 当某个根哈希的 ECHO 消息达到阈值（n-f）时，广播 VOTE 消息表示认可该根哈希
                    logger.debug(
                        f'Node-[{self.my_id}]: send vote message. Id: {self.my_id}, Dealer Id: {self.dealer_id}, root: {root}'
                    )
                    logger.info(f"receive enough echo time: {time.time()-distribute_start_time}")
                    vote_sent = True
                    broadcast((sid, SMDMessageType.VOTE, root))

            elif msg[1] == SMDMessageType.VOTE and not self.output_flag.is_set():
                root = msg[2]
                if sender in vote_set:  # 忽略重复的 VOTE 消息
                    logger.info("[{pid}] Redundant VOTE")
                    continue
                vote_set.add(sender)  # 记录发送方并统计根哈希出现次数
                vote_counter[root] = vote_counter[root] + 1
                logger.info(f"receive vote time {time.time()-distribute_start_time}")
                if vote_counter[root] >= vote_threshold_1 and not vote_sent:  # 当某个根哈希的VOTE消息达到f+1时，触发自身发送VOTE消息
                    vote_sent = True
                    broadcast((sid, SMDMessageType.VOTE, root))
                    logger.info(f"receive f+1 vote time {time.time()-distribute_start_time}")

                # 当某个根哈希的VOTE消息达到n-f时，开始验证并恢复消息
                if vote_counter[root] >= vote_threshold_2:
                    logger.debug(
                        f"Node-[{self.my_id}]: receive n-t vote message, verify and output. sid = {self.sid}"
                    )
                    # unpack
                    echo_msg_same_root = []  # 提取同根哈希的ECHO消息
                    for _echo_msg_collector in echo_msg_collector:
                        (sender, r, pij, rj, piji, sji, fji) = _echo_msg_collector
                        if r == root:  # 只保留与当前根哈希一致的ECHO消息
                            echo_msg_same_root.append(_echo_msg_collector)
                    logger.debug(
                        f"Node-[{self.my_id}]: message unpacked. sid = {self.sid}"
                    )
                    logger.info(f"reveive n-f vote time: {time.time()-distribute_start_time}")

                    echo_msg_val = []  # 有效ECHO消息列表
                    fji_val = [None for _ in range(self.n)]  # 有效编码消息
                    sji_val = []  # 有效多项式份额
                    val_flag = False  # 验证标志
                    rj_val = None  # 已验证的局部根哈希
                    pij_val = None  # 已验证的局部根哈希的路径
                    output_flag = False

                    logger.debug(
                        f"Node-[{self.my_id}]: echo_msg_same_root = {echo_msg_same_root}. sid = {self.sid},length of echo_root is {len(echo_msg_same_root)}"
                    )

                    for _echo_msg_collector in echo_msg_same_root:

                        (sender_i, r, pij, rj, piji, sji, fji) = _echo_msg_collector

                        if rj_val is None and pij_val is None:  # 验证rj是否属于全局根r
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

                        if val_flag == True and rj_val == rj and pij_val == pij:  # 验证(H(i, s_ij), f_ij)是否属于rj
                            logger.debug(
                                f"Node-[{self.my_id}]: 2"
                            )
                            map_sender_id = self.receiver_ids.index(sender_i)
                            logger.debug(
                                f"Node-[{self.my_id}]: 3"
                            )
                            kji = hash(f"{map_sender_id}-{hash(str(sji))}")
                            logger.debug(
                                f"Node-[{self.my_id}]: 4"
                            )
                            kji_fji = kji + fji
                            logger.debug(
                                f"Node-[{self.my_id}]: 5"
                            )
                            if merkle_verify(
                                    self.n,
                                    kji_fji,
                                    rj,
                                    piji,
                                    map_sender_id
                            ):
                                logger.debug(
                                    f"Node-[{self.my_id}]: 6"
                                )
                                # 验证通过，记录有效数据
                                echo_msg_val.append((sender_i, r, pij, rj, piji, sji, fji))
                                logger.debug(
                                    f"Node-[{self.my_id}]: 7"
                                )
                                logger.debug(
                                    f"Node-[{self.my_id}]: sid = {sid}, fji_val = {fji_val}, sender_i = {sender_i}"
                                )
                                fji_val[self.receiver_ids.index(sender_i)] = fji
                                logger.debug(
                                    f"Node-[{self.my_id}]: 8"
                                )
                                sji_val.append((map_sender_id, sji))
                                logger.debug(
                                    f"Node-[{self.my_id}]: 9"
                                )
                            else:
                                logger.error(f"Node-[{self.my_id}]: merkle_verify( \
                                    self.n, \
                                    kji_fji, \
                                    rj, \
                                    piji, \
                                    map_sender_id \
                                ) fail, sid = {self.sid}")
                        else:
                            logger.error(
                                f"Node-[{self.my_id}]: val_flag == True and rj_val == rj and pij_val == pij fail, sid = {self.sid}")

                        logger.debug(
                            f"Node-[{self.my_id}]: 2"
                        )

                        if len(echo_msg_val) >= rec_threshold:  # 当有效消息达到恢复阈值时
                            self.tagvars[sid]["forward_msg"] = echo_msg_val
                            logger.debug(
                                f"5555555Node [{self.my_id}] and sid is [{sid}]is {self.tagvars[sid]['forward_msg']}"
                            )
                            logger.debug(
                                f"Node-[{self.my_id}]: 3"
                            )

                            logger.debug(f'fji_val: {fji_val},length is {len(fji_val)}')
                            cj = decode(self.f + 1, self.n, fji_val)  # 从fji_val恢复加密消息cj
                            logger.debug(f'cj_decode for node {self.my_id}, data: {cj} and fji is {fji_val} and length is {len(fji_val)}')

                            fj_out = encode(self.f + 1, self.n, cj)  # 重新编码以验证：确保解码结果正确
                            #logger.debug(f'fj_out for node {self.my_id}, data: {fj_out}')
                            #logger.debug(f'sji_val for node {self.my_id}, data: {sji_val}')
                            # 恢复多项式份额
                            kj_out = [None for _ in range(self.n)]
                            kj_fj_out = [None for _ in range(self.n)]
                            sj_out = []
                            for i in range(self.n):
                                sji_out = self.poly.interpolate_at(sji_val, i)  # 插值恢复sji
                                sj_out.append(sji_out)
                                kj_out[i] = hash(f'{i}-{hash(str(sji_out))}')
                                kj_fj_out[i] = kj_out[i] + fj_out[i]
                            #logger.debug(f'kj_out for node {self.my_id}, data: {kj_out}')
                            # logger.debug(f'sj_out for node {self.my_id}, data: {sj_out}')
                            # logger.debug(f'kj_fj_out for node {self.my_id}, data: {kj_fj_out}')
                            # 构建最终Merkle树并验证
                            merkle_tree_out_data = merkle_tree(kj_fj_out)
                            logger.debug(
                                f'root of merkle_tree_out_data for node {self.my_id}, data: {merkle_tree_out_data[1]}, root_val: {rj_val}')

                            if merkle_tree_out_data[1] == rj_val:  # 验证恢复的Merkle树根是否与rj_val一致
                                key = sha256(int(self.poly.interpolate_at(sji_val, 0)).to_bytes(32,
                                                                                                byteorder="big")).digest()  # 恢复加密密钥：使用sji_val在x=0处的值
                                logger.debug(f'key for node {self.my_id}, data: {key}')
                                mj = SymmetricCrypto.decrypt(key, cj)  # 解密消息
                                mj = loads(mj)
                                self.mj=mj
                                logger.debug(f'Node-[{self.my_id}]: output mj as node {self.my_id}, dealer: {self.dealer_id}, data: {mj} key is {key}')
                                self.output_queue((mj, root))
                                self.tagvars[sid]['root'] = root

                                self.output_flag.set()


                                output_time = time.time()
                                logger.info(f"output time: {output_time-distribute_start_time}")
                                # logger.debug(f'Node-[{self.my_id}]: output root as node {self.my_id}, dealer: {self.dealer_id}, root: {root}')
                                logger.debug(f'Node-[{self.my_id}]: output in smd, tag = {sid}')
                                logger.debug(
                                    f"Node [{self.my_id}] [{sid}]is {self.tagvars[sid]['forward_msg']}"
                                )
                                break
                            else:
                                logger.error(
                                    f'Failed to verify final message. Id: {self.my_id}, Dealer Id: {self.dealer_id}'
                                )
            elif msg[1] in (SMDMessageType.FORWARD, SMDMessageType.EXFORWARD):
                # Both paths authenticate the ORIGINAL owner, not the relay.
                try:
                    if msg[1] == SMDMessageType.FORWARD:
                        msg_type, proof = msg[2]
                        owner = self.receiver_ids.index(sender)
                    else:
                        msg_type, owner, proof = msg[2]
                    mj = self._decode_forward_payload(sid, owner, proof)
                except (AssertionError, ValueError, TypeError, IndexError, KeyError):
                    logger.warning("Rejected invalid forwarded SMD evidence")
                    continue
                self.forward_msg_from_others[owner] = proof
                original_sender = self.receiver_ids[owner]
                value = (mj, self.receiver_ids.index(sender), owner, original_sender)
                self.forward_output[msg_type] = value
                self.forward_output_flag[msg_type].set()
                self.forward_output_queue.put_nowait((msg_type,) + value)
