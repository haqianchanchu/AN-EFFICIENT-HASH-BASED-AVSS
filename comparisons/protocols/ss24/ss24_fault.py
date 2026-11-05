import asyncio
from collections import defaultdict
from GoSSamer.crypto.elliptic_curve import Subgroup
from GoSSamer.crypto.field import GF
from GoSSamer.util.serializer import serialize as dumps, deserialize as loads
import re
import time
from GoSSamer.crypto.polynomial import polynomials_over
from GoSSamer.util.misc import wrap_send, subscribe_recv
from comparisons.protocols.ss24.smd_ss24 import SMD_SS24
from comparisons.protocols.ss24.optqrbc import optqrbc
from GoSSamer.util.serilization import Serial
from GoSSamer.distribute.encode import hash_to_field
from GoSSamer.util.misc import print_exception_callback

import logging

from adkg.exceptions import adkgError
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)



class GossamerAcssMessageType:
    """协议消息类型定义 (按论文第5.1节协议描述)"""
    OK = "OK"  # 正常确认消息
    VOTE = "VOTE"  # 投票消息
    COMPLAIN = "COMPLAIN"  # 投诉消息（论文5.3节unhappy path）
    FAULTY = "FAULTY"
    REC = "REC"
    ASSIST = "ASSIST"  # 协助消息（新增，论文5.3节assist流程）
    REPORT = "REPORT"  # 报告消息（用于传播投诉证据）
    RESPONSE = "RESPONSE"


class SS24:
    """异步可验证秘密共享协议实现 (遵循论文第5节协议)"""

    def __init__(
            self, n, t, batch_size,my_id, send, recv, field, omega, receiver_ids=None
    ):
        # 初始化网络参数（保持原有注释）
        self.n, self.t, self.batch_size,self.my_id = n, t, batch_size,my_id
        self.receiver_ids = receiver_ids
        self.field = field  # 有限域定义（论文中的A）
        self.poly = polynomials_over(field)
        self.serial = Serial(field)  # 序列化工具
        self.group_size = self.t + 1
        self.output_queue = asyncio.Queue()  # 输出队列
        # 协议状态存储（按标签组织）
        self.tagvars = defaultdict(dict)
        self.gi_hi_buffers = [asyncio.Future() for _ in range(self.n)]
        # 网络层配置
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        self.get_send = lambda tag: wrap_send(tag, send)
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def kill(self):
        """清理所有协议实例"""
        logger.debug(f"Node-[{self.my_id}]: ACSS kill called")  # 这行debug显示调用了ACSS协议的终止方法
        self.subscribe_recv_task.cancel()
        logger.debug(f"Node-[{self.my_id}]: ACSS recv task cancelled")  # 这行debug显示接收任务已被取消
        for tag in list(self.tagvars.keys()):
            logger.debug(f"Node-[{self.my_id}]: killing tag={tag}")  # 这行debug显示正在终止指定标签的协议实例
            for task in self.tagvars[tag].get('tasks', []):
                task.cancel()
            del self.tagvars[tag]

    def _construct_secret_polynomials(self, secrets):
        """
        构造L个秘密多项式（论文2.2节Shamir方案）
        每个多项式的常数项为秘密值secret，其他系数随机生成
        """
        start_time = time.time()
        L = len(secrets)
        #logger.debug(f"Node-[{self.my_id}]: constructing {L} secret polynomials")  # 这行debug显示正在构造的秘密多项式数量
        f_polys = []
        for idx, secret in enumerate(secrets):
            coefficients = [secret]  # 常数项为秘密值
            coefficients.extend([self.field.random() for _ in range(self.t)])  # 随机系数
            f_poly = self.poly(coefficients)
            f_polys.append(f_poly)
            logger.debug(f"Node-[{self.my_id}]: constructed secret poly {idx}: {f_poly}")  # 这行debug显示已构造的单个秘密多项式内容
        construction_time = time.time() - start_time
        logger.info(f"Secret polynomials construction time: {construction_time:.6f}s")
        return f_polys

    def _construct_blinding_polynomials(self, R):
        """
        生成R个随机t阶多项式（用于盲化过程）
        每个多项式的所有系数均随机生成，不包含固定的秘密值
        """
        start_time = time.time()
        logger.debug(f"Node-[{self.my_id}]: constructing {R} blinding polynomials")
        g_polys = []
        for idx in range(R):
            # 生成t+1个随机系数，构造t阶多项式（多项式阶数 = 系数数量 - 1）
            coefficients = [self.field.random() for _ in range(self.t + 1)]
            g_poly = self.poly(coefficients)
            g_polys.append(g_poly)
            logger.debug(f"Node-[{self.my_id}]: constructed blinding poly {idx}: {g_poly}")
        construction_time = time.time() - start_time
        logger.info(f"Blinding polynomials construction time: {construction_time:.6f}s")
        return g_polys

    def _get_dealer_msg(self, secrets, tag):  # secrets为分发的秘密，也就是各个多项式的常数项
        """
        构造Dealer消息（论文5.1节步骤1）：
        生成多项式并计算各节点的份额
        """
        start_time = time.time()
        L = len(secrets)
        # R = self.t + 1  # 随机多项式数量R
        R = 1
        logger.debug(f"Node-[{self.my_id}]: constructing dealer msg for tag={tag}, L={L}, R={R}")  # 这行debug显示正在构造的经销商消息参数

        # 构造L个秘密多项式f1...fL
        f_polys = self._construct_secret_polynomials(secrets)
        logger.debug(f"Node-[{self.my_id}]: constructed {L} secret polynomials")  # 这行debug显示所有秘密多项式构造完成

        # 生成R个随机多项式g1...gR（盲化多项式）
        g_polys = self._construct_blinding_polynomials(R)
        logger.debug(f"Node-[{self.my_id}]: constructed {R} blinding polynomials")  # 显示所有盲化多项式构造完成

        # 保存g_polys到tagvars
        self.tagvars[tag]['g_polys'] = g_polys

        # 合并所有多项式（f + g）
        all_polys = f_polys + g_polys

        # 计算各节点的份额（论文式(3)）
        shares = []  # shares=[[x=1],[x=2]……]
        for j in range(self.n):
            # 计算所有多项式在点(j+1)处的值
            point_values = [poly(j + 1) for poly in all_polys]
            shares.append(point_values)
            logger.debug(f"Node-[{self.my_id}]: shares for node {j+1}: {point_values}")  # 这行debug显示计算得到的某个节点的份额值

        # 构造SMD消息（安全消息分发）
        smd_msg = []
        for j in range(self.n):
            # 序列化份额（v || w格式）
            distributed_shares = [*shares[j], L, R]
            logger.debug(f"The {distributed_shares} and length of serialized_shares is {len(distributed_shares)}")
            smd_msg.append(distributed_shares)
            logger.debug(f"Node-[{self.my_id}]: serialized shares for node {j+1}")  # 这行debug显示已序列化的节点份额
        logger.debug(f"Length of smd is {smd_msg} and length is {len(smd_msg)}")
        dealer_msg_time = time.time() - start_time
        logger.info(f"Dealer message generation time: {dealer_msg_time:.6f}s")
        return smd_msg, f_polys

    def _handle_smd_msg(self, smd_msg, L, R,tag):
        """
        处理接收到的SMD消息（论文5.1节步骤2）
        恢复多项式并验证格式
        """
        start_time = time.time()
        logger.debug(f"Node-[{self.my_id}]: handling SMD msg, L={L}, R={R} and smd_msg is {smd_msg}")  # 这行debug显示正在处理的SMD消息参数
        # 反序列化消息（v || w结构）


        shares = smd_msg[0]
        logger.debug(f"Node-[{self.my_id}]: deserialized shares: {shares}")  # 这行debug显示反序列化后的份额内容

        # 提取秘密份额(v)和盲化份额(w)
        secret_shares = shares[:L]  # 前L个为秘密份额
        blind_shares = shares[L:-2]  # 后R个为盲化份额
        self.tagvars[tag]['secret_shares']= secret_shares
        self.tagvars[tag]['blind_shares'] = blind_shares

        logger.debug(f"Node-[{self.my_id}]: extracted secret_shares={secret_shares}, blind_shares={blind_shares}")  # 这行debug显示从消息中提取的秘密份额和盲化份额
        handle_time = time.time() - start_time
        logger.info(f"SMD msg handling time: {handle_time:.6f}s")
        return secret_shares, blind_shares

    def _verify_shares(self, secret_shares, blind_shares, L, R, challenge, h_polys):
        """
        验证份额的正确性（论文5.1节步骤4验证式）：
        hʳ(eⱼ) = wⱼʳ + ∑θℓʳ·vⱼℓ
        """
        start_time = time.time()
        logger.debug(
            f"Node-[{self.my_id}]: verifying shares with L={L}, R={R}, and secret_shares is{secret_shares}, blind_shares is {blind_shares},challenge is {challenge}")  # 这行debug显示正在进行份额验证的参数

        # 初始化验证结果为True
        verification_passed = True

        # 从挑战值计算hʳ(eⱼ)
        for r in range(R):
            hr_ej = blind_shares[r]
            for ℓ in range(L):
                hr_ej += challenge[r][ℓ] * secret_shares[ℓ]
            expected = h_polys[r](self.receiver_ids.index(self.my_id) + 1)
            logger.debug(
                f"Node-[{self.my_id}]: verify r={r}, expected={expected}, computed={hr_ej}")  # 这行debug显示份额验证过程中的计算值和期望值

            # 验证 hʳ(eⱼ) + wⱼʳ 是否等于预期值
            if hr_ej != expected:
                logger.error(f"Node-[{self.my_id}]: share verification failed for r={r}")  # 这行debug显示份额验证失败的信息
                verification_passed = False  # 标记验证失败
            else:
                logger.debug(f"Node-[{self.my_id}]: share verification passed for r={r}")  # 这行debug显示份额验证通过的信息

        verify_time = time.time() - start_time
        logger.info(f"Share verification time: {verify_time:.6f}s")

        # 根据验证结果返回True或False
        return verification_passed

    async def _handle_share_recovery(self, dealer_id, acss_id,tag):
        logger.debug(f"ready to recovery for {self.my_id}")
        smd = self.tagvars[tag]['smd']
        faulty_sent = False
        rec_sent = False
        rec_sent_2 = False
        val_shares = defaultdict(lambda: [])
        def _handle_val_shares(msg, i1, i2, sender):
            n = len(msg) - 2  # 计算有效负载长度（排除最后两个元素）
            all_shares = msg[:n]  # 切片获取前m个元素
            challenge = self.tagvars[tag]['challenge']  # 假设为R×L的二维挑战矩阵
            h = self.tagvars[tag]['h_poly']  # 全局多项式v(x,y)
            R = msg[-1]
            L = msg[-2]

            # 拆分秘密份额和盲化份额
            secret_shares = all_shares[:L]  # 前L个为秘密份额 [A₁(eⱼ), ..., Aᴸ(eⱼ)]
            blind_shares = all_shares[L:]  # 后R个为盲化份额 [g¹(eⱼ), ..., gᴿ(eⱼ)]
            # logger.info(f"1111111msg is {secret_shares}1111{blind_shares}and h is {h}")
            val = True  # 初始化为验证成功
            for r in range(R):
                # 计算hʳ(eⱼ) = gʳ(eⱼ) + Σ(γʳˡ · Aˡ(eⱼ)) ，其中γʳˡ为challenge[r][ℓ]
                hr_ej = blind_shares[r]
                for ℓ in range(L):
                    hr_ej += challenge[r][ℓ] * secret_shares[ℓ]
                # 验证hʳ(eⱼ)是否等于vxy(i₁+1, i₂+1)
                if hr_ej != h[r](i2 + 1):
                    val = False  # 只要有一个多项式验证失败，整体失败
                    break

            return val, sender, all_shares  # 返回验证结果val（布尔值）、发送方、原始份额

        exit_flag = False
        while True:
            msg_type, mj, i1, i2, sender = await smd.forward_output_queue.get()
            logger.debug(f"ready to recovery for {self.my_id} and msg_type is {msg_type}, mj is {mj} and i1 is {i1} and i2 is {i2}")
            if exit_flag:
                break

            if msg_type == GossamerAcssMessageType.COMPLAIN:
                if not faulty_sent:
                    logger.debug(f'Node-[{self.my_id}]: get {msg_type} msg from smd')
                    # smd.forward_output_flag[GossamerAcssMessageType.COMPLAIN].clear()
                    # complain_msg = smd.forward_output[GossamerAcssMessageType.COMPLAIN]

                    val, sender, _ = _handle_val_shares(mj, i1, i2, sender)

                    logger.debug(f'Node-[{self.my_id}]: complain_msg = {mj}, val = {val}, sender = {sender}')

                    if not val:
                        # logger.info(f"Node-[{self.my_id}]: h(sender) not on h_poly, send faulty, tag = {tag}, sender = {sender}")
                        faulty_sent = True
                        for j in range(self.n):
                            smd.forward(self.receiver_ids[j],GossamerAcssMessageType.REC)
            elif msg_type == GossamerAcssMessageType.REC and not self.tagvars[tag]['shares_valid_local']:
                if not rec_sent_2:
                    logger.debug(f'Node-[{self.my_id}]: get {msg_type} msg from smd')
                    # smd.forward_output_flag[GossamerAcssMessageType.REC].clear()
                    # rec_msg = smd.forward_output[GossamerAcssMessageType.REC]

                    val, sender, secret_blind_share = _handle_val_shares(mj, i1, i2, sender)

                    logger.debug(f'Node-[{self.my_id}]: val = {val}, sender = {sender}')

                    m = len(secret_blind_share)#R+L

                    if val:
                        for i in range(m):
                            val_shares[i].append((self.receiver_ids.index(sender) + 1, secret_blind_share[i]))
                        logger.debug(f'Node-[{self.my_id}]: val_shares = {val_shares}')

                        if len(val_shares[0]) == self.t + 1:

                            gx_hx = []#存恢复后R+L个多项式
                            for i in range(m):
                                gx_hx.append(self.poly.interpolate(val_shares[i]))

                            logger.debug(f'Node-[{self.my_id}]: Aiy_Eiy = {gx_hx}')

                            rec_sent_2 = True
                            gi_hi = [gx_hx[i](self.receiver_ids.index(self.my_id)+1) for i in range(m)]
                            self.output_queue.put_nowait((dealer_id, acss_id, gi_hi))
                            logger.info(f'Node-[{self.my_id}]: output recover shares')
                            exit_flag = True
                            break
            else:
                break
        logger.info(f'Node-[{self.my_id}]: end handle share recovery, tag = {tag}')
        return
    async def _process_acss_msg(self, acss_id, dealer_id, tag):
        """
        处理ACSS消息（协议主流程）
        执行验证和共识
        """
        start_time = time.time()
        logger.debug(f"Node-[{self.my_id}]: processing ACSS msg for acss_id={acss_id}, dealer_id={dealer_id}, tag={tag}")  # 这行debug显示正在处理的ACSS消息参数
        smd_msg = self.tagvars[tag]['smd_msg']
        L = self.batch_size
        R = self.t + 1
        logger.debug(f"Node-[{self.my_id}]: L={L}, R={R} and smd_msg is {smd_msg}")  # 这行debug显示协议执行中的L和R参数值
        # 处理SMD消息
        if self.my_id in self.receiver_ids:
            secret_shares, blind_shares = self._handle_smd_msg(smd_msg, L, R, tag)

        # 步骤3：生成挑战值（随机信标）
        challenge_start = time.time()
        challenge = self._generate_challenge(tag, L, R)
        self.tagvars[tag]['challenge'] = challenge
        challenge_time = time.time() - challenge_start
        logger.info(f"Challenge generation time: {challenge_time:.6f}s")
        logger.debug(f"Node-[{self.my_id}]: generated challenge: {challenge}")  # 这行debug显示生成的挑战值内容
        rbc_tag = f"{dealer_id}-{acss_id}-HRBC"
        send, recv = self.get_send(rbc_tag), self.subscribe_recv(rbc_tag)
        output_queue = asyncio.Queue()
        async def predicate(m=None):
            return True
        # 步骤4：可靠广播h(r)
        rbc_start = time.time()
        logger.debug(f"My ID is {self.my_id} and the receiver ID is {self.receiver_ids}")
        final_bytes=None
        if self.my_id == dealer_id:
            # Dealer计算响应多项式
            f_polys = self.tagvars[tag]['polynomials']
            g_polys = self.tagvars[tag].get('g_polys')

            combined_bytes = bytearray()
            combined_bytes.extend(R.to_bytes(4, 'big'))
            logger.debug(f"f_poly is {f_polys} and g_poly is {g_polys}, R={R}, L={L}, len(c) = {len(challenge)}, len(c0) = {len(challenge[0])}, len(f_poly) = {len(f_polys)}")

            for r in range(R):
                hr = g_polys[r]
                for l in range(L):
                    hr += f_polys[l].__rmul__(challenge[r][l])
                serialized_h = dumps(hr.coeffs)
                combined_bytes.extend(len(serialized_h).to_bytes(4, 'big'))  # 添加长度
                combined_bytes.extend(serialized_h)  # 添加内容
                logger.debug(f"Node-[{self.my_id}]: constructed h_poly {r}: {hr} and the length is {len(serialized_h)}")  # 这行debug显示构造完成的h多项式内容
            final_bytes = bytes(combined_bytes)
            logger.debug(f" poly is {final_bytes} and length is {len(final_bytes)}")
            # 通过可靠广播发送h_polys（使用QRBC协议）



        rbc_task = asyncio.create_task(
            optqrbc(
                rbc_tag, self.my_id, self.n, self.t, dealer_id,
                predicate,  # 谓词验证
                final_bytes, output_queue.put_nowait,
                send, recv, self.receiver_ids
            )
        )
        rbc_task.add_done_callback(print_exception_callback)
        self.tagvars[tag]['tasks'].append(rbc_task)
        received_h_bytes = await output_queue.get()
        rbc_time = time.time() - rbc_start
        logger.info(f"RBC protocol time: {rbc_time:.6f}s, tag is {tag}")
        if self.my_id == dealer_id:
            received_h_bytes = final_bytes
            logger.debug(f'Node-[{self.my_id}]: dealer work done')

        logger.debug(f"[{self.my_id}]finish rbc is {received_h_bytes}")
        if self.my_id in self.receiver_ids:
            # verify secret shares
            send, recv = self.get_send(tag), self.subscribe_recv(tag)
            logger.debug(f'Node-[{self.my_id}]: Ready to receive')
            def multicast(msg):
                for i in range(self.n):
                    send(self.receiver_ids[i], msg)

            self.tagvars[tag]['io'] = [send, recv, multicast]
            self.tagvars[tag]['in_share_recovery'] = False

            ok_set = set()
            vote_set = set()
            vote_sent = False
            ready_sent = False
            output = False
            received_h_polys = []
            offset = 0
            # 1. 读取多项式总数（前4字节）
            logger.debug(f"[{received_h_bytes}] 这是收到的h的字节流")
            total_polys = int.from_bytes(received_h_bytes[offset:offset + 4], 'big')
            logger.debug(f"[{self.my_id}] 预期解析个多项式")
            offset += 4
            logger.debug(f"[{self.my_id}] 预期解析 {total_polys} 个多项式")
            h_poly=[]

            # 2. 循环解析每个多项式
            for _ in range(total_polys):
                # 2.1 读取当前多项式的长度（4字节）
                poly_length = int.from_bytes(received_h_bytes[offset:offset + 4], 'big')
                offset += 4

                # 2.2 提取多项式字节
                poly_bytes = received_h_bytes[offset:offset + poly_length]
                offset += poly_length

                # 2.3 反序列化单个多项式
                poly = self.poly(loads(poly_bytes))
                h_poly.append(poly)
                received_h_polys.append(poly)
                logger.debug(f"[{self.my_id}] 解析多项式成功，为{poly},长度: {poly_length} 字节")
            self.tagvars[tag]['h_poly']=h_poly

            # 步骤5：本地验证份额
            valid = self._verify_shares(secret_shares, blind_shares, L, R, challenge, received_h_polys)#布尔值
            self.tagvars[tag]['shares_valid_local']=valid
            logger.debug(f"Node-[{self.my_id}]: share validation result: {valid}")  # 这行debug显示份额验证的最终结果

            if self.tagvars[tag]['shares_valid_local']:
                # Happy路径：广播OK并启动共识（处理正常投票）
                logger.debug(f"Multicast OK from Node {self.my_id}")
                multicast((GossamerAcssMessageType.OK, ""))


            rec2_flag = False

            aik_count = 0

            while True:
                # Bracha-style agreement
                sender, osv_msg = await recv()
                logger.debug(f"Node-[{self.my_id}] get to the while true phase and ovs_msg is {osv_msg} and ok_set is {ok_set} and length is {len(ok_set)}")
                # OK
                if osv_msg[0] == GossamerAcssMessageType.OK and sender not in ok_set:
                    logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                    ok_set.add(sender)
                    logger.debug(f"ok_set is {ok_set}")
                    if len(ok_set) >= (2 * self.t + 1) and not vote_sent:
                        #logger.debug("[%d] Received enough OK and will broadcast vote", self.my_id)
                        vote_sent = True
                        multicast((GossamerAcssMessageType.VOTE, ""))
                        logger.debug(f"broadcast VOTE from {self.my_id}")

                if osv_msg[0] == GossamerAcssMessageType.VOTE and (sender not in vote_set):
                    logger.debug(f"[%d] Received READY from [%d] and vote_set is {vote_set} length is {len(vote_set)}", self.my_id, sender)
                    vote_set.add(sender)
                    if len(vote_set) == (self.t + 1) and not ready_sent:
                        logger.debug("[%d] Received enough vote and will again broadcast vote", self.my_id)
                        ready_sent = True
                        multicast((GossamerAcssMessageType.VOTE, ""))
                        logger.debug(f"broadcast VOTE from {self.my_id}")
                # if 2t+1 ready -> output shares
                if len(vote_set) == (2 * self.t + 1):
                    logger.debug(f"达到输出要求")
                    # output result by setting the future value
                    if self.tagvars[tag]['shares_valid_local'] and not output:
                        logger.debug("[%d] ready to output", self.my_id)


                        shares = self.tagvars[tag]['secret_shares']
                        logger.debug(f'Node-[{self.my_id}]: shares = {shares}')

                        shares_blind = self.tagvars[tag]['blind_shares']
                        self.output_queue.put_nowait((dealer_id, acss_id, shares, shares_blind))
                        output = True
                        await self._handle_share_recovery(dealer_id, acss_id,tag)

                        logger.debug(f'Node-[{self.my_id}]: end share recovery')


                    elif not self.tagvars[tag]['shares_valid_local'] and not rec2_flag:
                        logger.debug(f'Node-[{self.my_id}]: begin complain')
                        smd = self.tagvars[tag]['smd']
                        for j in range(self.n):
                            smd.forward(self.receiver_ids[j],GossamerAcssMessageType.COMPLAIN)
                            logger.debug(f'Node-[{self.my_id}] finish forward')
                        logger.debug(f'Node-[{self.my_id}] finish all all forward')
                        await self._handle_share_recovery(dealer_id, acss_id,tag)
                        rec2_flag = True
                        output = True
                        multicast((GossamerAcssMessageType.OK, ""))
                        logger.info(f'Node-[{self.my_id}]: end complain')

                # The only condition where we can terminate
                if (len(ok_set) == 3 * self.t + 1) and output:
                    logger.info("[%d] exit", self.my_id)
                    self.tagvars[tag] = {}
                    break

            return secret_shares, blind_shares, challenge
    def _generate_challenge(self, tag, L, R):
        """
        生成随机挑战值θℓʳ（论文式(4)实现）
        使用哈希函数模拟随机信标，将SMD的总根哈希加入种子
        """
        start_time = time.time()
        logger.debug(f"Node-[{self.my_id}]: generating challenge for tag={tag}, L={L}, R={R}")  # 这行debug显示正在生成挑战值
        # 获取SMD阶段的总根哈希
        total_root = self.tagvars[tag].get('total_root')
        if total_root is None:
            logger.warning(f"SMD total_root not found for tag {tag}. Using default seed.")
            total_root = b""  # 若未找到，使用空字节（但建议确保总根哈希已正确存储）
        else:
            logger.debug(f"Node-[{self.my_id}]: using total_root: {total_root.hex()}")  # 这行debug显示用于生成挑战值的总根哈希值

        challenge = []
        for r in range(R):
            theta_r = []
            for ℓ in range(L):
                # 在原有种子基础上拼接总根哈希
                seed = f"{tag}-{r}-{ℓ}-{total_root}".encode()  # 加入总根哈希
                theta = hash_to_field(seed, self.field)  # 哈希到域元素
                theta_r.append(theta)
                logger.debug(f"Node-[{self.my_id}]: generated theta[{r}][{ℓ}] = {theta}")  # 这行debug显示生成的具体挑战值元素
            challenge.append(theta_r)
        challenge_gen_time = time.time() - start_time
        logger.info(f"Challenge generation time: {challenge_gen_time:.6f}s")
        return challenge

    def _recover_from_assists(self, assists, tag):
        """
        从assist消息中恢复正确份额（论文式(7)实现）
        使用拉格朗日插值法
        """
        start_time = time.time()
        logger.debug(f"Node-[{self.my_id}]: attempting recovery with {len(assists)} assists")  # 这行debug显示尝试从协助消息恢复
        try:
            # 获取协议参数
            dealer_id = self.tagvars[tag]['dealer_id']
            L = len(self.tagvars[tag].get('values', [])) if dealer_id == self.my_id else self.t + 1
            logger.debug(f"Node-[{self.my_id}]: recovering {L} secrets")  # 这行debug显示正在恢复的秘密数量

            # 提取有效点集合（节点ID，份额列表）
            points = [(sid, shares) for sid, shares in assists if shares is not None]

            # 需要至少t+1个点来恢复t次多项式
            if len(points) < self.t + 1:
                logger.warning(f"Node-[{self.my_id}]: insufficient points for recovery: {len(points)}/{self.t+1}")  # 这行debug显示恢复所需点不足
                return None

            recovered_shares = []
            for ℓ in range(L):
                # 对每个秘密进行插值
                x_coords = [self.field(sid + 1) for sid, _ in points]  # 节点ID转换为评估点（x=i+1）
                y_coords = [self.field(shares[ℓ]) for _, shares in points]
                logger.debug(f"Node-[{self.my_id}]: interpolating secret {ℓ} with points: {list(zip(x_coords, y_coords))}")  # 这行debug显示插值使用的点集合

                # 执行拉格朗日插值
                poly = self.poly.interpolate(zip(x_coords, y_coords))
                recovered_value = poly(0)  # 恢复秘密（常数项）
                recovered_shares.append(recovered_value)
                logger.debug(f"Node-[{self.my_id}]: recovered secret {ℓ}: {recovered_value}")  # 这行debug显示已恢复的单个秘密值
            recovery_total_time = time.time() - start_time
            logger.info(f"Recovery total time: {recovery_total_time:.6f}s")
            return recovered_shares

        except Exception as e:
            logger.error(f"Node-[{self.my_id}]: recovery failed: {str(e)}", exc_info=True)  # 这行debug显示恢复过程中发生的错误
            return None

    def _output_valid_shares(self, tag, secret_shares):
        """输出验证通过的份额到队列"""
        dealer_id = self.tagvars[tag]['dealer_id']
        acss_id = self.tagvars[tag]['acss_id']
        self.output_queue.put_nowait((
            dealer_id,
            acss_id,
            secret_shares
        ))
        logger.debug(f"Node-[{self.my_id}]: output shares to queue: dealer={dealer_id}, acss_id={acss_id}, shares={secret_shares[:3]}...")  # 这行debug显示已将份额输出到队列


    async def acss(self, avss_id, values=None, dealer_id=None):
        """
        主协议入口（论文算法1）
        初始化并执行ACSS协议
        """
        acss_start_time = time.time()
        if values is not None:#values参数的作用是承载待共享的秘密值,只有Dealer 节点需要提供这些值
            if dealer_id is None:
                dealer_id = self.my_id#通过 values 参数提供秘密值，必须设置 dealer_id 为自身 ID
            assert dealer_id == self.my_id, "Only dealer can share values."

        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:#接收者不提供 values，但需指定 dealer_id（必须与自身 ID 不同）
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        logger.debug(f"Node-[{self.my_id}]: starting ACSS with avss_id={avss_id}, dealer_id={dealer_id}")  # 这行debug显示开始执行ACSS协议
        n = self.n
        acss_tag = f"{dealer_id}-{avss_id}-B-ACSS"
        self.tagvars[acss_tag] = {
            'tasks': [],
            'acss_id': avss_id,
            'dealer_id': dealer_id
        }
        logger.debug(f"Node-[{self.my_id}]: initialized tagvars for tag={acss_tag}")  # 这行debug显示已初始化协议标签变量

        # Dealer初始化：构造并分发消息
        smd_distribute_msg = None
        if self.my_id == dealer_id:
            smd_distribute_msg, f_polys = self._get_dealer_msg(values, acss_tag)
            #logger.debug(f"Length of smd_distribute_msg is {len(smd_distribute_msg)}")-4
            self.tagvars[acss_tag]['values'] = values
            self.tagvars[acss_tag]['polynomials'] = f_polys
            logger.debug(f"Node-[{self.my_id}]: constructed SMD distribute msg for {len(self.tagvars[acss_tag]['values'])} secrets")  # 这行debug显示构造的SMD分发消息

        # 启动SMD子协议
        smd_msg_queue = asyncio.Queue()  # 单个SMD队列
        smd_tag = f"{dealer_id}-{avss_id}-B-SMD"
        smd = SMD_SS24(
            smd_tag, self.n, self.t, self.my_id, dealer_id,
            smd_msg_queue.put_nowait,
            self.get_send(smd_tag),
            self.subscribe_recv(smd_tag),
            self.field,
            self.receiver_ids
        )
        self.tagvars[acss_tag]['smd'] = smd
        self.tagvars[acss_tag]['tasks'].append(smd)
        task = asyncio.create_task(
            smd.distribute(smd_distribute_msg) if self.my_id == dealer_id  # 经销商分发完整消息列表
            else smd.distribute()  # 接收方获取消息
        ).add_done_callback(print_exception_callback)
        self.tagvars[acss_tag].setdefault('smd_tasks', []).append(task)
        logger.debug(f"Node-[{self.my_id}]: started SMD task for tag={smd_tag}")

        # 等待单个SMD任务完成
        smd_start = time.time()
        smd_result = await smd_msg_queue.get()
        smd_time = time.time() - smd_start
        logger.info(f"SMD distribution time: {smd_time:.6f}s")
        logger.debug(f"Node-[{self.my_id}]: received SMD result is {smd_result}")

        if smd_result and len(smd_result) > 1:
            self.tagvars[acss_tag]['total_root'] = smd_result[1]  # 存储总根哈希
            logger.debug(f"Node-[{self.my_id}]: stored total_root: {self.tagvars[acss_tag]['total_root'].hex()}")
        else:
            logger.error("Failed to retrieve SMD total_root!")

        self.tagvars[acss_tag]['smd_msg'] = smd_result  # 结果列表包含所有节点消息
        logger.debug(f"Node-[{self.my_id}]: stored SMD messages for tag={acss_tag}")

        # 处理后续协议流程
        process_start = time.time()
        process_task = asyncio.create_task(
            self._process_acss_msg(avss_id, dealer_id, acss_tag)
        )
        process_task.add_done_callback(print_exception_callback)
        self.tagvars[acss_tag]['tasks'].append(process_task)
        logger.debug(f"Node-[{self.my_id}]: started processing task for tag={acss_tag}")  # 这行debug显示已启动协议处理任务
        await process_task
        process_end_time = time.time() - process_start
        logger.info(f"ACSS processing task time: {process_end_time:.6f}s")
        acss_total_time = time.time() - acss_start_time
        logger.info(f"Total ACSS time: {acss_total_time:.6f}s")
        logger.debug(f"Node-[{self.my_id}]: completed ACSS protocol for tag={acss_tag}")  # 这行debug显示指定标签的ACSS协议已完成


class BadDealer(SS24):

    def _get_dealer_msg(self, secrets,tag):

        fault_n = range(self.t)
        fault_k = range(self.n)

        polynomials = []
        L = len(secrets)
        R = self.t + 1  # 随机多项式数量R
        logger.debug(
            f"Node-[{self.my_id}]: constructing dealer msg for tag={tag}, L={L}, R={R}, and I am a baddealer")  # 这行debug显示正在构造的经销商消息参数

        # 构造L个秘密多项式f1...fL
        f_polys = self._construct_secret_polynomials(secrets)
        logger.debug(f"Node-[{self.my_id}]: constructed {L} secret polynomials")  # 这行debug显示所有秘密多项式构造完成

        # 生成R个随机多项式g1...gR（盲化多项式）
        g_polys = self._construct_blinding_polynomials(R)
        logger.debug(f"Node-[{self.my_id}]: constructed {R} blinding polynomials")  # 显示所有盲化多项式构造完成

        # 保存g_polys到tagvars
        self.tagvars[tag]['g_polys'] = g_polys

        # 合并所有多项式（f + g）
        all_polys = f_polys + g_polys

        shares = []  # shares=[[x=1],[x=2]……]
        for j in range(self.n):
            if j in fault_n:
                point_values = [self.field.random()] * (len(all_polys))
            else:
                point_values = [poly(j + 1) for poly in all_polys]
            shares.append(point_values)
            logger.debug(f"Node-[{self.my_id}]: shares for node {j + 1}: {point_values}")  # 这行debug显示计算得到的某个节点的份额值

        # 构造SMD消息（安全消息分发）
        smd_msg = []
        for j in range(self.n):
            # 序列化份额（v || w格式）
            distributed_shares = [*shares[j], L, R]
            logger.debug(f"The {distributed_shares} and length of serialized_shares is {len(distributed_shares)}")
            smd_msg.append(distributed_shares)
            logger.debug(f"Node-[{self.my_id}]: serialized shares for node {j + 1}")  # 这行debug显示已序列化的节点份额
        logger.debug(f"Length of smd is {smd_msg} and length is {len(smd_msg)}")
        return smd_msg, f_polys