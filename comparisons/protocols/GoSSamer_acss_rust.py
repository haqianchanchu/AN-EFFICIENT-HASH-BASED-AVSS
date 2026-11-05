import asyncio
from collections import defaultdict
from GoSSamer.crypto.elliptic_curve import Subgroup
from GoSSamer.crypto.field import GF
from GoSSamer.util.serializer import serialize as dumps, deserialize as loads
import re
import time
from GoSSamer.crypto.polynomial import EvalPoint, polynomials_over, get_omega
from GoSSamer.crypto.polynomial_bi import polynomials_over_bi
from GoSSamer.crypto.robust_reconstruction import robust_reconstruct
from GoSSamer.crypto.symmetric_crypto import SymmetricCrypto
from GoSSamer.util.misc import wrap_send, subscribe_recv
from GoSSamer.distribute.smd_batch_rust_lk import SMD_SS24
from GoSSamer.distribute.optqrbc import optqrbc
from GoSSamer.util.serilization import Serial
from GoSSamer.distribute.encode import encode, decode, merkle_tree, get_merkle_branch, hash, merkle_verify, hash_to_field
from GoSSamer.util.misc import print_exception_callback

import logging

from adkg.exceptions import adkgError
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

class GossamerAcssMessageType:
    OK = "OK"
    ECHO = "ECHO"
    VOTE = "VOTE"
    COMPLAIN = "COMPLAIN"
    FAULTY = "FAULTY"
    REC = "REC"
    REC2 = "REC2"
    
class Gossamer_acss:
    #@profile
    #@profile
    def __init__(
            self, n, t, my_id, send, recv, field, omega, receiver_ids, batch_size
    ):  # (# noqa: E501)

        self.n, self.t, self.my_id = n, t, my_id
        self.batch_size = batch_size 
        self.batch_size_poly = batch_size // (t + 1) + batch_size % (t + 1)
        
        self.receiver_ids = receiver_ids

        logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.acss_status = defaultdict(lambda: True)
        self.field = field
        self.poly = polynomials_over(self.field)
        self.poly_bi = polynomials_over_bi(self.field)
        self.poly.clear_cache()
        self.poly_bi.clear_cache()
        self.output_queue = asyncio.Queue()
        self.tagvars = {}

        self.serial = Serial(self.field)
        self.group_size = self.t + 1

        # self.omega = omega

        # dealer only
        self.Axy = []
        self.Exy = None
        self.vxy = None

        self.state = None
        self.Aik_Eik_buffers = [asyncio.Future() for _ in range(self.n)]
        self.smd_task = None
        self.process_task = None

    def kill(self):
        # logger.info("ACSS kill called")
        
        self.subscribe_recv_task.cancel()
        # logger.info("ACSS recv task cancelled")
        self.smd_task.cancel()
        
        for key in self.tagvars:
            # logger.debug(f"ACSS kill called, tag = {key}, self.tagvars[key]['tasks']={self.tagvars[key]}")
            for task in self.tagvars[key]['tasks']:
                if task is not None and not task.done():
                    task.cancel()
        
        self.process_task.cancel()
        # logger.info("ACSS self.tasks cancelled")

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self
    
    #@profile
    def _get_dealer_msg(self, values):
        # divide input B secrets into m=B/(t+1) groups
        # each group has t+1 secrets
        # for each group sample a bivariate polynomial f(x,y) of degree (t,t)
        # such that f(x,0) encode the t+1 secrets
        # stack the m bivariate polynomials into a vector \vec{f}(x,y)
        """
        Convert input secrets into a vector of bivariate polynomials (as dealer messages).

        Args:
            values (List[field]): A list of secrets to encode (length = B)
            n (int): Total number of parties (used to define evaluation grid)

        Returns:
            List[Polynomial_bi]: A list of bivariate polynomials f_i(x, y), each of degree (t, t)
                                such that f_i(x, 0) encodes t+1 secrets
        """

        def _pad_values_to_group(values, group_size, field):
            """
            Pad the values list with zeros so its length becomes a multiple of group_size.
            """
            padding = (-len(values)) % group_size
            if padding > 0:
                values += [field(0)] * padding
            return values
        
        group_size = self.group_size 
        values = _pad_values_to_group(values, group_size, self.field)
        
        m = len(values) // group_size

        polynomials = []

        for i in range(m):
            
            # Extract the group of t+1 secrets ai
            ai = values[i * group_size:(i + 1) * group_size]
            logger.debug(f'the {i}-th group of secrets: {ai}')
            
            # omega = get_omega(self.field, group_size)  
            # omega = self.omega
            # Ax0 = self.poly.interpolate_fft(ai, omega)
            # logger.debug(f"Ax0 = {Ax0}")
            Ax0 = self.poly.interpolate([(i + 1, ai[i]) for i in range(group_size)])

            # for j in range(group_size):
            #     logger.debug(f"A({j},0) = {Ax0(pow(omega, j))}")
            # Ax0_point = Ax0.evaluate_fft(omega, group_size)
            # logger.debug(f"Ax0_point = {Ax0_point}")

            Axy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t, x_poly_0=Ax0)
            logger.debug(f"the {i}-th bivariate polynomial: {Axy.coeffs}")
            # for j in range(group_size):
            #     # logger.error(f"secrets not same as Axy({j},0) = {Axy(pow(omega, j), 0)}, ai[j] = {ai[j]}", exc_info = not Axy(pow(omega, j)) == ai[j])
            #     logger.debug(f"A({j},0) = {Axy(pow(omega, j), 0)}")
            polynomials.append(Axy)
            self.Axy.append(Axy)
        
        self.Exy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t)
        polynomials.append(self.Exy)

        

        # smd_msg = [] # k in [n], i in [n]
        # for k in range(self.n):
        #     smd_msg_for_k = []
        #     for i in range(self.n):
        #         dealer_msg_for_k_point = [poly(k + 1, i + 1) for poly in polynomials]
        #         logger.debug(f'k = {k}, i = {i}, dealer_ms = {dealer_msg_for_k_point}')
        #         # smd_msg_for_k.append(self.serial.serialize_fs_GFElement(dealer_msg_for_k_point))
        #         smd_msg_for_k.append(dealer_msg_for_k_point)
        #     smd_msg.append(smd_msg_for_k)
        smd_msg = []
        # 预计算 (i+1) 的幂次
        powers = [i + 1 for i in range(self.n)]
        
        for k in range(self.n):
            smd_msg_for_k = []
            Aky = [poly.get_poly_y(k + 1) for poly in polynomials]
            for i in range(self.n):
                # 使用预计算的 powers[i] 替代 i+1
                smd_msg_for_k.append([poly(powers[i]) for poly in Aky])
            smd_msg.append(smd_msg_for_k)

        return smd_msg

    
    def _get_dealer_msg_rbc(self, smd_msg):
        logger.debug(f'in _get_dealer_msg_rbc')
        m = len(self.Axy)

        challenge_raw = [msg[1] for msg in smd_msg]

        challenge = []
        for i in range(m):
            data = b''.join(challenge_raw + [i.to_bytes(2, 'big')])
            challenge.append(self.field.hash(data))

        logger.debug(f'Node-[{self.my_id}]: challenge = {challenge}')


        vxy = self.Exy
        for i in range(m):
            # TODO: class polynomial_bi function rmul
            vxy += self.Axy[i].__rmul__(challenge[i])
    

        return dumps(vxy.coeffs)
    
    
    def _handle_smd_msg(self, smd_msg, tag):
        self.tagvars[tag]['shares_recv'] = []
        roots_recv = []
        val = True

        logger.debug(f'Node-[{self.my_id}]: smd_msg = {smd_msg}')

        for k in range(self.n):
            self.tagvars[tag]['shares_recv'].append(smd_msg[k][0])
            roots_recv.append(smd_msg[k][1])

        m = len(self.tagvars[tag]['shares_recv'][0]) - 1

        logger.debug(f'Node-[{self.my_id}]: m = {m}')

        # calculate challenge value
        challenge = []
        for i in range(m):
            data = b''.join(roots_recv + [i.to_bytes(2, 'big')])
            challenge.append(self.field.hash(data))

        logger.debug(f'Node-[{self.my_id}]: challenge = {challenge}, shares_recv = {self.tagvars[tag]["shares_recv"]}')

        # interpolate A(x,i), E(x,i)
        # TODO: implement FFT
        Axi = []

        # logger.debug(f"=== shares_recv as node {self.my_id}, shares_recv = {self.tagvars[tag]['shares_recv']}===")
        # for j, share_row in enumerate(self.tagvars[tag]['shares_recv'][j][m]):
        #     logger.debug(f"shares_recv[{j}] = [{share_row}]")

        Exi = self.poly.interpolate([(k + 1, self.tagvars[tag]['shares_recv'][k][m]) for k in range(self.t + 1)])
        for i in range(m):
            # else A(x, i)
            Axi.append(self.poly.interpolate(
                [(k + 1, self.tagvars[tag]['shares_recv'][k][i]) for k in range(self.t + 1)]
            ))
        self.poly.clear_cache()

        logger.debug(f'Node-[{self.my_id}]: Exi = {Exi}, Axi = {Axi}')

        self.tagvars[tag]['shares_poly'] = Axi
        self.tagvars[tag]['shares_poly_blind'] = Exi

        # verify the other (n-t) points whether on Axi and Exi
        # logger.debug(f'Node-[{self.my_id}]: Exi_shares = {[shares_recv[j][m] for j in range(self.n)]}')
        # logger.debug(f'Node-[{self.my_id}]: Exi_point = {[Exi(j + 1) for j in range(self.n)]}')
        
        for j in range(self.n):
            expected = self.tagvars[tag]['shares_recv'][j][m]
            actual = Exi(j + 1)
            if actual != expected:
                val = False
                logger.debug(
                    f"Node-[{self.my_id}]: verify Exi fail, Point check {actual == expected}: "
                    f"Exi({j+1})={actual}, expected={expected}, j={j}, m={m}, tag={tag}"
                )
            # logger.debug(f'Node-[{self.my_id}]: verify Exi, tag = {tag}')
            # assert Exi(j + 1) == shares_recv[j][m], f"Node-[{self.my_id}]: Point check failed: Exi({j+1})={Exi(j + 1)}, expected={shares_recv[j][m]} at j={j}, m={m}"
        for i in range(m):
            for j in range(self.n):
                logger.debug(f'Node-[{self.my_id}]: verify Axi, tag = {tag}')
                if Axi[i](j + 1) !=  self.tagvars[tag]['shares_recv'][j][i]:
                    val = False
                    logger.debug(
                        f"Node-[{self.my_id}]: verify Axi fail, Point check {Axi[i](j + 1) ==  self.tagvars[tag]['shares_recv'][j][i]}")

        return challenge, Exi, Axi, val

    def _handle_shares(self, challenge, Exi, Axi, vxy):
        # calculate v(x, i) = E(x, i) + r * A(x, i)
        vxi = Exi
        for i in range(len(Axi)):
            vxi += Axi[i].__rmul__(challenge[i])
        
        logger.debug(f"Node-[{self.my_id}]: vxi = {vxi}")
        
        if vxy.get_poly_x(self.receiver_ids.index(self.my_id) + 1) == vxi:
            logger.debug(f"vxi verified")
            return True
        else:
            logger.debug(f"vxi not verified, vxi = {vxy.get_poly_x(self.receiver_ids.index(self.my_id) + 1)}")
            return False
        
    async def _handle_share_recovery(self, tag):
        smd = self.tagvars[tag]['smd']
        faulty_sent = False
        rec_sent = False
        rec_sent_2 = False
        val_shares = defaultdict(lambda: [])

        def _handle_val_shares(msg, i1, i2, sender):

            all_shares = msg
            challenge = self.tagvars[tag]['challenge']

            m = len(all_shares) - 1

            vxy = self.tagvars[tag]['vxy']

            Eik = all_shares[m]
            Aik = all_shares[:m]
            vik = Eik
            for i in range(m):
                vik += challenge[i] * Aik[i]
            return vxy(i1 + 1, i2 + 1) == vik, sender, all_shares

        
        # async def monitor_flags(smd):
        #     flag_queue = asyncio.Queue()
            
        #     async def monitor_complain():
        #         while True:  # 持续监听
        #             await smd.forward_output_flag[GossamerAcssMessageType.COMPLAIN].wait()
        #             smd.forward_output_flag[GossamerAcssMessageType.COMPLAIN].clear()
        #             flag_queue.put_nowait(GossamerAcssMessageType.COMPLAIN)
                    
                    
        #     async def monitor_faulty():
        #         while True:  # 持续监听
        #             await smd.forward_output_flag[GossamerAcssMessageType.FAULTY].wait()
        #             smd.forward_output_flag[GossamerAcssMessageType.FAULTY].clear()
        #             flag_queue.put_nowait(GossamerAcssMessageType.FAULTY)
                    
                    
        #     async def monitor_rec():
        #         while True:  # 持续监听
        #             await smd.forward_output_flag[GossamerAcssMessageType.REC].wait()
        #             smd.forward_output_flag[GossamerAcssMessageType.REC].clear()
        #             flag_queue.put_nowait(GossamerAcssMessageType.REC)
                    
            
        #     tasks = [
        #         asyncio.create_task(monitor_complain()),
        #         asyncio.create_task(monitor_faulty()),
        #         asyncio.create_task(monitor_rec())
        #     ]
            
        #     return flag_queue, tasks
        
        # flag_queue, tasks = await monitor_flags(smd)

        exit_flag = False
        

        while True:
            msg_type, mj, i1, i2, sender = await smd.forward_output_queue.get()
            

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
                        logger.info(f"Node-[{self.my_id}]: vik not on vxy, send faulty, tag = {tag}, sender = {sender}")
                        faulty_sent = True
                        for receiver in self.receiver_ids:
                            smd.exforward_in_batch(receiver, GossamerAcssMessageType.FAULTY, self.receiver_ids.index(sender))

            elif msg_type == GossamerAcssMessageType.FAULTY:
                if not rec_sent and self.tagvars[tag]['shares_valid_local']:
                    logger.debug(f'Node-[{self.my_id}]: get {msg_type} msg from smd')
                    # smd.forward_output_flag[GossamerAcssMessageType.FAULTY].clear()
                    # faulty_msg = smd.forward_output[GossamerAcssMessageType.FAULTY]

                    val, sender, _ = _handle_val_shares(mj, i1, i2, sender)

                    if not val:
                        logger.info(f"Node-[{self.my_id}]: vik not on vxy, send rec, tag = {tag}")
                        rec_sent = True
                        for receiver in self.receiver_ids:
                            smd.forward_in_batch(receiver, self.receiver_ids.index(receiver), GossamerAcssMessageType.REC)

            elif msg_type == GossamerAcssMessageType.REC:
                if not rec_sent_2:
                    logger.debug(f'Node-[{self.my_id}]: get {msg_type} msg from smd')
                    # smd.forward_output_flag[GossamerAcssMessageType.REC].clear()
                    # rec_msg = smd.forward_output[GossamerAcssMessageType.REC]

                    val, sender, Aij_Eij = _handle_val_shares(mj, i1, i2, sender)

                    logger.debug(f'Node-[{self.my_id}]: val = {val}, sender = {sender}')

                    m = len(Aij_Eij)
                    
                    if val:
                        for i in range(m):
                            val_shares[i].append((self.receiver_ids.index(sender) + 1, Aij_Eij[i]))
                        logger.debug(f'Node-[{self.my_id}]: val_shares = {val_shares}')

                        if len(val_shares[0]) == self.t + 1:

                            Aiy_Eiy = []
                            for i in range(m):
                                Aiy_Eiy.append(self.poly.interpolate(val_shares[i]))
                            
                            logger.debug(f'Node-[{self.my_id}]: Aiy_Eiy = {Aiy_Eiy}')

                            rec_sent_2 = True
                            
                            for receiver in self.receiver_ids:
                                Aik_Eik = [Aiy_Eiy[i](self.receiver_ids.index(receiver) + 1) for i in range(m)]
                                self.tagvars[tag]['io'][0](receiver, (GossamerAcssMessageType.REC2, Aik_Eik))
                                logger.debug(f'Node-[{self.my_id}]: send rec2, tag = {tag}')
                            exit_flag = True
                            break
            else:
                break
        logger.debug(f'Node-[{self.my_id}]: end handle share recovery, tag = {tag}')
        return



    
    async def _process_acss_msg(self, acss_id, dealer_id, tag):

        rbc_start = time.time()
        
        
        smd_msg = self.tagvars[tag]['smd_msg']
        logger.debug(f'Node-[{self.my_id}]: smd_msg = {smd_msg}')


        # dealer RBC verification script
        rbc_tag = f"{dealer_id}-{acss_id}-[v(x,y)]-B-RBC"
        send, recv = self.get_send(rbc_tag), self.subscribe_recv(rbc_tag)
        
        rbc_msg = None
        if self.my_id == dealer_id:
            rbc_msg = self._get_dealer_msg_rbc(smd_msg)
        
            logger.debug(f'Node-[{self.my_id}]: get_dealer_msg_rbc, sid = {tag}')
        

        async def predicate(m=None):
            return True 

        logger.debug(f'Node-[{self.my_id}]: begin RBC')

    
        output = asyncio.Queue()
        rbc_task = asyncio.create_task(
        optqrbc(
            rbc_tag,
            self.my_id,
            self.receiver_ids,
            self.t,
            dealer_id,
            predicate,
            rbc_msg,
            output.put_nowait,
            send,
            recv
        )).add_done_callback(print_exception_callback)

        self.tagvars[tag]['tasks'].append(rbc_task)

        

        vxy_bytes = await output.get()

        rbc_time = time.time() - rbc_start
        logger.info(f"RBC time: {rbc_time}")

        share_output_start = time.time()

        if self.my_id == dealer_id:
            vxy_bytes = rbc_msg
            logger.debug(f'Node-[{self.my_id}]: dealer work done')

        logger.debug(f'Node-[{self.my_id}]: receive vxy in RBC, tag = {rbc_tag}, vxy = {vxy_bytes}')


        if self.my_id in self.receiver_ids:
            # verify secret shares
            send, recv = self.get_send(tag), self.subscribe_recv(tag)

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


            # deserilize vxy
            vxy = self.poly_bi(loads(vxy_bytes))
            self.tagvars[tag]['vxy'] = vxy

            # verify shares
            challenge, Exi, Axi, val = self._handle_smd_msg(smd_msg, tag)
            if val:
                self.tagvars[tag]['shares_valid_local'] = self._handle_shares(challenge, Exi, Axi, vxy)
            else:
                self.tagvars[tag]['shares_valid_local'] = False

            self.tagvars[tag]['challenge'] = challenge

        
            if self.tagvars[tag]['shares_valid_local']:
                logger.debug(f'Node-[{self.my_id}]: shares verified')
                multicast((GossamerAcssMessageType.OK, ""))
            else:
                res = asyncio.Future()

                robust_field = GF(Subgroup.BLS12_381)
                
                point = EvalPoint(robust_field, self.n, use_omega_powers=False)

                reconstruction = asyncio.create_task(
                    robust_reconstruct(self.Aik_Eik_buffers, robust_field, self.n, self.t, point, self.t, self.batch_size_poly + 1)
                )

                self.tagvars[tag]['tasks'].append(reconstruction)

                def cb(r):
                    p, errors = r.result()
                    if p is None:
                        logging.error(
                            f"Robust reconstruction for share (id:) "
                            f"failed with errors: {errors}!"
                        )
                        res.set_exception(
                            adkgError(f"Failed to open share !")
                        )
                    else:
                        res.set_result(p)

                reconstruction.add_done_callback(cb)
        
            
            rec2_flag = False

            aik_count = 0

            while True:
                # Bracha-style agreement
                sender, osv_msg = await recv()

                if rec2_flag == True and osv_msg[0] == GossamerAcssMessageType.REC2:
                    logger.debug(f'Node-[{self.my_id}]: receive rec2, tag = {tag}, osv_msg = {osv_msg}')

                    
                    Aik_Eik = [robust_field(int(b)) for b in osv_msg[1]]
                    
                    self.Aik_Eik_buffers[self.receiver_ids.index(sender)].set_result((self.receiver_ids.index(sender) + 1, Aik_Eik))
                    
                    aik_count += 1

                    logger.debug(f'Node-[{self.my_id}]: Aik_Eik_buffers = {self.Aik_Eik_buffers}')

                    if not self.tagvars[tag]['shares_valid_local']:
                        if res.done():
                            Axi_Exi = res.result()
                            logger.debug(f'Node-[{self.my_id}]: Axi_Eik = {Axi_Exi}')

                            # shares = []
                            # for _shares_poly in Axi_Exi[:-1]:
                            #     # shares.append(_shares_poly.evaluate_fft(self.omega, self.group_size))
                            #     shares.append([self.field(int(_shares_poly(i + 1))) for i in range(self.group_size)])

                            shares = []
                            # 预计算所有需要的点值
                            points = [self.field(i + 1) for i in range(self.group_size)]
                            
                            for _shares_poly in Axi_Exi[:-1]:
                                # 使用预计算的点值进行多项式求值
                                shares.append([self.field(int(_shares_poly(point))) for point in points])

                            shares = [share for row in shares for share in row]

                            #share_blind = Axi_Exi[-1].evaluate_fft(self.omega, self.group_size)
                            shares_blind = [self.field(int(Axi_Exi[-1](i + 1))) for i in range(self.group_size)]

                            self.output_queue.put_nowait((dealer_id, acss_id, shares, shares_blind))
                            output = True
                            logger.debug(f"Node-[{self.my_id}]: output in acss instance {tag}")

                            multicast((GossamerAcssMessageType.OK, ""))
                        elif aik_count == self.n:
                            Axi_Exi = await res
                            logger.debug(f'Node-[{self.my_id}]: Axi_Eik = {Axi_Exi}')

                            shares = []
                            # 预计算所有需要的点值
                            points = [self.field(i + 1) for i in range(self.group_size)]
                            
                            for _shares_poly in Axi_Exi[:-1]:
                                # 使用预计算的点值进行多项式求值
                                shares.append([self.field(int(_shares_poly(point))) for point in points])

                            shares = [share for row in shares for share in row]

                            #share_blind = Axi_Exi[-1].evaluate_fft(self.omega, self.group_size)
                            shares_blind = [self.field(int(Axi_Exi[-1](i + 1))) for i in range(self.group_size)]

                            self.output_queue.put_nowait((dealer_id, acss_id, shares, shares_blind))
                            output = True
                            logger.debug(f"Node-[{self.my_id}]: output in acss instance {tag}")

                            multicast((GossamerAcssMessageType.OK, ""))

                # OK
                if osv_msg[0] == GossamerAcssMessageType.OK and sender not in ok_set:
                    # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                    ok_set.add(sender)
                    if len(ok_set) >= (2 * self.t + 1) and not vote_sent:
                        vote_sent = True
                        multicast((GossamerAcssMessageType.VOTE, ""))

                if osv_msg[0] == GossamerAcssMessageType.VOTE and (sender not in vote_set):
                    # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                    vote_set.add(sender)
                    if len(vote_set) == (self.t + 1) and not ready_sent:
                        ready_sent = True
                        multicast((GossamerAcssMessageType.VOTE, ""))
                # if 2t+1 ready -> output shares
                if len(vote_set) == (2 * self.t + 1):
                    # output result by setting the future value
                    if self.tagvars[tag]['shares_valid_local'] and not output:

                        shares_poly = self.tagvars[tag]['shares_poly']
                        shares = []
                        for _shares_poly in shares_poly:
                            #shares.append(_shares_poly.evaluate_fft(self.omega, self.group_size))
                            shares.append([_shares_poly(i + 1) for i in range(self.group_size)])

                        logger.debug(f'Node-[{self.my_id}]: shares_poly = {shares_poly}')
                        logger.debug(f'Node-[{self.my_id}]: shares = {shares}')
                        
                        shares = [share for row in shares for share in row]

                        logger.debug(f'Node-[{self.my_id}]: shares = {shares}')
                        
                        shares_poly_blind = self.tagvars[tag]['shares_poly_blind']
                        # share_blind = shares_poly_blind.evaluate_fft(self.omega, self.group_size)
                        share_blind = [shares_poly_blind(i + 1) for i in range(self.group_size)]


                        self.output_queue.put_nowait((dealer_id, acss_id, shares, share_blind))
                        output = True
                        logger.debug(f"Node-[{self.my_id}]: output in acss instance {tag}")

                        share_output_time = time.time() - share_output_start
                        logger.info(f"Share output time: {share_output_time}")

                        await self._handle_share_recovery(tag)
                        logger.debug(f'Node-[{self.my_id}]: end share recovery')


                    elif not self.tagvars[tag]['shares_valid_local'] and not rec2_flag:
                        logger.debug(f'Node-[{self.my_id}]: begin complain')
                        smd = self.tagvars[tag]['smd']
                        for j in range(self.n):
                            smd.forward_in_batch(self.receiver_ids[j], j, GossamerAcssMessageType.COMPLAIN)
                        await self._handle_share_recovery(tag)
                        rec2_flag = True
                        logger.debug(f'Node-[{self.my_id}]: end complain')
                    

                # The only condition where we can terminate
                if (len(ok_set) == 3 * self.t + 1) and output:
                    #logger.debug("[%d] exit", self.my_id)
                    self.tagvars[tag] = {}
                    break
            

            return Exi, Axi, challenge
        

    #@profile
    async def acss(self, avss_id, values=None, dealer_id=None):
        """
        GoSSamer-acss: a lightweight batched ACSS protocol with linear communication complexity.
        values: [field.random() for _ in range(batch_size)] 
        output: node Pi get A(x,i)
        """

        acss_start_time = time.time()
        
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."

        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(avss_id) is int

        logger.debug(
            f"Node-[{self.my_id}]: Starting Batch AVSS. Dealer Id: {dealer_id}"
        )

        n = self.n

        acss_tag = f"{dealer_id}-{avss_id}-B-ACSS"

        self.tagvars[acss_tag] = {}
        self.tagvars[acss_tag]['tasks'] = []
        
        dealer_msg_start = time.time()
        if self.my_id == dealer_id:
            smd_distribute_msg = self._get_dealer_msg(values)
        dealer_msg_time = time.time() - dealer_msg_start
        logger.info(f"Dealer message generation time: {dealer_msg_time}")


        smd_msg_queue = [asyncio.Queue() for _ in range(n)]

        
        smd_tag = f"{dealer_id}-{avss_id}-B-SMD"

        send, recv = self.get_send(smd_tag), self.subscribe_recv(smd_tag)

        smd = SMD_SS24(
                    smd_tag,
                    n,
                    self.t,
                    self.my_id,
                    dealer_id,
                    [smd_msg_queue[i].put_nowait for i in range(n)],
                    send,
                    recv,
                    self.field,
                    self.receiver_ids
                )
        
        self.tagvars[acss_tag]['smd'] = smd

        smd_start = time.time()
        
        if self.my_id == dealer_id:
            task = asyncio.create_task(smd.distribute(smd_distribute_msg))
        else :
            task = asyncio.create_task(smd.distribute())
        task.add_done_callback(print_exception_callback)

        self.smd_task = task

        await smd.output_flag.wait()

        self.tagvars[acss_tag]['smd_msg'] = smd.output_queue
        smd_time = time.time() - smd_start
        logger.info(f"SMD distribution time: {smd_time}")

        logger.debug(
                f'Node-[{self.my_id}]: output in smd')

        logger.debug(f'Node-[{self.my_id}]: end')


        logger.debug(f"Node-[{self.my_id}]: tagvars_smd = {self.tagvars[acss_tag]['smd']}")
        
        
        process_task = asyncio.create_task(self._process_acss_msg(avss_id, dealer_id, acss_tag))
        process_task.add_done_callback(print_exception_callback)

        self.process_task = process_task
        
        await process_task
        
        
        acss_time = time.time() - acss_start_time

        # logger.info(f"ACSS time: {(acss_time)}")

        return 


        

class BadDealer(Gossamer_acss):

    def _get_dealer_msg(self, values):

        fault_n = range(self.t)
        fault_k = range(self.n)

        def _pad_values_to_group(values, group_size, field):
            """
            Pad the values list with zeros so its length becomes a multiple of group_size.
            """
            padding = (-len(values)) % group_size
            if padding > 0:
                values += [field(0)] * padding
            return values
        
        group_size = self.group_size 
        values = _pad_values_to_group(values, group_size, self.field)
        
        m = len(values) // group_size

        polynomials = []

        for i in range(m):
            
            # Extract the group of t+1 secrets ai
            ai = values[i * group_size:(i + 1) * group_size]
            logger.debug(f'the {i}-th group of secrets: {ai}')
        

            Ax0 = self.poly.interpolate([(i + 1, ai[i]) for i in range(group_size)])
            # Ax0 = self.poly.random(self.t)
            

            Axy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t, x_poly_0=Ax0)
            logger.debug(f"the {i}-th bivariate polynomial: {Axy.coeffs}")

            polynomials.append(Axy)
            self.Axy.append(Axy)
        
        self.Exy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t)
        polynomials.append(self.Exy)
        

        smd_msg = []
        # 预计算 (i+1) 的幂次
        powers = [i + 1 for i in range(self.n)]
        
        for k in range(self.n):
            smd_msg_for_k = []
            Aky = [poly.get_poly_y(k + 1) for poly in polynomials]
            for i in range(self.n):
                # 使用预计算的 powers[i] 替代 i+1
                smd_msg_for_k.append([poly(powers[i]) for poly in Aky])
            smd_msg.append(smd_msg_for_k)

        return smd_msg