import asyncio
from collections import defaultdict
from GoSSamer.crypto.elliptic_curve import Subgroup
from GoSSamer.crypto.field import GF
from pickle import dumps, loads
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
from concurrent.futures import ThreadPoolExecutor

import logging

from adkg.exceptions import adkgError
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
        self.record_event = lambda *args: None
        self.batch_size_poly = (batch_size + t) // (t + 1)
        
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
        # self.Aik_Eik_buffers = [[asyncio.Future() for _ in range(self.n)] for _ in range(self.batch_size_poly + 1)]
        self.Aik_Eik_buffers_all = [asyncio.Future() for _ in range(self.n)]
        self.Aik_Eik_shares = []
        self.smd_task = None
        self.process_task = None

    def kill(self):
        # logger.info("ACSS kill called")
        
        self.subscribe_recv_task.cancel()
        # logger.info("ACSS recv task cancelled")
        if self.smd_task is not None:
            self.smd_task.cancel()
        
        for key in self.tagvars:
            # logger.debug(f"ACSS kill called, tag = {key}, self.tagvars[key]['tasks']={self.tagvars[key]}")
            for task in self.tagvars[key].get('tasks', []):
                if task is not None and not task.done():
                    task.cancel()
        
        if self.process_task is not None:
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
            
            
            Ax0 = self.poly.interpolate([(i + 1, ai[i]) for i in range(group_size)])

            Axy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t, x_poly_0=Ax0)
            #Axy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t)
            logger.debug(f"the {i}-th bivariate polynomial: {Axy.coeffs}")

            polynomials.append(Axy)
            self.Axy.append(Axy)
        
        self.Exy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t)
        polynomials.append(self.Exy)

        # 缓存幂值
        x_pows_table = [[(k+1) ** a for a in range(self.t + 1)] for k in range(self.n)]

        smd_msg = []
        for k in range(self.n):
            smd_msg_for_k = []
            Aky = [poly.get_poly_y(k + 1) for poly in polynomials]
            for i in range(self.n):
                smd_msg_for_k.append([poly(i + 1) for poly in Aky])
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
    

        # Convert 2D coefficients array to 1D array for serialization
        # coeffs_1d = []
        # for row in vxy.coeffs:
        #     coeffs_1d.extend(row)

        return dumps(vxy.coeffs)
            
        
    
    
    def _handle_smd_msg(self, smd_msg, tag):
        self.tagvars[tag]['shares_recv'] = []
        roots_recv = []
        val = True

        logger.debug(f'Node-[{self.my_id}]: smd_msg = {smd_msg}')

        for k in range(self.n):
            self.tagvars[tag]['shares_recv'].append(smd_msg[k][0])
            roots_recv.append(smd_msg[k][1])

        # The batch dimension is public configuration, including when SMD
        # authenticates a ciphertext whose plaintext cannot be deserialized.
        m = self.batch_size_poly

        logger.debug(f'Node-[{self.my_id}]: m = {m}')

        # calculate challenge value
        challenge = []
        for i in range(m):
            data = b''.join(roots_recv + [i.to_bytes(2, 'big')])
            challenge.append(self.field.hash(data))

        if any(row is None for row in self.tagvars[tag]['shares_recv']):
            # Keep root-bound challenges for native complaint/recovery. There
            # are no local polynomials to trust until recovery completes.
            return challenge, None, None, False

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

            # SMD emits None only after authenticating and decrypting the
            # committed material. It is valid evidence of invalid content.
            if msg is None:
                return False, sender, ()

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
                        self.record_event('valid_accuse', self.my_id, {'sender': sender})
                        logger.debug(f"Node-[{self.my_id}]: vik not on vxy, send faulty, tag = {tag}, sender = {sender}")
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
                        logger.debug(f"Node-[{self.my_id}]: vik not on vxy, send rec, tag = {tag}")
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
                        self.record_event('rec1_valid', self.my_id, {'sender': sender})
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
                                self.record_event('rec2_sent', self.my_id, {'target': receiver})
                                logger.info(f'Node-[{self.my_id}]: send rec2 to {receiver}, tag = {tag}')
                            exit_flag = True
                            break
            else:
                break
        logger.debug(f'Node-[{self.my_id}]: end handle share recovery, tag = {tag}')
        return



    
    async def _process_acss_msg(self, acss_id, dealer_id, tag, rbc_output):

        rbc_start = time.time()
        
        
        smd_msg = self.tagvars[tag]['smd_msg']
        logger.debug(f'Node-[{self.my_id}]: smd_msg = {smd_msg}')


        # dealer RBC verification script
        


        if self.my_id == dealer_id:

            rbc_tag = f"{dealer_id}-{acss_id}-[v(x,y)]-B-RBC"
            send, recv = self.get_send(rbc_tag), self.subscribe_recv(rbc_tag)
            
            rbc_msg = None
            
            async def predicate(m=None):
                return True 
            rbc_msg = self._get_dealer_msg_rbc(smd_msg)
            rbc_task = asyncio.create_task(
            optqrbc(
                rbc_tag,
                self.my_id,
                self.receiver_ids,
                self.t,
                dealer_id,
                predicate,
                rbc_msg,
                rbc_output.put_nowait,
                send,
                recv
            )).add_done_callback(print_exception_callback)
            self.tagvars[tag]['tasks'].append(rbc_task)
        
            logger.debug(f'Node-[{self.my_id}]: get_dealer_msg_rbc, sid = {tag}')
        

        

        logger.info(f'Node-[{self.my_id}]: begin RBC')

    
        

        

        logger.info(f'Node-[{self.my_id}]: waiting for vxy in RBC')

        vxy_bytes = await rbc_output.get()

        rbc_time = time.time() - rbc_start
        logger.info(f"RBC time: {rbc_time}")

        share_output_start = time.time()

        if self.my_id == dealer_id:
            vxy_bytes = rbc_msg
            logger.debug(f'Node-[{self.my_id}]: dealer work done')

        logger.info(f'Node-[{self.my_id}]: receive vxy in RBC')


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

            # Convert back to 2D array
            # t = self.t
            # coeffs_2d = []
            # for i in range(t+1):
            #     coeffs_2d.append(vxy_bytes[i*(t+1):(i+1)*(t+1)])
                
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

            robust_field = GF(Subgroup.BLS12_381)

            async def batch_robust_reconstruct(B):
                res = asyncio.Future()
                point = EvalPoint(robust_field, self.n, use_omega_powers=False)

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
                        res.set_result((p, errors))

                reconstruction_post = asyncio.create_task(
                        robust_reconstruct(self.Aik_Eik_buffers_all, robust_field, self.n, self.t, point, self.t, B)
                    )
                reconstruction_post.add_done_callback(cb)
                poly, errors = await res
                self.record_event('oec_success', self.my_id, {'errors': list(errors) if errors else []})
                poly_rec = poly
                
                return poly_rec  

        
            if self.tagvars[tag]['shares_valid_local']:
                logger.info(f'Node-[{self.my_id}]: shares verified')
                multicast((GossamerAcssMessageType.OK, ""))
            else:
                logger.info(f'Node-[{self.my_id}]: shares not verified')
                reconstruction_task = asyncio.create_task(
                                batch_robust_reconstruct(self.batch_size_poly + 1))
                # Completion must wake the state machine even if a Byzantine
                # node stays silent and no further REC2 packet will arrive.
                reconstruction_task.add_done_callback(lambda task:
                    self.tagvars[tag]['io'][0](self.my_id, ('RECONSTRUCTED', None))
                    if not task.cancelled() else None)
                self.tagvars[tag]['tasks'].append(reconstruction_task)
                logger.info(f'Node-[{self.my_id}]: begin robust reconstruction')

            # async def batch_robust_reconstruct(B):

            #     black_list = set()
            #     point = EvalPoint(robust_field, self.n, use_omega_powers=False)
            #     poly_rec = []
                
            #     for i in range(B):
            #         res = asyncio.Future()

            #         def cb(r):
            #             p, errors = r.result()
            #             if p is None:
            #                 logging.error(
            #                     f"Robust reconstruction for share (id:) "
            #                     f"failed with errors: {errors}!"
            #                 )
            #                 res.set_exception(
            #                     adkgError(f"Failed to open share !")
            #                 )
            #             else:
            #                 res.set_result((p, errors))

                    

            #         reconstruction_pre = asyncio.create_task(
            #             robust_reconstruct(self.Aik_Eik_buffers[i], robust_field, self.n, self.t, point, self.t, 1, errors=black_list)
            #         )
            #         reconstruction_pre.add_done_callback(cb)

            #         poly, errors = await res
            #         poly_rec.extend(poly)
            #         black_list = set(black_list) | set(errors)

            #         logger.info(f"black_list = {black_list}")

            #         if len(black_list) == self.t:
            #             res = asyncio.Future()
                        
            #             reconstruction_post = asyncio.create_task(
            #                 robust_reconstruct(self.Aik_Eik_buffers_all, robust_field, self.n, self.t, point, self.t, B, errors=black_list)
            #             )
            #             reconstruction_post.add_done_callback(cb)
            #             poly, errors = await res
            #             poly_rec = poly
            #             break
                
            #     return poly_rec

            
        
            
            rec2_flag = False
            pending_rec2 = {}
            aik_count = 0
            Aik_Eik_shares = []

            while True:
                # Bracha-style agreement
                if rec2_flag and pending_rec2:
                    sender, osv_msg = pending_rec2.popitem()
                else:
                    sender, osv_msg = await recv()
                # Other targets can trigger recovery before this node has
                # received enough VOTEs. Keep each sender's first REC2 locally.
                if osv_msg[0] == GossamerAcssMessageType.REC2 and not rec2_flag:
                    pending_rec2.setdefault(sender, osv_msg)
                    continue

                if rec2_flag == True and osv_msg[0] in (GossamerAcssMessageType.REC2, 'RECONSTRUCTED'):
                    logger.info(f'Node-[{self.my_id}]: receive rec2, tag = {tag}')

                    
                    if osv_msg[0] == GossamerAcssMessageType.REC2:
                        Aik_Eik = [robust_field(int(b)) for b in osv_msg[1]]
                        Aik_Eik_shares.append((self.receiver_ids.index(sender) + 1, Aik_Eik))

                    # for k in range(len(Aik_Eik)):
                    #     self.Aik_Eik_buffers[k][self.receiver_ids.index(sender)].set_result((self.receiver_ids.index(sender) + 1, [Aik_Eik[k]]))
                    
                        buffer = self.Aik_Eik_buffers_all[self.receiver_ids.index(sender)]
                        if not buffer.done():
                            buffer.set_result((self.receiver_ids.index(sender) + 1, Aik_Eik))
                            aik_count += 1

                    # logger.debug(f'Node-[{self.my_id}]: Aik_Eik_buffers = {self.Aik_Eik_buffers}')

                    if not self.tagvars[tag]['shares_valid_local']:
                        
                        Axi_Exi = None
                        if reconstruction_task.done():
                            Axi_Exi = reconstruction_task.result()
                        else:
                            if aik_count == self.n:
                                Axi_Exi = await reconstruction_task

                        if Axi_Exi is None:
                            continue
                        
                        logger.info(f'Node-[{self.my_id}]: Axi_Eik')

                        shares = []
                        for _shares_poly in Axi_Exi[:-1]:
                            # shares.append(_shares_poly.evaluate_fft(self.omega, self.group_size))
                            shares.append([self.field(int(_shares_poly(i + 1))) for i in range(self.group_size)])

                        shares = [share for row in shares for share in row]

                        #share_blind = Axi_Exi[-1].evaluate_fft(self.omega, self.group_size)
                        shares_blind = [self.field(int(Axi_Exi[-1](i + 1))) for i in range(self.group_size)]

                        self.record_event('output', self.my_id, {})
                        self.output_queue.put_nowait((dealer_id, acss_id, shares, shares_blind))
                        output = True
                        logger.info(f"Node-[{self.my_id}]: output in acss instance {tag}")

                        self.tagvars[tag]['shares_valid_local'] = True

                        multicast((GossamerAcssMessageType.OK, ""))

                        
                        # res = asyncio.Future()
                        
                        # if res_pre.done():
                        #     _, errors = res_pre.result()
                        #     robust_field = GF(Subgroup.BLS12_381)
                        #     point = EvalPoint(robust_field, self.n, use_omega_powers=False)
                        

                        #     def cb(r):
                        #         p, errors = r.result()
                        #         if p is None:
                        #             logging.error(
                        #                 f"Robust reconstruction for share (id:) "
                        #                 f"failed with errors: {errors}!"
                        #             )
                        #             res.set_exception(
                        #                 adkgError(f"Failed to open share !")
                        #             )
                        #         else:
                        #             res.set_result((p, errors))

                        #     reconstruction = asyncio.create_task(
                        #         robust_reconstruct(self.Aik_Eik_buffers, robust_field, self.n, self.t, point, self.t, self.batch_size_poly + 1, errors=errors)
                        #     )
                        #     reconstruction.add_done_callback(cb)
                        #     self.tagvars[tag]['tasks'].append(reconstruction)
                        #     res_flag = True

                        # if res.done():
                        #     Axi_Exi, _ = res.result()
                        #     logger.debug(f'Node-[{self.my_id}]: Axi_Eik = {Axi_Exi}')

                        #     shares = []
                        #     for _shares_poly in Axi_Exi[:-1]:
                        #         # shares.append(_shares_poly.evaluate_fft(self.omega, self.group_size))
                        #         shares.append([self.field(int(_shares_poly(i + 1))) for i in range(self.group_size)])

                        #     shares = [share for row in shares for share in row]

                        #     #share_blind = Axi_Exi[-1].evaluate_fft(self.omega, self.group_size)
                        #     shares_blind = [self.field(int(Axi_Exi[-1](i + 1))) for i in range(self.group_size)]

                        #     self.output_queue.put_nowait((dealer_id, acss_id, shares, shares_blind))
                        #     output = True
                        #     logger.debug(f"Node-[{self.my_id}]: output in acss instance {tag}")

                        #     multicast((GossamerAcssMessageType.OK, ""))
                        # if aik_count == self.n:
                        #     if not res_flag:
                        #         _, errors =await res_pre
                        #         robust_field = GF(Subgroup.BLS12_381)
                        #         point = EvalPoint(robust_field, self.n, use_omega_powers=False)
                                
                        #         res = asyncio.Future()

                        #         def cb(r):
                        #             p, errors = r.result()
                        #             if p is None:
                        #                 logging.error(
                        #                     f"Robust reconstruction for share (id:) "
                        #                     f"failed with errors: {errors}!"
                        #                 )
                        #                 res.set_exception(
                        #                     adkgError(f"Failed to open share !")
                        #                 )
                        #             else:
                        #                 res.set_result((p, errors))

                        #         reconstruction = asyncio.create_task(
                        #             robust_reconstruct(self.Aik_Eik_buffers, robust_field, self.n, self.t, point, self.t, self.batch_size_poly + 1, errors=errors)
                        #         )
                        #         reconstruction.add_done_callback(cb)
                        #         self.tagvars[tag]['tasks'].append(reconstruction)
                        #         res_flag = True

                            # Axi_Exi, _ = await res
                            # logger.debug(f'Node-[{self.my_id}]: Axi_Eik = {Axi_Exi}')

                            # shares = []
                            # for _shares_poly in Axi_Exi[:-1]:
                            #     # shares.append(_shares_poly.evaluate_fft(self.omega, self.group_size))
                            #     shares.append([self.field(int(_shares_poly(i + 1))) for i in range(self.group_size)])

                            # shares = [share for row in shares for share in row]

                            # #share_blind = Axi_Exi[-1].evaluate_fft(self.omega, self.group_size)
                            # shares_blind = [self.field(int(Axi_Exi[-1](i + 1))) for i in range(self.group_size)]

                            # self.output_queue.put_nowait((dealer_id, acss_id, shares, shares_blind))
                            # output = True
                            # logger.debug(f"Node-[{self.my_id}]: output in acss instance {tag}")

                            # multicast((GossamerAcssMessageType.OK, ""))

                # OK
                if osv_msg[0] == GossamerAcssMessageType.OK and sender not in ok_set:
                    # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                    logger.info(f'Node-[{self.my_id}]: receive ok from {sender}')
                    ok_set.add(sender)
                    if len(ok_set) >= (2 * self.t + 1) and not vote_sent:
                        vote_sent = True
                        multicast((GossamerAcssMessageType.VOTE, ""))
                        logger.info(f'Node-[{self.my_id}]: send vote')

                if osv_msg[0] == GossamerAcssMessageType.VOTE and (sender not in vote_set):
                    # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                    logger.info(f'Node-[{self.my_id}]: receive vote from {sender}')
                    vote_set.add(sender)
                    if len(vote_set) == (self.t + 1) and not ready_sent:
                        ready_sent = True
                        multicast((GossamerAcssMessageType.VOTE, ""))
                        logger.info(f'Node-[{self.my_id}]: send vote')
                # if 2t+1 ready -> output shares
                if len(vote_set) == (2 * self.t + 1):
                    # output result by setting the future value
                    logger.info(f'Node-[{self.my_id}]: 2t+1 vote received')
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


                        self.record_event('output', self.my_id, {})
                        self.output_queue.put_nowait((dealer_id, acss_id, shares, share_blind))
                        output = True
                        logger.info(f"Node-[{self.my_id}]: output in acss instance {tag}")

                        share_output_time = time.time() - share_output_start
                        logger.info(f"Share output time: {share_output_time}")

                        await self._handle_share_recovery(tag)
                        logger.debug(f'Node-[{self.my_id}]: end share recovery')


                    elif not self.tagvars[tag]['shares_valid_local'] and not rec2_flag:
                        logger.debug(f'Node-[{self.my_id}]: begin complain')
                        smd = self.tagvars[tag]['smd']
                        self.record_event('accuse', self.my_id, {'recipients': list(self.receiver_ids)})
                        for j in range(self.n):
                            smd.forward_in_batch(self.receiver_ids[j], j, GossamerAcssMessageType.COMPLAIN)
                        await self._handle_share_recovery(tag)
                        rec2_flag = True
                        logger.debug(f'Node-[{self.my_id}]: end complain')

                # The only condition where we can terminate
                if (len(ok_set) == 3 * self.t + 1) and output:
                    logger.debug("[%d] exit", self.my_id)
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

        logger.info(
            f"Node-[{self.my_id}]: Starting Batch AVSS. Dealer Id: {dealer_id}"
        )

        n = self.n

        acss_tag = f"{dealer_id}-{avss_id}-B-ACSS"

        self.tagvars[acss_tag] = {}
        self.tagvars[acss_tag]['tasks'] = []


        rbc_output = asyncio.Queue()

        if self.my_id != dealer_id:

            rbc_tag = f"{dealer_id}-{avss_id}-[v(x,y)]-B-RBC"
            send, recv = self.get_send(rbc_tag), self.subscribe_recv(rbc_tag)
            
            rbc_msg = None
            
            async def predicate(m=None):
                return True 
            
            rbc_task = asyncio.create_task(
            optqrbc(
                rbc_tag,
                self.my_id,
                self.receiver_ids,
                self.t,
                dealer_id,
                predicate,
                rbc_msg,
                rbc_output.put_nowait,
                send,
                recv
            ))
            
            rbc_task.add_done_callback(print_exception_callback)
            self.tagvars[acss_tag]['tasks'].append(rbc_task)




        
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

        logger.info(
                f'Node-[{self.my_id}]: output in smd')

        logger.debug(f'Node-[{self.my_id}]: end')
        
        
        process_task = asyncio.create_task(self._process_acss_msg(avss_id, dealer_id, acss_tag, rbc_output))
        process_task.add_done_callback(print_exception_callback)

        self.process_task = process_task
        
        await process_task
        
        
        acss_time = time.time() - acss_start_time

        # logger.info(f"ACSS time: {(acss_time)}")

        return 


        

class BadDealer(Gossamer_acss):

    def _get_dealer_msg(self, values):

        fault_n = getattr(self, 'fault_targets', range(self.t))
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
            # Axy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t)
            logger.debug(f"the {i}-th bivariate polynomial: {Axy.coeffs}")

            polynomials.append(Axy)
            self.Axy.append(Axy)
        
        self.Exy = self.poly_bi.random_bi(degree_x = self.t, degree_y=self.t)
        polynomials.append(self.Exy)

        
        # for i in range(self.n):
        #     logger.debug(f"=== as node {self.my_id}, shares_send to node {i} or {self.receiver_ids[i]}===")
        #     for k in range(self.n):
        #         logger.debug(f'{self.Exy(k + 1, i + 1)}')
        

        smd_msg = []
        for k in range(self.n):
            smd_msg_for_k = []
            Aky = [poly.get_poly_y(k + 1) for poly in polynomials]
            for i in range(self.n):
                if i in fault_n:
                    smd_msg_for_k.append([self.field.random()] * (len(polynomials)))
                else:
                    smd_msg_for_k.append([poly(i + 1) for poly in Aky])
            smd_msg.append(smd_msg_for_k)

        return smd_msg
