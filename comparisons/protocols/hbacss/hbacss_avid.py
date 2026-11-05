import asyncio
from collections import defaultdict
import time
#from pickle import dumps, loads
#from dpss.broadcast.crypto.boldyreva import dealer, serialize
from pypairing import ZR as pZR
from GoSSamer.crypto.polynomial import polynomials_over
from GoSSamer.crypto.symmetric_crypto import SymmetricCrypto
from GoSSamer.util.misc import wrap_send, subscribe_recv, print_exception_callback
# from dpss.broadcast.qrbc import qrbc
from GoSSamer.distribute.optqrbc import optqrbc
#from dpss.utils.serilization import serialize_gs, deserialize_gs, deserialize_g, deserialize_f
from comparisons.protocols.hbacss.serializer import serialize as dumps, deserialize as loads
from GoSSamer.distribute.avid import AVID
from comparisons.protocols.hbacss.share_recovery import poly_lagrange_at_x, poly_interpolate_at_x, interpolate_g1_at_x

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Uncomment this when you want logs from this file.
# logger.setLevel(logging.DEBUG)


class HbAVSSMessageType:
    OK = "OK"
    IMPLICATE = "IMPLICATE"
    READY = "READY"
    RECOVERY = "RECOVERY"
    RECOVERY1 = "RECOVERY1"
    RECOVERY2 = "RECOVERY2"
    KDIBROADCAST = "KDIBROADCAST"

class Hbacss0:
    #@profile
    def __init__(self, public_keys, private_key, g, h, receiver_ids, t, my_id, G1, ZR, send, recv, pc, client_mode=False):
    #def __init__(
    #        self, public_keys, private_key, g, n, t, my_id, send, recv, pc, field=ZR
    #):  # (# noqa: E501)
        self.public_keys, self.private_key = public_keys, private_key
        self.t, self.my_id = t, my_id
        self.g, self.h = g, h
        self.receiver_ids = receiver_ids
        self.n = len(receiver_ids)
        self.poly_commit = pc

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

        self.acss_status = defaultdict(lambda: True)
        self.field = ZR
        self.poly = polynomials_over(self.field)
        self.poly.clear_cache()
        self.output_queue = asyncio.Queue()
        self.shares_future = asyncio.Future()
        self.avid_msg_queue = asyncio.Queue()
        self.tagvars = {}
        self.tasks = []
        self.total_time = 0
        self.client_mode = client_mode

    #def __exit__(self, typ, value, traceback):
    def kill(self):
        # self.benchmark_logger.info("ACSS kill called")
        self.subscribe_recv_task.cancel()
        # self.benchmark_logger.info("ACSS recv task cancelled")
        for task in self.tasks:
            task.cancel()
        # self.benchmark_logger.info("ACSS self.tasks cancelled")
        for key in self.tagvars:
            for task in self.tagvars[key]['tasks']:
                task.cancel()
        # self.benchmark_logger.info("ACSS self tagvars canceled")

    async def _recv_loop(self, q):
        while True:
            avid, tag, dispersal_msg_list = await q.get()
            task = asyncio.create_task(avid.disperse(tag, self.my_id, dispersal_msg_list))
            task.add_done_callback(print_exception_callback)
            self.tasks.append(
                task
            )

    def __enter__(self):
        self.avid_recv_task = asyncio.create_task(self._recv_loop(self.avid_msg_queue))
        return self

    def __exit__(self, typ, value, traceback):
        self.subscribe_recv_task.cancel()
        self.avid_recv_task.cancel()
        for task in self.tasks:
            task.cancel()

    
    #@profile
    async def _handle_implication(self, tag, j, j_sk):
        """
        Handle the implication of AVSS.
        Return True if the implication is valid, False otherwise.
        """
        commitments =  self.tagvars[tag]['commitments']
        # discard if PKj ! = g^SKj
        if self.public_keys[j] != pow(self.g, j_sk):
            logger.debug(f"implicate failed, public_keys[j] != pow(self.g, j_sk), j = {j}, j_sk = {j_sk}")
            return False
        # decrypt and verify
        implicate_msg = await self.tagvars[tag]['avid'].retrieve(tag, self.receiver_ids.index(j))
        j_shared_key = pow(self.tagvars[tag]['ephemeral_public_key'], j_sk)

        # Same as the batch size
        secret_count = len(commitments)

        try:
            j_z = SymmetricCrypto.decrypt(
                str(j_shared_key).encode(), implicate_msg
            )
            j_shares, j_witnesses = loads(j_z)
        except Exception as e:  # TODO specific exception
            logger.warn("Implicate confirmed, bad encryption:", e)
            return True
        return not self.poly_commit.batch_verify_eval(
            commitments, j + 1, j_shares, j_witnesses
        )

    def _init_recovery_vars(self, tag):
        self.kdi_broadcast_sent = False
        self.saved_shares = [None] * self.n
        self.saved_shared_actual_length = 0
        self.interpolated = False

    # this function should eventually multicast OK, set self.tagvars[tag]['all_shares_valid'] to True, and set self.tagvars[tag]['shares']
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['in_share_recovery']:
            return
        if self.tagvars[tag]['all_shares_valid'] and not self.kdi_broadcast_sent:
            logger.debug("[%d] sent_kdi_broadcast", self.my_id)
            kdi = self.tagvars[tag]['shared_key']
            multicast((HbAVSSMessageType.KDIBROADCAST, kdi))
            self.kdi_broadcast_sent = True
        if self.tagvars[tag]['all_shares_valid']:
            return

        if avss_msg[0] == HbAVSSMessageType.KDIBROADCAST:
            logger.debug("[%d] received_kdi_broadcast from sender %d", self.my_id, sender)
            
            # FIXME: IMPORTANT!! read the message from rbc output
            # retrieved_msg = await avid.retrieve(tag, sender)
            retrieved_msg = None
            try:
                j_shares, j_witnesses = SymmetricCrypto.decrypt(
                    str(avss_msg[1]).encode(), retrieved_msg
                )
            except Exception as e:  # TODO: Add specific exception
                logger.debug("Implicate confirmed, bad encryption:", e)
            commitments = self.tagvars[tag]['commitments']
            if (self.poly_commit.batch_verify_eval(commitments,
                                                   sender + 1, j_shares, j_witnesses, self.t)):
                if not self.saved_shares[sender]:
                    self.saved_shared_actual_length += 1
                    self.saved_shares[sender] = j_shares

        # if t+1 in the saved_set, interpolate and sell all OK
        if self.saved_shared_actual_length >= self.t + 1 and not self.interpolated:
            logger.debug("[%d] interpolating", self.my_id)
            # Batch size
            shares = []
            secret_count = len(self.tagvars[tag]['commitments'])
            for i in range(secret_count):
                phi_coords = [
                    (j + 1, self.saved_shares[j][i]) for j in range(self.n) if self.saved_shares[j] is not None
                ]
                shares.append(self.poly.interpolate_at(phi_coords, self.my_id + 1))
            self.tagvars[tag]['all_shares_valid'] = True
            self.tagvars[tag]['shares'] = shares
            self.tagvars[tag]['in_share_recovery'] = False
            self.interpolated = True
            multicast((HbAVSSMessageType.OK, ""))
    
    def decode_proposal(self, proposal):
        if True:
            dispersal_msgs, commits, ephkey = loads(proposal)
            dispersal_msg = dispersal_msgs[self.receiver_ids.index(self.my_id)]
            return (dispersal_msg, commits, ephkey)
        g_size = 48
        c_size = 64

        commit_data = proposal[0:g_size*(self.t+1)]
        commits = deserialize_gs(commit_data) 

        ephkey_data = proposal[g_size*(self.t+1):g_size*(self.t+2)]
        ephkey = deserialize_g(ephkey_data)

        dispersal_msg_raw = proposal[g_size*(self.t+2):]
        dispersal_msg = dispersal_msg_raw[self.my_id*c_size : (self.my_id+1)*c_size]

        return (dispersal_msg, commits, ephkey)

    
    def verify_proposal(self, dealer_id, dispersal_msg, commits, ephkey):
        shared_key = pow(ephkey, self.private_key)
        logger.debug("[%d] Decrypting Proposal", self.my_id)

        try:
            sharesb = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
            logger.debug("[%d] Decrypted", self.my_id)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            self.acss_status[dealer_id] = False
            return False
        logger.debug("[%d] unpacking", self.my_id)
        shares, witnesses = loads(sharesb)
        logger.debug("[%d] calling bve", self.my_id)
        #witnesses = [None]

        #shares = [deserialize_f(sharesb)]

        if self.poly_commit.batch_verify_eval(
            commits, self.my_id + 1, shares, witnesses
        ): 
            self.acss_status[dealer_id] = True
            logger.debug("[%d] Accepted Dealer's proposal", self.my_id)
            return True
        
        self.acss_status[dealer_id] = False
        print("failed verification!")
        return False

    
    #@profile    
    async def _process_avss_msg(self, avss_id, dealer_id, rbc_msg, avid):
        tag = f"{dealer_id}-{avss_id}-B-AVSS"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        self.tagvars[tag] = {}
        self._init_recovery_vars(tag)

        def multicast(msg):
            for i in self.receiver_ids:
                send(i, msg)

        self.tagvars[tag]['io'] = [send, recv, multicast]
        self.tagvars[tag]['avid'] = avid
        implicate_sent = False
        self.tagvars[tag]['in_share_recovery'] = False
        # get phi and public key from reliable broadcast msg
        #commitments, ephemeral_public_key = loads(rbc_msg)
        # retrieve the z
        dispersal_msg = await avid.retrieve(tag, self.receiver_ids.index(self.my_id))
        # this function will both load information into the local variable store 
        # and verify share correctness
        self.tagvars[tag]['all_shares_valid'] = self._handle_dealer_msgs(tag, dispersal_msg, rbc_msg, dealer_id)
        if self.tagvars[tag]['all_shares_valid']:
            multicast((HbAVSSMessageType.OK, ""))
        else:
            multicast((HbAVSSMessageType.IMPLICATE, self.private_key))
            implicate_sent = True
            self.tagvars[tag]['in_share_recovery'] = True

    

        ok_set = set()
        ready_set = set()
        implicate_set = set()
        output = False
        ready_sent = False

        while True:
            # Bracha-style agreement
            sender, avss_msg = await recv()

            # IMPLICATE
            if avss_msg[0] == HbAVSSMessageType.IMPLICATE and not self.tagvars[tag]['in_share_recovery']:
                if sender not in implicate_set:
                    implicate_set.add(sender)
                    # validate the implicate
                    #todo: implicate should be forwarded to others if we haven't sent one
                    if await self._handle_implication(tag, sender, avss_msg[1]):
                        # proceed to share recovery
                        self.tagvars[tag]['in_share_recovery'] = True
                        await self._handle_share_recovery(tag)
                        logger.debug("[%d] after implication", self.my_id)

            #todo find a more graceful way to handle different protocols having different recovery message types
            if avss_msg[0] in [HbAVSSMessageType.KDIBROADCAST, HbAVSSMessageType.RECOVERY1, HbAVSSMessageType.RECOVERY2]:
                await self._handle_share_recovery(tag, sender, avss_msg)
            # OK
            if avss_msg[0] == HbAVSSMessageType.OK and sender not in ok_set:
                # logger.debug("[%d] Received OK from [%d]", self.my_id, sender)
                ok_set.add(sender)
                if len(ok_set) >= (2 * self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # READY
            if avss_msg[0] == HbAVSSMessageType.READY and (sender not in ready_set):
                # logger.debug("[%d] Received READY from [%d]", self.my_id, sender)
                ready_set.add(sender)
                if len(ready_set) >= (self.t + 1) and not ready_sent:
                    ready_sent = True
                    multicast((HbAVSSMessageType.READY, ""))
            # if 2t+1 ready -> output shares
            if len(ready_set) >= (2 * self.t + 1):
                # output result by setting the future value
                if self.tagvars[tag]['all_shares_valid'] and not output:
                    shares = self.tagvars[tag]['shares']
                    int_shares = [int(shares[i]) for i in range(len(shares))]
                    self.output_queue.put_nowait((dealer_id, avss_id, int_shares))
                    output = True
                    logger.debug("[%d] Output", self.my_id)

                    end_time = time.time()
                    self.benchmark_logger.info(f"Time taken to output shares: {end_time - self.start_time} seconds")
                    self.benchmark_logger.info(f"total times: {end_time - self.total_time} seconds")


            # The only condition where we can terminate
            if (len(ok_set) == self.n) and output:
                logger.debug("[%d] exit", self.my_id)
                self.tagvars[tag] = {}
                break
    #@profile
    def _get_dealer_msg(self, values):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        logger.debug("[%d] generating dealer message", self.my_id)
        '''
        while len(values) % (batch_size) != 0:
            values.append(0)
        '''
        secret_count = len(values)
        phi = [None] * secret_count
        commitments = [None] * secret_count
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        # r = ZR.random()
        for k in range(secret_count):
            phi[k] = self.poly.random(self.t, values[k])
            commitments[k] = self.poly_commit.commit(phi[k])

        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        #dispersal_msg_list = bytearray()
        dispersal_msg_list = []
        logger.debug("[%d] generating dealer message", self.my_id)
        rids_plus_1 = [self.receiver_ids.index(id)+1 for id in self.receiver_ids]
        witnesses = self.poly_commit.double_batch_create_witness(phi, rids_plus_1, n=self.n)
        
        #phis_i = [phi[k](rids_plus_1[0] + 1) for k in range(secret_count)]
        #phis_hat_i = [phi_hat[k](rids_plus_1[0] + 1) for k in range(secret_count)]
        #print(self.poly_commit.batch_verify_eval(commitments, rids_plus_1[0], phis_i, phis_hat_i, witnesses[0]))
        
        logger.debug("[%d] generating dealer message", self.my_id)
        #for i in range(n):
        for i, receiver in enumerate(self.receiver_ids):
            shared_key = self.public_keys[receiver].pow(ephemeral_secret_key)
            #phis_i = [phi[k](receiver + 1).__getstate__() for k in range(secret_count)]
            logger.debug("[%d] finna eval on em", self.my_id)
            phis_i = [phi[k](self.receiver_ids.index(receiver) + 1) for k in range(secret_count)]
            #z = (phis_i, witnesses[i])
            logger.debug("[%d] finna dump on em", self.my_id)
            z = dumps((phis_i, witnesses[i]))
            #print(z)
            logger.debug("[%d] finna encrypt on em", self.my_id)
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            #zz = SymmetricCrypto.encrypt(str(shared_key).encode(), phis_i[0])
            #dispersal_msg_list.extend(zz)
            dispersal_msg_list.append(zz)
        #commitments[0].append(ephemeral_public_key)
        logger.debug("[%d] generating dealer message", self.my_id)
        return dumps((commitments, ephemeral_public_key)), dispersal_msg_list
        '''
        datab = serialize_gs(commitments[0]) # Serializing commitments
        
        # TODO: Note that this only works for hbACSS
        datab.extend(dispersal_msg_list) # Appending the AVID messages
        return bytes(datab)
        '''
    
    #@profile
    def _handle_dealer_msgs(self, tag, dispersal_msg, rbc_msg, dealer_id):

        all_shares_valid = True
        logger.debug(f"rbc_msg: {rbc_msg}")
        commitments, ephemeral_public_key = loads(rbc_msg)
        shared_key = pow(ephemeral_public_key, self.private_key)
        self.tagvars[tag]['shared_key'] = shared_key
        self.tagvars[tag]['commitments'] = commitments
        self.tagvars[tag]['ephemeral_public_key'] = ephemeral_public_key
        
        try:
            sharesb = SymmetricCrypto.decrypt(str(shared_key).encode(), dispersal_msg)
        except ValueError as e:  # TODO: more specific exception
            logger.warn(f"Implicate due to failure in decrypting: {e}")
            all_shares_valid = False

        logger.debug(f"sharesb: {sharesb}")

        # call if decryption was successful
        if all_shares_valid:
            logger.debug(f"all_shares_valid: {all_shares_valid}")

            shares, witnesses = loads(sharesb)
            if self.poly_commit.batch_verify_eval(
                    commitments, self.receiver_ids.index(self.my_id) + 1, shares, witnesses
            ):
                self.tagvars[tag]['shares'] = shares
                self.tagvars[tag]['witnesses'] = witnesses
                logger.debug(f"self.poly_commit.batch_verify_eval: {True}")
            else:
                all_shares_valid = False
                # all_shares_valid = True
                # self.tagvars[tag]['shares'] = shares
                # self.tagvars[tag]['witnesses'] = witnesses
                logger.error(f"self.poly_commit.batch_verify_eval: {False}")
        return all_shares_valid

    #@profile
    async def avss(self, avss_id, values=None, dealer_id=None):
        """
        An acss with share recovery
        """
        self.total_time = time.time()
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id, "You're gonna need some shares, dealer"
        assert type(avss_id) is int, "avss_id should be an int"

        # logger.debug(
        #     "[%d] Starting Batch AVSS. Id: %s, Dealer Id: %d",
        #     self.my_id,
        #     avss_id,
        #     dealer_id,
        # )

        start_time = time.time()

        rbctag = f"{dealer_id}-{avss_id}-B-RBC"
        acsstag = f"{dealer_id}-{avss_id}-B-AVSS"

        self.tagvars[acsstag] = {}
        self.tagvars[acsstag]['tasks'] = []

        broadcast_msg = None
        dispersal_msg_list = None
        if self.my_id == dealer_id:
            broadcast_msg, dispersal_msg_list = self._get_dealer_msg(values)

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)
        logger.debug("[%d] Starting reliable broadcast", self.my_id)

        async def predicate(_m):
            return True

        end_time = time.time()
        self.benchmark_logger.info(f"Time taken to generate dealer message: {end_time - start_time} seconds")
        
        start_time = time.time()
        output = asyncio.Queue()
        rbc_task = asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.receiver_ids,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_task.add_done_callback(print_exception_callback)
        
        if (not self.client_mode) or (self.client_mode and self.my_id != dealer_id):
            logger.debug(f"Node-[{self.my_id}]: waiting rbc, self.client_mode and self.my_id != dealer_id = {self.client_mode} ")
            rbc_msg = await output.get()
        end_time = time.time()
        self.benchmark_logger.info(f"Time taken to receive RBC message: {end_time - start_time} seconds")

        self.start_time = time.time()

        tag = f"{dealer_id}-{avss_id}-B-AVID"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)

        logger.debug("[%d] Starting AVID disperse", self.my_id)
        avid = AVID(self.n, self.t, dealer_id, recv, send, self.n, self.receiver_ids)
        if self.client_mode and self.my_id == dealer_id:
            await avid.disperse(tag, self.my_id, dispersal_msg_list, client_mode=True)
            self.shares_future.set_result(True)
            return
        
        self.avid_msg_queue.put_nowait((avid, tag, dispersal_msg_list))


        await self._process_avss_msg(avss_id, dealer_id, rbc_msg, avid)

        

        # for task in self.tagvars[acsstag]['tasks']:
        #     task.cancel()
        self.tagvars[acsstag] = {}
        del self.tagvars[acsstag]


class Hbacss1(Hbacss0):
    def _init_recovery_vars(self, tag):
        self.tagvars[tag]['finished_interpolating_commits'] = False
    #@profile
    async def _handle_share_recovery(self, tag, sender=None, avss_msg=[""]):
        if not self.tagvars[tag]['in_share_recovery']:
            return
        ls = len(self.tagvars[tag]['commitments']) // (self.t + 1)
        send, recv, multicast = self.tagvars[tag]['io']
        if not self.tagvars[tag]['finished_interpolating_commits']:
            all_commits = [ [] for l in range(ls)]
            for l in range(ls):
                known_commits = self.tagvars[tag]['commitments'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                known_commit_coords = [[i + 1, known_commits[i]] for i in range(self.t + 1)]
                # line 502
                interpolated_commits = [interpolate_g1_at_x(known_commit_coords, i + 1) for i in range(self.t + 1, self.n)]
                #interpolated_commits = known_commits + known_commits + known_commits
                all_commits[l] = known_commits + interpolated_commits
            self.tagvars[tag]['all_commits'] = all_commits
            self.tagvars[tag]['finished_interpolating_commits'] = True

            #init some variables we'll need later
            self.tagvars[tag]['r1_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['r2_coords_l'] = [ [] for l in range(ls)]
            self.tagvars[tag]['sent_r2'] = False
            self.tagvars[tag]['r1_set'] = set()
            self.tagvars[tag]['r2_set'] = set()
            
            if self.tagvars[tag]['all_shares_valid']:
                logger.debug("[%d] prev sent r1", self.my_id)
                all_evalproofs = [ [] for l in range(ls)]
                all_points = [ [] for l in range(ls)]
                for l in range(ls):
                    # the proofs for the specific shares held by this node
                    known_evalproofs = self.tagvars[tag]['witnesses'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_evalproof_coords = [[i + 1, known_evalproofs[i]] for i in range(self.t + 1)]
                    # line 504
                    interpolated_evalproofs = [interpolate_g1_at_x(known_evalproof_coords, i + 1) for i in
                                            range(self.t + 1, self.n)]
                    #interpolated_evalproofs = known_evalproofs + known_evalproofs + known_evalproofs
                    all_evalproofs[l] = known_evalproofs + interpolated_evalproofs
    
                    # another way of doing the bivariate polynomial. Essentially the same as how commits are interpolated
                    known_points = self.tagvars[tag]['shares'][l * (self.t + 1): (1 + l) * (self.t + 1)]
                    known_point_coords = [[i + 1, known_points[i]] for i in range(self.t + 1)]
                    mypoly = self.poly.interpolate(known_point_coords)
                    interpolated_points = [mypoly(i+1) for i in range(self.t + 1, self.n)]
                    all_points[l] = known_points + interpolated_points

                logger.debug("[%d] in between r1", self.my_id)
                # lines 505-506
                for j in range(self.n):
                    send(j, (HbAVSSMessageType.RECOVERY1, [ all_points[l][j] for l in range(ls)], [all_evalproofs[l][j] for l in range(ls)]))
                logger.debug("[%d] sent r1", self.my_id)

        if avss_msg[0] == HbAVSSMessageType.RECOVERY1 and not self.tagvars[tag]['sent_r2']:
            logger.debug("[%d] prev sent r2", self.my_id)
            _, points, proofs = avss_msg
            all_commits = self.tagvars[tag]['all_commits']
            if self.poly_commit.batch_verify_eval([all_commits[l][self.my_id] for l in range(ls)], sender + 1, points, proofs):
                if sender not in self.tagvars[tag]['r1_set']:
                    self.tagvars[tag]['r1_set'].add(sender)
                    for l in range(ls):
                        self.tagvars[tag]['r1_coords_l'][l].append([sender, points[l]])
                    #r1_coords.append([sender, point])
                if len(self.tagvars[tag]['r1_set']) == self.t + 1:
                    #r1_poly = self.poly.interpolate(r1_coords)
                    r1_poly_l = [ [] for l in range(ls)]
                    for l in range(ls):
                        r1_poly_l[l] = self.poly.interpolate(self.tagvars[tag]['r1_coords_l'][l])
                    for j in range(self.n):
                        r1_points_j = [r1_poly_l[l](j) for l in range(ls)]
                        #send(j, (HbAVSSMessageType.RECOVERY2, r1_poly(j)))
                        send(j, (HbAVSSMessageType.RECOVERY2, r1_points_j))
                    self.tagvars[tag]['sent_r2'] = True
                    logger.debug("[%d] sent r2", self.my_id)

        if avss_msg[0] == HbAVSSMessageType.RECOVERY2 and not self.tagvars[tag]['all_shares_valid']: # and self.tagvars[tag]['sent_r2']:
            _, points = avss_msg
            if sender not in self.tagvars[tag]['r2_set']:
                self.tagvars[tag]['r2_set'].add(sender)
                #r2_coords.append([sender, point])
                for l in range(ls):
                    self.tagvars[tag]['r2_coords_l'][l].append([sender, points[l]])
            if len(self.tagvars[tag]['r2_set']) == 2 * self.t + 1:
                # todo, replace with robust interpolate that takes at least 2t+1 values
                # this will still interpolate the correct degree t polynomial if all points are correct
                r2_poly_l = [ [] for l in range(ls)]
                shares = []
                for l in range(ls):
                    r2_poly = self.poly.interpolate(self.tagvars[tag]['r2_coords_l'][l])
                    shares += [r2_poly(i) for i in range(self.t + 1)]
                multicast((HbAVSSMessageType.OK, ""))
                self.tagvars[tag]['all_shares_valid'] = True
                self.tagvars[tag]['shares'] = shares

class BadDealer(Hbacss1):
    '''
        fix all parameters for test only
    '''
    def _get_dealer_msg(self, values):
        # Sample B random degree-(t) polynomials of form φ(·)
        # such that each φ_i(0) = si and φ_i(j) is Pj’s share of si
        # The same as B (batch_size)
        logger.debug("[%d] generating dealer message", self.my_id)
        '''
        while len(values) % (batch_size) != 0:
            values.append(0)
        '''
        fault_n = range(self.t)
        fault_k = range(len(values))

        secret_count = len(values)
        phi = [None] * secret_count
        commitments = [None] * secret_count

        
        # BatchPolyCommit
        #   Cs  <- BatchPolyCommit(SP,φ(·,k))
        # TODO: Whether we should keep track of that or not
        # r = ZR.random()
        for k in range(secret_count):
            phi[k] = self.poly.random(self.t, values[k])
            commitments[k] = self.poly_commit.commit(phi[k])

        ephemeral_secret_key = self.field.random()
        ephemeral_public_key = pow(self.g, ephemeral_secret_key)
        #dispersal_msg_list = bytearray()
        dispersal_msg_list = []
        logger.debug("[%d] generating dealer message", self.my_id)
        rids_plus_1 = [id+1 for id in self.receiver_ids]
        witnesses = self.poly_commit.double_batch_create_witness(phi, rids_plus_1, n=self.n)
        
        #phis_i = [phi[k](rids_plus_1[0] + 1) for k in range(secret_count)]
        #phis_hat_i = [phi_hat[k](rids_plus_1[0] + 1) for k in range(secret_count)]
        #print(self.poly_commit.batch_verify_eval(commitments, rids_plus_1[0], phis_i, phis_hat_i, witnesses[0]))
        
        logger.debug("[%d] generating dealer message", self.my_id)
        #for i in range(n):
        for i, receiver in enumerate(self.receiver_ids):
            shared_key = self.public_keys[receiver].pow(ephemeral_secret_key)
            #phis_i = [phi[k](receiver + 1).__getstate__() for k in range(secret_count)]
            logger.debug("[%d] finna eval on em", self.my_id)
            phis_i = [phi[k](receiver + 1) for k in range(secret_count)]
            #z = (phis_i, witnesses[i])

            if i in fault_n:
                for k in fault_k:
                    phis_i[k] = self.field.random()

            logger.debug("[%d] finna dump on em", self.my_id)
            z = dumps((phis_i, witnesses[i]))
            #print(z)
            logger.debug("[%d] finna encrypt on em", self.my_id)
            zz = SymmetricCrypto.encrypt(str(shared_key).encode(), z)
            #zz = SymmetricCrypto.encrypt(str(shared_key).encode(), phis_i[0])
            #dispersal_msg_list.extend(zz)
            dispersal_msg_list.append(zz)
        #commitments[0].append(ephemeral_public_key)
        logger.debug("[%d] generating dealer message", self.my_id)
        return dumps((commitments, ephemeral_public_key)), dispersal_msg_list