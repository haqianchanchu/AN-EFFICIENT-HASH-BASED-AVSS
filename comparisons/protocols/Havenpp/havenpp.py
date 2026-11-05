
from collections import defaultdict
import logging
import asyncio
from comparisons.protocols.Havenpp.betterpairing import G1, ZR
from comparisons.protocols.Havenpp.haven_polynomial import get_omega, Polynomial
from comparisons.protocols.Havenpp.poly_commit_log import PolyCommitLog
from comparisons.protocols.Havenpp.poly_commit_amt_unity import PolyCommitAMTUnity
from comparisons.protocols.Havenpp.haven_batch_proof import HavenPolyCommit, PolynomialCommitment
from comparisons.protocols.Havenpp.reliablebroadcast import get_merkle_branch, merkle_tree, merkle_verify
from GoSSamer.util.misc import wrap_send, subscribe_recv
import multiprocessing

def create_poly_commit(com, crs, n, omegas):
    if(com == PolynomialCommitment.BULLET_PROOFS):
        pc = PolyCommitLog(crs=crs, omegas=omegas, n=n)
    elif(com == PolynomialCommitment.AMT):
        pc = PolyCommitAMTUnity(crs, n, omegas)
    elif(com == PolynomialCommitment.KZG):
        pc = PolyCommitAMTUnity(crs, n, omegas)

    return HavenPolyCommit(pc, com)

def generate_random_bivariate_poly_fft(t, p, n, pc):
    omega_N = len(pc.omegas) 
    omega = pc.omegas[1]

    rows_polys = [Polynomial.random(p) for _ in range(t+1)]
    rows_evals = [poly.evaluate_fft(omega, omega_N)[:n] for poly in rows_polys]
    cols_polys = []
    cols_evals = []
    cols_commits = []

    for i in range(n):
        tmp_col_eval = [(int(pc.omegas[j]), rows_evals[j][i]) for j in range(t+1)]
        col_poly = Polynomial.interpolate(tmp_col_eval)
        cols_polys.append(col_poly.coeffs)
        cols_evals.append(col_poly.evaluate_fft(omega, omega_N)[:n])
        cols_commits.append(pc.commit(col_poly, ZR(0)))

    rows_polys = [poly.coeffs for poly in rows_polys]
    for i in range(t+1, n):
        row = [None for _ in range(n)]
        for j in range(n):
            row[j] = (int(pc.omegas[j]), cols_evals[j][i])
        rows_polys.append(Polynomial.interpolate(row).coeffs)

    return (cols_polys, cols_commits, cols_evals, rows_polys)
 
def helper_proof_generate(*args):
    polys = [Polynomial(p) for p in args[0]]

    def flip(matrix):
        flipped = [row for row in zip(*matrix)]
        res = []
        for row in flipped:
            new_row = []
            for i in range(len(row)):
                new_row.append((i+1, row[i]))
            res.append(new_row)
        return res
    pc = args[2]
    return pc.double_batch_create_witness_advanced(polys, evals=flip(args[1]))

def helper_bivariate_poly_generate(*args):
    t, p, n, pc = args
    return generate_random_bivariate_poly_fft(t, p, n, pc)

def helper_verify_proof(*arg):
    s_hat = arg[0]
    phis_at_i = arg[1]
    index = arg[2]
    col_witnesses = arg[3]
    pc = arg[4]
    return pc.verify_batch_witness_advanced(s_hat, index, phis_at_i, col_witnesses)


class our_avss:
    def __init__(self, n, t, p, num_secrets, my_id, send, recv, poly_commit, benchmark_by_part=False):

        self.n, self.t, self.p, self.num_secrets, self.my_id = n, t, p, num_secrets, my_id
        self.num_bivariate_poly = (num_secrets // (t+1)) + (num_secrets % (t+1) > 0) # support sharing number of secrets not divisible by t
        self.field = ZR
        self.pc = poly_commit 
        self.benchmark_by_part = benchmark_by_part

        if benchmark_by_part:
            return
        
         # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send
        self.tasks = []
        self.output_queue = asyncio.Queue()
        self.tagvars = {}
    
    async def avss(self, avss_id, value=None, dealer_id=None):
        # If `values` is passed then the node is a 'Sender'
        # `dealer_id` must be equal to `self.my_id`
        if value is not None:
            if dealer_id is None:
                dealer_id = self.my_id
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
    
        assert type(avss_id) is int

        cols_commits_all, party_columns_evals, party_rows, witnesses = [None] * 4

        if self.my_id == dealer_id:
            # s_hat, ys, witnesses, col_polys = self._get_dealer_msg(value)
            cols_commits_all, party_columns_evals, party_rows, witnesses = self._get_dealer_msg()
        tag = f"{dealer_id}-{avss_id}-B-RBC"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        
        msg = await self.avss_protocol(
           tag,
           self.my_id,
           self.n,
           self.t,
           dealer_id,
           (cols_commits_all, party_columns_evals, party_rows, witnesses),
           recv,
           send,
        )
        await self._process_avss_msg(avss_id, msg)


    def _get_dealer_msg(self):
        with multiprocessing.Pool() as pool:
            args = [(self.t, self.p, self.n, self.pc) for _ in range(self.num_bivariate_poly)]
            bivariates = pool.starmap(helper_bivariate_poly_generate, args)

            # what each party will get
            party_columns = [[] for _ in range(self.n)]
            party_columns_evals = [[] for _ in range(self.n)]
            party_rows = [[] for _ in range(self.n)]

            #the commits are ordered the same way as the column polynomial for easy verification later
            cols_commits_all = [[] for _ in range(self.n)]

            for bivariate in bivariates:
                cols_polys, cols_commits, cols_evals, rows_polys = bivariate
                for i in range(self.n):
                    party_columns[i].append(cols_polys[i])
                    party_columns_evals[i].append(cols_evals[i])
                    party_rows[i].append(rows_polys[i])
                    cols_commits_all[i].append(cols_commits[i])

            args = [(party_columns[i], party_columns_evals[i], self.pc) for i in range(self.n)]
            witnesses = pool.starmap(helper_proof_generate, args)
        return cols_commits_all, party_columns_evals, party_rows, witnesses
               


    
    async def _process_avss_msg(self, avss_id, out):
        self.output_queue.put_nowait((self.my_id, avss_id, out))

    async def avss_protocol(self, sid, pid, n, f, leader, input_args, receive, send):  # (# noqa: E501)
        k = n - 2 * f  # Wait to reconstruct. (# noqa: E221)
        echo_threshold = n - f  # Wait for ECHO to send READY. (# noqa: E221)
        ready_threshold = n - 2 * f  # Wait for READY to amplify. (# noqa: E221)
        output_threshold = n - f  # Wait for this many READY to output

        if pid == leader:
            cols_commits_all, party_columns_evals, party_rows, col_witnesses = input_args

            for i in range(n):
                row_witnesses = [col_witnesses[j][i] for j in range(n)] # witnesses for the row points are consistent with columns
                send(i, (sid, "SEND", (cols_commits_all, party_rows[i], row_witnesses, party_columns_evals[i], col_witnesses[i])))

        from_leader = None
        # stores the column evaluation of this party on each bivariate polynomial for every root commitment
        col_evals = defaultdict(lambda: [None for _ in range(n)])
        # stores the row evaluations of this party on each bivaraite polynomial for every root commitment
        row_evals = defaultdict(lambda: [None for _ in range(n)])
        # stores the polynomial commitment to each column of each bivariate polynomial for every root commitment
        poly_commits_received = defaultdict(lambda: [None for _ in range(n)])
        # stores the number of valid echoes received for each root commitment 
        echo_counter = defaultdict(lambda: 0)
        echo_senders = set()  # Peers that have sent us ECHO messages
        ready = defaultdict(set)
        ready_sent = False
        ready_senders = set()  # Peers that have sent us READY messages
        dealer_cols = defaultdict(lambda: None) # holds the vertical polynomial of party i received from the dealer
        dealer_rows_evals = defaultdict(lambda: None) # holds the row polynomials evaluation of party i received from the dealer

        while True:  # main receive loop
            sender, msg = await receive()
            if msg[1] == "SEND" and from_leader is None:
                (s_hat, party_rows, row_witnesses, cols_eval, col_witnesses) = msg[2]
                # if sender != leader:
                #     print(f"[{pid}] SEND message from other than leader: {sender}")
                #     continue

                status, party_rows = self.verify_dealer_message(s_hat, party_rows, row_witnesses, col_witnesses, cols_eval, pid)
                if status == False:
                    print(f"[{pid}]Failed to validate SEND message")
                    continue

                # vector commit to all vertical polynomial commitments in a merkle tree
                mt = merkle_tree([str(s_hat[j]) for j in range(0, n)])
                roothash = mt[1]
                dealer_rows_evals[roothash] = party_rows
                dealer_cols[roothash] = (cols_eval, col_witnesses, get_merkle_branch(pid, mt), s_hat[pid])

                for j in range(self.n):
                    y = [party_rows[i][j] for i in range(self.num_bivariate_poly)] 
                    send(j, (sid, "ECHO", roothash, get_merkle_branch(j, mt), s_hat[j], y, row_witnesses[j]))

            elif msg[1] == "ECHO":
                (_, _, roothash, branch, s_hat_j, party_rows_j, witnesses) = msg
                # Validation
                if (
                    roothash in col_evals
                    and col_evals[roothash][sender] is not None
                    or sender in echo_senders
                ):
                    print("f[{pid}] Redundant ECHO")
                    continue

                if(not self.verify_echo_message(sender, roothash, branch, s_hat_j, party_rows_j, witnesses, pid, dealer_cols)):
                    print(f"[{pid}]Failed to validate ECHO message")
                    continue

                # Update
                col_evals[roothash][sender] = party_rows_j
                echo_senders.add(sender)
                echo_counter[roothash] += 1
                poly_commits_received[roothash][sender] = (branch, s_hat_j)

                def send_ready_with_columns(roothash):
                    column_eval, s_hat, proof, witnesses = [None] * 4
                    if not (roothash in dealer_cols) or dealer_cols[roothash][0] is None:
                        # if no verticals are received from the dealer then interpolate the verticals from other parties
                        column_eval = [None for _ in range(self.num_bivariate_poly)] # num batches x n
                        poly_to_commit = []
                        for j in range(self.num_bivariate_poly):
                            to_interpolate = [(int(self.pc.omegas[i]), col_evals[roothash][i][j]) for i in echo_senders if col_evals[roothash][i] is not None]
                            polynomial = Polynomial.interpolate(to_interpolate)
                            poly_to_commit.append(polynomial)
                            column_eval[j]= [polynomial(self.pc.omegas[i]) for i in range(self.n)]
                        witnesses = self.pc.double_batch_create_witness_advanced(poly_to_commit) # size n
                        s_hat, proof = poly_commits_received[roothash][sender][1], poly_commits_received[roothash][sender][0]
                    else:
                        # Use the fact that this party received the right columns from the dealer
                        column_eval = dealer_cols[roothash][0]
                        s_hat, proof, witnesses = dealer_cols[roothash][3], dealer_cols[roothash][2], dealer_cols[roothash][1]

                    for j in range(self.n):
                        col_evals_to_send = [column_eval[i][j] for i in range(self.num_bivariate_poly)]

                        send(j, (sid, "READY", roothash, proof, s_hat, col_evals_to_send, witnesses[j]))

                # send a ready if heard n-f echoes and haven't send a ready yet
                if echo_counter[roothash] >= echo_threshold and not ready_sent:
                    send_ready_with_columns(roothash)
                    ready_sent = True

                # send a ready if the amplfication of ready is met but just now you have reached the minimum number of echoes rquired to send a ready
                elif echo_counter[roothash] >= k and not ready_sent and len(ready[roothash]) >= ready_threshold:
                    send_ready_with_columns(roothash)
                    ready_sent = True


            elif msg[1] == "READY":
                (_, _, roothash, proof, s_hat_j, row_eval, w) = msg
                # Validation
                if sender in ready[roothash] or sender in ready_senders:
                    print("[{pid}] Redundant READY")
                    continue
                try:
                    # only do the assertion if you don't have your row from the dealer!
                    if not (roothash in dealer_rows_evals and dealer_rows_evals[roothash] is not None):
                        assert self.pc.verify_batch_witness_advanced(s_hat_j, self.my_id, row_eval, w)
                except AssertionError as e:
                    print(f"Failed to validate READY message: {e}")
                    continue
                # Update
                ready[roothash].add(sender)
                ready_senders.add(sender)
                row_evals[roothash][sender] = row_eval

                # Amplify ready messages
                if len(ready[roothash]) >= ready_threshold and not ready_sent:
                    # send a ready if enough echos are here
                    if echo_counter[roothash] >= k:
                        send_ready_with_columns(roothash)
                        ready_sent = True


                if len(ready[roothash]) >= output_threshold and echo_counter[roothash] >= k:
                    return (col_evals[roothash], row_evals[roothash], dealer_rows_evals[roothash], dealer_cols[roothash])
    
                
    def __enter__(self):
        return self
            
    def __exit__(self, typ, value, traceback):
        self.subscribe_recv_task.cancel()
        for task in self.tasks:
            task.cancel()

    def verify_dealer_message(self, s_hat, rows_polys, witnesses, col_witnesses, cols_evals, pid, multi_core=True):
        if not all([len(row) == self.p + 1 for row in rows_polys]):
            return False
        

        rows_evals = [Polynomial(row_poly).evaluate_fft(self.pc.omegas[1], len(self.pc.omegas))[:self.n] for row_poly in rows_polys]

        # if multi_core:
        #     args_2 = [(s_hat[i], [rows_evals[j][i] for j in range(len(rows_evals))], pid, witnesses[i], self.pc) for i in range(self.n)]
        #     args_1 = [(s_hat[pid], [cols_evals[j][i] for j in range(len(cols_evals))], i, col_witnesses[i], self.pc) for i in range(self.n)]

        #     with multiprocessing.Pool() as pool:
        #         res = pool.starmap(helper_verify_proof, args_2)
        # else:
        #     res1 = [self.pc.verify_batch_witness_advanced(s_hat[i],  pid, [rows_evals[j][i] for j in range(len(rows_evals))], witnesses[i]) for i in range(self.n)]
        #     res2 = [self.pc.verify_batch_witness_advanced(s_hat[pid],  i, [cols_evals[j][i] for j in range(len(cols_evals))], col_witnesses[i]) for i in range(self.n)]
        #     res = (all(res1), all(res2))

        res1 = [self.pc.verify_batch_witness_advanced(s_hat[i],  pid, [rows_evals[j][i] for j in range(len(rows_evals))], witnesses[i]) for i in range(self.n)]
        res2 = [self.pc.verify_batch_witness_advanced(s_hat[pid],  i, [cols_evals[j][i] for j in range(len(cols_evals))], col_witnesses[i]) for i in range(self.n)]
        res = (all(res1), all(res2))


        return all(res), rows_evals


    def verify_echo_message(self, sender, roothash, branch, s_hat_j, party_rows_j, witnesses, pid, dealer_cols):

        # if verticals already exist from the dealer, then no need to check the echos coming from other parties
        if(roothash in dealer_cols and dealer_cols[roothash] is not None):
            return True


        # verify that the polynomial commitments are part of the vector commitments at the right places 
        if(not merkle_verify(self.n, str(s_hat_j), roothash, branch, pid)):
            return False

        # verify that the points are claimed to be on your vertical polynomial of degree t are actually part of it
        # index = self.omegas[sender]

        # check that each point is part of a vertical polynomial commitment of degree t.
        return self.pc.verify_batch_witness_advanced(s_hat_j, sender, party_rows_j, witnesses)


