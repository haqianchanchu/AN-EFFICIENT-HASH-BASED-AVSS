from comparisons.protocols.Havenpp.proofs import MerkleTree
from comparisons.protocols.Havenpp.betterpairing import ZR, bls12_381_r
from comparisons.protocols.Havenpp.haven_polynomial import Polynomial
from math import log, ceil
import pickle

class PolynomialCommitment:
    BULLET_PROOFS = 1
    AMT = 2
    KZG = 3


def get_all_roots_of_unity(n):
    #get smallest power of two greater than or equal to N
    N = 2 ** ceil(log(n,2))
    omega = ZR.root_of_unity()
    omega = omega**(bls12_381_r//N)

    omegas = [ZR(1), omega]
    for i in range(2,N):
        omegas.append(omegas[i-1]*omega)
    return omegas


class HavenPolyCommit:
    def __init__(self, poly_commit, polycom_type):
        self.pc = poly_commit
        self.field = poly_commit.field
        self.polycom_type = polycom_type
        self.omegas = poly_commit.omegas

    def double_batch_create_witness_advanced(self, phis, rs=None, n=None, evals=None):
        omegas = self.omegas
        t = len(phis[0].coeffs) - 1
        if (n is None):
            n = 3*t+1

        if evals is None:
            evals = []
            for z in range(0, n):
                evals.append([(j+1, phis[j](omegas[z])) for j in range(0, len(phis))])


        tree = MerkleTree()
        for j in range(n):
            tree.append(pickle.dumps(evals[j]))
        roothash = tree.get_root_hash()

        witnesses = [[] for i in range(n)]
        for j in range(n):
            branch = tree.get_branch(j)
            witnesses[j].append(roothash)
            witnesses[j].append(branch)
        challenge = self.field.hash(pickle.dumps([roothash, self.pc.crs]))
        # print("challenge is", challenge)

        poly_challenge = []
        for z in range(1, t + 2):
            poly_challenge.append((int(omegas[z-1]), Polynomial.interpolate_at(evals[z-1], challenge)))

        poly_challenge = Polynomial.interpolate(poly_challenge)
        if (rs is not None):
            r = Polynomial.interpolate_at(rs, challenge)
        else:
            r = self.field(0)

        witnesses_2 = self.pc.batch_create_witness(poly_challenge, r, n)

        # print("challenge commit looks like: ", self.pc.commit(poly_challenge, r))


        for i in range(n):
            witnesses[i].append(witnesses_2[i])
        return witnesses

    def verify_batch_witness_advanced(self, cs, i, phis_at_i, witness):
        if(self.polycom_type == PolynomialCommitment.BULLET_PROOFS):
            i = int(self.pc.omegas[i])
        evals = [(j+1, phis_at_i[j]) for j in range (0, len(phis_at_i))]
        cs = [(j+1, cs[j]) for j in range(0, len(cs))]

        roothash, branch, witness_real = witness
        if not MerkleTree.verify_membership(pickle.dumps(evals), branch, roothash):
            return False
        challenge = self.field.hash(pickle.dumps([roothash, self.pc.crs]))
        # print("verifiation challenge looks like", challenge)

        c = Polynomial.interpolate_exp_at(cs, challenge)
        # print("verification challenge commit looks like: ", c)
        interpolated = Polynomial.interpolate_at(evals, challenge)
        return self.pc.verify_eval(c, i, interpolated, witness_real)

    def commit(self, poly, r):
        return self.pc.commit(poly, r)





if __name__ == "__main__":
    # field = GF(Subgroup.BLS12_381)
    from honeybadgermpc.betterpairing import ZR
    import honeybadgermpc.poly_commit_log as pc_bullet
    import honeybadgermpc.poly_commit_amt_unity as pc_AMT
    t = 22
    n = 3*t+1

    field = ZR
    poly1 = Polynomial.random(t)
    poly2 = Polynomial.random(t)
    phis = [poly1, poly2]
    omegas = get_all_roots_of_unity(n)

    r1 = field.random()
    r2 = field.random()
    rs = [(1, r1), (2, r2)]



    #####
    ## Bullet proofs
    poly_commit_bullet = pc_bullet.PolyCommitLog(degree_max=n, omegas=omegas)

    
    pc  = HavenPolyCommit(poly_commit_bullet, PolynomialCommitment.BULLET_PROOFS)
    c1 = pc.commit(poly1, r1)
    c2 = pc.commit(poly2, r2)
    cs = [c1, c2]



    print("testing double batch create witness with Bullet Proofs")
    witnesses = pc.double_batch_create_witness_advanced(phis, rs=rs)
    for i in range(0, len(witnesses)):
        phis_at_i = []
        for j in range(len(phis)):
            phis_at_i.append(phis[j](pc.omegas[i]))
        assert(pc.verify_batch_witness_advanced(cs, i, phis_at_i, witnesses[i]))
    print("passed bullet proofs batch verification")

    ####
    # AMT 
    crs = pc_AMT.gen_crs(len(omegas))
    poly_commit_AMT = pc_AMT.PolyCommitAMTUnity(crs, n, omegas)
    pc  = HavenPolyCommit(poly_commit_AMT, PolynomialCommitment.AMT)

    c1 = pc.commit(poly1, r1)
    c2 = pc.commit(poly2, r2)
    cs = [c1, c2]

    print("testing double batch create witness with AMT")
    witnesses = pc.double_batch_create_witness_advanced(phis, rs=rs)
    for i in range(0, len(witnesses)):
        phis_at_i = []
        for j in range(len(phis)):
            phis_at_i.append(phis[j](pc.omegas[i]))
        assert(pc.verify_batch_witness_advanced(cs, i, phis_at_i, witnesses[i]))
    print("passed AMT batch verification")

