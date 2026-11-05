import unittest
from copy import deepcopy
from pypairing import ZR

from bdecs_avss.bdecs import BDECS, Parameters, MODULUS
from bdecs_avss.recovery import Recovery


class CommitmentTests(unittest.TestCase):
    def setUp(self):
        self.b = BDECS(Parameters(4, 1, 2), 'test', 0)
        self.com, self.key = self.b.commit(self.b.pack((0, 0, 3, 4)))

    def test_openings_points_and_local(self):
        for i in range(1, 5):
            opening = self.b.poly_open(i, self.key)
            self.assertTrue(self.b.poly_verify(self.com, i, opening))
            for j in range(1, 5):
                m, f, m0 = self.b.point_from_opening(opening, j)
                self.assertTrue(self.b.point_verify(self.com, j, i, m, f, m0))
                for owner in {i, j}:
                    local = self.b.extract_local_commitment(self.com, owner)
                    self.assertTrue(self.b.local_point_verify(local, j, i, m, f, m0))
                bad = ((f[0] + 1) % MODULUS,) + f[1:]
                self.assertFalse(self.b.point_verify(self.com, j, i, m, bad, m0))
                badm = ((m[0] + 1) % MODULUS,) + m[1:]
                self.assertFalse(self.b.point_verify(self.com, j, i, badm, f, m0))
                self.assertFalse(self.b.point_verify(self.com, j, i, m, f, (m0 + 1) % MODULUS))
                for invalid in (None, b'bad', -1, MODULUS, True):
                    self.assertFalse(self.b.point_verify(self.com, j, i, m, f, invalid))

    def test_binding_and_format(self):
        opening = self.b.poly_open(1, self.key)
        self.assertFalse(self.b.poly_verify(self.com, 0, opening))
        self.assertFalse(self.b.poly_verify(self.com, 1, (opening[0], ())))
        bad = (opening[0], (opening[1][0] + (1,), opening[1][1]), opening[2])
        self.assertFalse(self.b.poly_verify(self.com, 1, bad))
        for m0 in ((), opening[2] + (1,), (MODULUS, 0),
                     ((opening[2][0] + 1) % MODULUS,) + opening[2][1:]):
            self.assertFalse(self.b.poly_verify(self.com, 1, opening[:2] + (m0,)))
        h, r = self.com
        badh = ((b'x' * 32,) + h[0][1:],) + h[1:]
        self.assertFalse(self.b.poly_verify((badh, r), 1, opening))
        rows = [list(row) for row in r[0]]
        rows[0][0] = (rows[0][0] + 1) % MODULUS
        self.assertFalse(self.b.poly_verify((h, (tuple(map(tuple, rows)),) + r[1:]), 1, opening))
        other = BDECS(self.b.p, 'other-session', 0)
        self.assertFalse(other.poly_verify(self.com, 1, opening))
        self.assertFalse(self.b.vector((MODULUS,), 1))

    def test_packing_and_two_round_recovery(self):
        rows = []
        for receiver in range(4):
            recovery = Recovery(self.b, receiver + 1,
                                self.b.extract_local_commitment(self.com, receiver + 1))
            for sender in (0, 2):
                opening = self.b.poly_open(sender + 1, self.key)
                m, f, m0 = self.b.point_from_opening(opening, receiver + 1)
                self.assertFalse(recovery.add_rec1(sender, f, m, (m0 + 1) % MODULUS))
                self.assertTrue(recovery.add_rec1(sender, f, m, m0))
                self.assertFalse(recovery.add_rec1(sender, f, m, m0))
            rows.append(recovery.row)
        target = Recovery(self.b, 2, self.b.extract_local_commitment(self.com, 2))
        target.add_rec2(0, (123, 456))
        result = None
        for sender in (1, 2, 3):
            result = target.add_rec2(sender, tuple(int(p(2)) for p in rows[sender]))
        self.assertIsNotNone(result)
        self.assertEqual(target.support, (1, 2, 3))
        expected = self.b.poly_open(2, self.key)[1]
        self.assertEqual(tuple(self.b.uni_wire(p) for p in result), expected)
        # Zero boundary coefficients must stay zero after random extension.
        for a, values in enumerate(((0, 0), (3, 4))):
            f = self.b.bi([list(r) for r in self.key[1][a]])
            self.assertEqual(tuple(int(f(x, 0)) for x in (1, 2)), values)

    def test_security_parameters(self):
        self.assertTrue(self.b.p.security_compatible)
        self.assertFalse(Parameters(4, 1, 2, q_h=2 ** 200).security_compatible)

    def test_commit_grid_matches_direct_bivariate_evaluation(self):
        for l, r in ((1, 1), (4, 2)):
            with self.subTest(l=l, r=r):
                b = BDECS(Parameters(7, 2, l, fixed_r=r), 'grid-test', 0)
                # Asymmetric coefficients expose accidental coordinate swaps.
                fs = tuple(tuple(tuple(1 + 100*k + 10*i + j for j in range(3))
                                 for i in range(3)) for k in range(l))
                com, key = b.commit(fs)
                masks = [b.bi([list(row) for row in c]) for c in key[0]]
                secrets = [b.bi([list(row) for row in c]) for c in fs]
                m0 = b.bi([list(row) for row in key[2]])
                expected = tuple(tuple(b._hash_point(
                    tuple(int(f(ZR(i), ZR(j))) for f in secrets),
                    tuple(int(m(ZR(i), ZR(j))) for m in masks), int(m0(ZR(i), ZR(j))))
                    for j in range(1, 8)) for i in range(1, 8))
                self.assertEqual(com[0], expected)
                for i in range(1, 8):
                    self.assertTrue(b.poly_verify(com, i, b.poly_open(i, key)))
                    self.assertEqual(b.poly_open(i, key)[2], b.uni_wire(m0.get_poly_x(i)))
                # R retains exactly the original F/M combination, with no M0 term.
                for g, rr, mm in zip(b.challenges(com[0]), com[1], key[0]):
                    for i in range(3):
                        for j in range(3):
                            self.assertEqual(rr[i][j], (pow(g, l + 1, MODULUS) * mm[i][j]
                                + sum(pow(g, k + 1, MODULUS) * f[i][j]
                                      for k, f in enumerate(fs))) % MODULUS)


if __name__ == '__main__':
    unittest.main()
