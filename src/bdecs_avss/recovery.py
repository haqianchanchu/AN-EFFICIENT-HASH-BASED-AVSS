"""Two-round recovery using the reference interpolation and NTL Gao decoder."""
from adkg.ntl import gao_interpolate
from pypairing import ZR
from .bdecs import MODULUS


class Recovery:
    def __init__(self, bdecs, coordinate, local):
        self.b = bdecs
        self.coordinate = coordinate
        self.local = local
        self.rec1 = {}
        self.rec2 = {}
        self.row = None
        self.support = ()
        self.decode_attempts = 0

    def add_rec1(self, sender, f, m, m0):
        if sender in self.rec1 or not self.b.local_point_verify(
                self.local, self.coordinate, sender + 1, m, f, m0):
            return False
        self.rec1[sender] = f
        if self.row is None and len(self.rec1) >= self.b.p.t + 1:
            self.row = tuple(
                self.b.poly.interpolate([
                    (sender + 1, ZR(values[a])) for sender, values in self.rec1.items()
                ])
                for a in range(self.b.p.l)
            )
        return True

    def add_rec2(self, sender, f):
        if not 0 <= sender < self.b.p.n or not self.b.vector(f, self.b.p.l):
            return None
        self.rec2.setdefault(sender, f)
        required_support = self.b.p.n - self.b.p.t
        if len(self.rec2) < required_support:
            return None
        self.decode_attempts += 1
        ids = sorted(self.rec2)
        coordinates = [sender + 1 for sender in ids]
        polys = []
        for a in range(self.b.p.l):
            coeffs, _ = gao_interpolate(coordinates,
                [self.rec2[j][a] for j in ids], self.b.p.t + 1, MODULUS,
                use_omega_powers=False)
            if coeffs is None or len(coeffs) > self.b.p.t + 1:
                return None
            polys.append(self.b.poly(list(coeffs)))
        # A common support set is mandatory: independent successful component
        # decodes alone do not justify accepting a vector.
        support = tuple(j for j in ids if all(int(p(ZR(j + 1))) == self.rec2[j][a]
                        for a, p in enumerate(polys)))
        if len(support) < required_support:
            return None
        self.support = support
        return tuple(polys)
