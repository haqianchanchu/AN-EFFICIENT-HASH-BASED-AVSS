"""Single-axis BDECS from main.tex. Coordinates are 1..n, IDs are 0..n-1.

Wire objects contain integers/bytes/tuples, never backend polynomial objects.
All arithmetic, polynomial evaluation and hashing use the reference modules.
"""
import math
from dataclasses import dataclass

from pypairing import ZR
from GoSSamer.crypto.elliptic_curve import Subgroup
from GoSSamer.crypto.polynomial import polynomials_over
from GoSSamer.crypto.polynomial_bi import polynomials_over_bi
from GoSSamer.distribute.encode import hash as digest


MODULUS = int(Subgroup.BLS12_381)


def canonical(value):
    """Injective tagged encoding; fixed 32-byte unsigned field-sized integers."""
    if type(value) is int:
        if not 0 <= value < 2 ** 256:
            raise ValueError("integer outside canonical range")
        return b'i' + value.to_bytes(32, 'big')
    if isinstance(value, bytes):
        return b'b' + len(value).to_bytes(8, 'big') + value
    if isinstance(value, str):
        return b's' + canonical(value.encode('utf8'))
    if isinstance(value, (tuple, list)):
        return b'a' + len(value).to_bytes(8, 'big') + b''.join(map(canonical, value))
    raise ValueError("unsupported canonical type")


@dataclass(frozen=True)
class Parameters:
    n: int
    t: int
    l: int
    kappa: int = 128
    q_h: int = 2 ** 32
    q_fs: int = 2 ** 32
    fixed_r: int = 0

    def __post_init__(self):
        if self.t < 1 or self.n < 3 * self.t + 1 or not 0 < self.l < MODULUS - 1:
            raise ValueError("invalid n,t,l")
        if min(self.kappa, self.q_h, self.q_fs, self.fixed_r) < 0:
            raise ValueError("negative security parameter")

    @property
    def required_r(self):
        return math.ceil((self.kappa + 1 + math.log2(
            (self.q_fs + 1) * math.comb(self.n, self.t + 1) * self.n ** 2
        )) / math.log2(MODULUS / (self.l + 1)))

    @property
    def r(self):
        return self.fixed_r or self.required_r

    @property
    def required_lambda(self):
        q = self.q_h + self.n ** 2 + 1
        numerator = q * (q - 1) // 2 + (self.q_fs + 1) * self.n ** 2 * q
        return self.kappa + 1 + (numerator - 1).bit_length()

    @property
    def security_compatible(self):
        return self.r >= self.required_r and self.required_lambda <= 256


class BDECS:
    def __init__(self, parameters, sid, dealer):
        self.p = parameters
        if not 0 <= dealer < parameters.n:
            raise ValueError("dealer outside committee")
        self.poly = polynomials_over(ZR)
        self.bi = polynomials_over_bi(ZR)
        # Stable wire domain from the first M0 implementation.
        self.context = canonical(('BDECS-v2-polynomial-salt', sid, dealer, parameters.n,
                                  parameters.t, parameters.l, parameters.r, MODULUS))

    def vector(self, values, length):
        return (isinstance(values, (tuple, list)) and len(values) == length
                and all(type(v) is int and 0 <= v < MODULUS for v in values))

    def uni_valid(self, c):
        return self.vector(c, self.p.t + 1)

    def bi_valid(self, c):
        return (isinstance(c, (tuple, list)) and len(c) == self.p.t + 1
                and all(self.uni_valid(row) for row in c))

    def uni_wire(self, p):
        return tuple(int(p.coeffs[i]) if i < len(p.coeffs) else 0
                     for i in range(self.p.t + 1))

    def bi_wire(self, p):
        return tuple(tuple(int(p.coeffs[i][j])
                           if i < len(p.coeffs) and j < len(p.coeffs[i]) else 0
                           for j in range(self.p.t + 1)) for i in range(self.p.t + 1))

    def coord(self, x):
        return type(x) is int and 1 <= x <= self.p.n

    def _hash_point(self, f, m, m0):
        return digest(b'BDECS/POINT' + self.context + canonical((f, m, m0)))

    def _combine(self, gamma, mask, secrets):
        """R = gamma^(l+1) M + sum(gamma^(k+1) F_k), for coefficients or points."""
        g = ZR(gamma)
        return g ** (self.p.l + 1) * ZR(mask) + sum(
            (g ** (k + 1) * ZR(value) for k, value in enumerate(secrets)), ZR(0))

    def challenges(self, h):
        # Rejection sampling preserves uniform hash-to-field semantics. The
        # reference SHA-256 function itself is reused, not replaced.
        prefix = b'BDECS/FS' + self.context + canonical(h)
        limit = (2 ** 256 // MODULUS) * MODULUS
        result = []
        for a in range(self.p.r):
            counter = 0
            while True:
                x = int.from_bytes(digest(prefix + canonical((a, counter))), 'big')
                if x < limit:
                    result.append(x % MODULUS)
                    break
                counter += 1
        return tuple(result)

    def valid_commitment(self, com):
        try:
            h, rs = com
            return (len(h) == self.p.n and all(len(row) == self.p.n and all(
                isinstance(x, bytes) and len(x) == 32 for x in row) for row in h)
                and len(rs) == self.p.r and all(self.bi_valid(c) for c in rs))
        except (ValueError, TypeError):
            return False

    def commit(self, fs):
        if len(fs) != self.p.l or not all(self.bi_valid(f) for f in fs):
            raise ValueError("invalid secret polynomials")
        fpolys = [self.bi([list(row) for row in f]) for f in fs]
        mpolys = [self.bi.random_bi(self.p.t, self.p.t) for _ in range(self.p.r)]
        # M0 is an additional independent (t,t) mask, excluded from R.
        m0 = self.bi.random_bi(self.p.t, self.p.t)
        # Reuse each fixed-x section across the row, as in GoSSamer.
        rows = []
        for i in range(1, self.p.n + 1):
            frow = [f.get_poly_y(i) for f in fpolys]
            mrow = [m.get_poly_y(i) for m in mpolys]
            m0row = m0.get_poly_y(i)
            rows.append(tuple(self._hash_point(tuple(int(f(j)) for f in frow),
                                               tuple(int(m(j)) for m in mrow), int(m0row(j)))
                              for j in range(1, self.p.n + 1)))
        h = tuple(rows)
        ms = tuple(self.bi_wire(m) for m in mpolys)
        rs = tuple(
            tuple(tuple(int(self._combine(g, m[i][j], (f[i][j] for f in fs)))
                        for j in range(self.p.t + 1)) for i in range(self.p.t + 1))
            for g, m in zip(self.challenges(h), ms)
        )
        return (h, rs), (ms, tuple(fs), self.bi_wire(m0))

    def poly_open(self, coordinate, key):
        if not self.coord(coordinate):
            raise ValueError("invalid opening coordinate")
        ms, fs, m0 = key
        sections = tuple(tuple(self.uni_wire(self.bi([list(r) for r in c]).get_poly_x(coordinate))
                               for c in group) for group in (ms, fs))
        return sections + (self.uni_wire(self.bi([list(r) for r in m0]).get_poly_x(coordinate)),)

    def point_from_opening(self, opening, x):
        if not self.coord(x):
            raise ValueError("invalid point coordinate")
        ms, fs, m0 = opening
        values = tuple(tuple(int(self.poly(list(c))(ZR(x))) for c in group) for group in (ms, fs))
        return values + (int(self.poly(list(m0))(ZR(x))),)

    def poly_verify(self, com, coordinate, opening):
        try:
            if not self.coord(coordinate) or not self.valid_commitment(com):
                return False
            ms, fs, m0 = opening
            if len(ms) != self.p.r or len(fs) != self.p.l or not all(
                    self.uni_valid(c) for c in tuple(ms) + tuple(fs)) or not self.uni_valid(m0):
                return False
            h, rs = com
            for x in range(1, self.p.n + 1):
                m, f, m0_value = self.point_from_opening(opening, x)
                if self._hash_point(f, m, m0_value) != h[x - 1][coordinate - 1]:
                    return False
            for g, r, m in zip(self.challenges(h), rs, ms):
                lhs = self.uni_wire(self.bi([list(row) for row in r]).get_poly_x(coordinate))
                rhs = tuple(int(self._combine(g, m[j], (f[j] for f in fs)))
                    for j in range(self.p.t + 1))
                if lhs != rhs:
                    return False
            return True
        except (ValueError, TypeError, IndexError, AttributeError):
            return False

    def extract_local_commitment(self, com, i):
        if not self.valid_commitment(com) or not self.coord(i):
            raise ValueError("invalid commitment/coordinate")
        h, rs = com
        polys = [self.bi([list(row) for row in r]) for r in rs]
        return (i, tuple(row[i - 1] for row in h), tuple(h[i - 1]),
                tuple(self.uni_wire(r.get_poly_x(i)) for r in polys),
                tuple(self.uni_wire(r.get_poly_y(i)) for r in polys), self.challenges(h))

    def local_valid(self, local, coordinate):
        try:
            i, col, row, rx, ry, gs = local
            return (self.coord(i) and i == coordinate and len(col) == len(row) == self.p.n
                    and all(isinstance(h, bytes) and len(h) == 32 for h in tuple(col) + tuple(row))
                    and len(rx) == len(ry) == self.p.r and self.vector(gs, self.p.r)
                    and all(self.uni_valid(c) for c in tuple(rx) + tuple(ry)))
        except (ValueError, TypeError):
            return False

    def local_point_verify(self, local, x, y, m, f, m0):
        try:
            i = local[0]
            if not (self.local_valid(local, i) and self.coord(x) and self.coord(y)
                    and self.vector(m, self.p.r) and self.vector(f, self.p.l)
                    and self.vector((m0,), 1)):
                return False
            _, col, row, rx, ry, gs = local
            if y == i:
                h, sections, at = col[x - 1], rx, x
            elif x == i:
                h, sections, at = row[y - 1], ry, y
            else:
                return False
            if h != self._hash_point(f, m, m0):
                return False
            return all(self.poly(list(c))(ZR(at)) == self._combine(g, mm, f)
                       for c, g, mm in zip(sections, gs, m))
        except (ValueError, TypeError, IndexError):
            return False

    def point_verify(self, com, x, y, m, f, m0):
        try:
            return self.local_point_verify(self.extract_local_commitment(com, y), x, y, m, f, m0)
        except (ValueError, TypeError, IndexError):
            return False

    def commitment_id(self, com):
        if not self.valid_commitment(com):
            raise ValueError("invalid commitment")
        return digest(b'VSSCOM' + self.context + canonical(com))

    def pack(self, values):
        if not self.vector(values, self.p.l * (self.p.t + 1)):
            raise ValueError("secret count must equal l(t+1)")
        result = []
        for a in range(self.p.l):
            line = self.poly.interpolate([(v + 1, ZR(values[a * (self.p.t + 1) + v]))
                                          for v in range(self.p.t + 1)])
            # Explicitly pad the boundary polynomial: reference random_bi only
            # overwrites supplied coefficients, leaving omitted zero tails random.
            p = self.bi.random_bi(self.p.t, self.p.t)
            for i, c in enumerate(self.uni_wire(line)):
                p.coeffs[i][0] = ZR(c)
            result.append(self.bi_wire(p))
        return tuple(result)
