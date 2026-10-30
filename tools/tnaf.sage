"""
Reference implementation of exception-free tau-adic scalar multiplication on E_b : y^2 = x^3 + b over
F_p, p = 1 (mod 3), with tau = 1 - omega and complete formulas in homogeneous projective coordinates
(X : Y : Z): width-3 tau-NAF in G1 of any such curve, and tau-adic NAF and regular methods in G2 of
BLS12-381, combining tau with the untwist-Frobenius-twist endomorphism psi.

G1 (sections 1-7):
  * tripling   : two complete 3-isogeny half-steps  psi_b : E_b -> E_{-27b},  then (3X : Y : 27Z),  4S + 6M
                 psi(X:Y:Z) = ( X(Y^2 + 3bZ^2) : Y(Y^2 - 9bZ^2) : Z(Y^2 - bZ^2) )      [never (0,0,0)]
  * addition   : complete mixed addition (Z2 = 1), a = 0, 5M final block              10M
  * table      : 3 base points {1, -2, -1-tau}P and their tau-images, affine (one batch inversion),
                 plus beta*x; all 36 needed points follow from the six units +-1, +-w, +-w^2
  * recoding   : width-3 tau-NAF (Blake-Murty-Xu style), digits in the U-invariant set U*{1, -2, -1-tau}
  * evaluation : Horner in base 3, tau^(2m) = 3^m (-w)^m absorbed into the (unit-invariant) digit

G2 of BLS12-381 (sections 8-10): psi acts as a root of the 12th cyclotomic polynomial, so psi^2 acts as a
primitive 6th root of unity, i.e. as a unit u of Z[omega]. A 4-dimensional decomposition
k = k0 + k1 psi + k2 psi^2 + k3 psi^3 then regroups as

    k = A + B psi,    A = k0 + k2 u,  B = k1 + k3 u  in Z[omega],

and kQ = A Q + B psi(Q) is evaluated with two interleaved tau-adic expansions sharing one Horner loop of
triplings, with the same complete formulas over F_p^2.

Sections 1-5 and 8 use only integer arithmetic, so they run unchanged in Sage or plain Python. Sections
6, 9 and 10 need Sage: they check k*P against Sage's EllipticCurve. Section 7 is a pure-Python self-test of
G1. Run "sage tnaf.sage" for all checks, or "python3 -c 'exec(open(\"tnaf.sage\").read())'" for the
pure-Python ones; set RUN = False before loading to skip the checks.
Completeness of the addition needs odd #E(F_p) (no rational 2-torsion): true for secp256k1 and BLS12-381 G1.
"""

from collections import Counter

# ============================== 1. curve parameters ==============================
CURVES = {
    'secp256k1': dict(
        p = 2**256 - 2**32 - 977, b = 7,
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)),
    'BLS12-381 G1': dict(
        p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab, b = 4,
        n = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001,
        G = (0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb,
             0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)),
}

OPS = {'M': 0, 'S': 0, 'c': 0}          # field multiplications, squarings, small-constant multiplications

def inv(a, m):  return pow(int(a) % int(m), -1, int(m))

def sqrt_mod(a, q):                     # Tonelli-Shanks, q odd prime
    a = int(a) % int(q); q = int(q)
    if a == 0: return 0
    assert pow(a, (q-1)//2, q) == 1, "non-residue"
    s, t = 0, q - 1
    while t % 2 == 0: s += 1; t //= 2
    z = int(2)
    while pow(z, (q-1)//2, q) == 1: z += 1
    m, c, x, r = s, pow(z, t, q), pow(a, (t+1)//2, q), pow(a, t, q)
    while r != 1:
        i, tt = 0, r
        while tt != 1: tt = tt*tt % q; i += 1
        bb = pow(c, 1 << (m - i - 1), q)
        m, c, x, r = i, bb*bb % q, x*bb % q, r*bb*bb % q
    return x

# ============================== 2. complete formulas (homogeneous) ==============================
class Arith:
    def __init__(self, p, b):
        self.p, self.b, self.b3 = int(p), int(b), 3*int(b)
        g = int(2)
        while pow(g, (self.p-1)//3, self.p) == 1: g += 1
        self.beta = pow(g, (self.p-1)//3, self.p)            # primitive cube root of unity in F_p
        self.omb = (1 - self.beta) % self.p                   # 1 - beta
        self.omb3 = pow(self.omb, 3, self.p)                  # (1 - beta)^3

    def M(self, x, y): OPS['M'] += 1; return x*y % self.p
    def S(self, x):    OPS['S'] += 1; return x*x % self.p
    def c(self, k, x): OPS['c'] += 1; return k*x % self.p    # small curve constant: shift/add chain

    def psi(self, R, bb):
        """complete 3-isogeny E_bb -> E_{-27 bb}; 2S + 3M"""
        X, Y, Z = R; p = self.p
        Y2, Z2 = self.S(Y), self.S(Z); t = self.c(bb, Z2)
        return (self.M(X, (Y2 + 3*t) % p), self.M(Y, (Y2 - 9*t) % p), self.M(Z, (Y2 - t) % p))

    def tpl(self, R):
        """3R, complete; 4S + 6M"""
        X, Y, Z = self.psi(self.psi(R, self.b), (-27*self.b) % self.p)
        return (3*X % self.p, Y, 27*Z % self.p)               # E_{729b} -> E_b

    def tau(self, R):
        """tau R = R - omega R, omega(x, y) = (beta x, y); complete (kills the x = 0 three-torsion)"""
        X, Y, Z = self.psi(R, self.b)
        return (self.M(self.omb, X), Y, self.M(self.omb3, Z))  # E_{-27b} -> E_b

    def _prefix_tail(self, t0, t1, t2, A, t4, C):
        p, b3 = self.p, self.b3
        z = self.c(b3, t2); B = (t1 - z) % p; F = (t1 + z) % p; D = self.c(b3, t4); E = 3*t0 % p
        s = (F + D) % p                                       # 5M block: (AB - CD, ED + FB, CF + AE)
        m0 = self.M(s, (B - C) % p); m1 = self.M(F, C); m2 = self.M(D, (C + E - B) % p)
        m3 = self.M((A - s) % p, B); m4 = self.M(A, E)
        u = (m0 + m1) % p
        return ((u + m3) % p, (u + m2) % p, (m1 + m4) % p)

    def add_mixed(self, R, Q):
        """R + Q, R homogeneous, Q = (x, y) affine (never O); complete; 10M"""
        X1, Y1, Z1 = R; x2, y2 = Q; p = self.p
        t0, t1 = self.M(X1, x2), self.M(Y1, y2)
        A = (self.M((X1 + Y1) % p, (x2 + y2) % p) - t0 - t1) % p
        t4 = (self.M(x2, Z1) + X1) % p; C = (self.M(y2, Z1) + Y1) % p
        return self._prefix_tail(t0, t1, Z1, A, t4, C)

    def add(self, R1, R2):
        """R1 + R2, both homogeneous; complete; 11M (precomputation only)"""
        (X1, Y1, Z1), (X2, Y2, Z2) = R1, R2; p = self.p
        t0, t1, t2 = self.M(X1, X2), self.M(Y1, Y2), self.M(Z1, Z2)
        A  = (self.M((X1 + Y1) % p, (X2 + Y2) % p) - t0 - t1) % p
        t4 = (self.M((X1 + Z1) % p, (X2 + Z2) % p) - t0 - t2) % p
        C  = (self.M((Y1 + Z1) % p, (Y2 + Z2) % p) - t1 - t2) % p
        return self._prefix_tail(t0, t1, t2, A, t4, C)

    def dbl(self, R):
        """2R, complete (Renes-Costello-Batina Alg. 9, a = 0); 6M + 2S"""
        X, Y, Z = R; p, b3 = self.p, self.b3
        t0 = self.S(Y); Z3 = 8*t0 % p; t1 = self.M(Y, Z); t2 = self.c(b3, self.S(Z))
        X3 = self.M(t2, Z3); Y3 = (t0 + t2) % p; Z3 = self.M(t1, Z3)
        t0 = (t0 - 3*t2) % p; Y3 = (self.M(t0, Y3) + X3) % p; X3 = 2*self.M(t0, self.M(X, Y)) % p
        return (X3, Y3, Z3)

    def neg(self, R): return (R[0], (-R[1]) % self.p, R[2])

    def to_affine_batch(self, pts):
        """Montgomery's trick: one inversion for all points (none may be O)"""
        p = self.p; zs = [P[2] for P in pts]; acc = [1]
        for z in zs: acc.append(self.M(acc[-1], z))
        iv = inv(acc[-1], p); out = [None]*len(pts)
        for i in range(len(pts) - 1, -1, -1):
            zi = self.M(iv, acc[i]); iv = self.M(iv, zs[i])
            out[i] = (self.M(pts[i][0], zi), self.M(pts[i][1], zi))
        return out

# ============================== 3. Z[omega] arithmetic and the width-3 digit set ==============================
# elements u + v*omega as pairs (u, v);  g + h*tau  <->  (g + h, -h)
UNITS = [(1, 0), (-1, 0), (0, 1), (0, -1), (-1, -1), (1, 1)]          # 1, -1, w, -w, w^2, -w^2
def om_mul(a, b):  (u1, v1), (u2, v2) = a, b; return (u1*u2 - v1*v2, u1*v2 + v1*u2 - v1*v2)
def tau_to_om(g, h): return (g + h, -h)
def om_to_tau(u, v): return (u + v, -v)
def norm_om(u, v):   return u*u - u*v + v*v

W = 3                                                                    # window width
MX, MY = 3**((W + 1)//2), 3**(W//2)                                      # tau^3 | a + b tau  <=>  9 | a, 3 | b
BASE = [(1, 0), (-2, 0), (-1, -1)]                                       # base digits in tau-coords: 1, -2, -1 - tau
DIGIT = {}       # (a mod 9, b mod 3) -> digit (g, h)
WHICH = {}       # digit in omega-coords -> (base index, unit index)
for bi, (g, h) in enumerate(BASE):
    for ui, u in enumerate(UNITS):
        e = om_mul(u, tau_to_om(g, h)); gg, hh = om_to_tau(*e)
        assert norm_om(*e) < 3**W and gg % 3 != 0
        cls = (gg % MX, hh % MY)
        assert cls not in DIGIT, "digit set not a system of representatives"
        DIGIT[cls] = (gg, hh); WHICH[e] = (bi, ui)
assert len(DIGIT) == 2*3**(W - 1), "digit set must cover all classes not divisible by tau"

def recode(a, b):
    """width-3 tau-NAF of a + b*tau; digits least-significant first (None = 0)"""
    S = []
    while a or b:
        if a % 3:
            g, h = DIGIT[(a % MX, b % MY)]; a -= g; b -= h; S.append((g, h))
        else:
            S.append(None)
        a, b = a + b, -(a // 3)            # divide by tau: (a + b tau)/tau = (a + b) - (a/3) tau
    return S

# ============================== 4. scalar decomposition k -> a + b*tau ==============================
def setup_decomposition(n, lam):
    """reduced basis of {(x, y) : x + y*lam = 0 mod n} (Lagrange/Gauss reduction)"""
    v1, v2 = (int(n), 0), (-int(lam) % int(n), 1)
    def dot(a, c): return a[0]*c[0] + a[1]*c[1]
    if dot(v1, v1) < dot(v2, v2): v1, v2 = v2, v1
    while True:
        q = (2*dot(v1, v2) + dot(v2, v2)) // (2*dot(v2, v2))          # round(<v1,v2>/<v2,v2>)
        v1 = (v1[0] - q*v2[0], v1[1] - q*v2[1])
        if dot(v1, v1) >= dot(v2, v2): break
        v1, v2 = v2, v1
    D = v1[0]*v2[1] - v2[0]*v1[1]
    if D < 0: v2 = (-v2[0], -v2[1]); D = -D
    return v1, v2, D

def decompose(k, basis):
    """k = k1 + k2*lam (mod n) with |k1|, |k2| ~ sqrt(n); returned as a + b*tau, tau = 1 - lam"""
    (a1, b1), (a2, b2), D = basis
    rd = lambda x, d: (2*x + d) // (2*d)                                  # round(x/d), d > 0
    c1, c2 = rd(k*b2, D), rd(-k*b1, D)
    k1 = k - c1*a1 - c2*a2; k2 = -c1*b1 - c2*b2
    return k1 + k2, -k2                                                   # k1 + k2 w = (k1 + k2) - k2 tau

# ============================== 5. precomputation and scalar multiplication ==============================
class TauNAF:
    def __init__(self, p, b, n, G):
        self.F = Arith(p, b); self.n = int(n); self.G = (int(G[0]), int(G[1]))
        # lambda: eigenvalue of omega(x, y) = (beta x, y) on <G>
        s = sqrt_mod(-3, self.n); i2 = inv(2, self.n)
        cands = [((-1 + s)*i2) % self.n, ((-1 - s)*i2) % self.n]
        bG = (self.F.beta*self.G[0] % self.F.p, self.G[1])
        self.lam = next(l for l in cands if self.ref_mul(l, self.G) == bG)
        self.basis = setup_decomposition(self.n, self.lam)

    # independent affine reference (used once to pick lambda, and by the self-test)
    def ref_add(self, P, Q):
        p = self.F.p
        if P is None: return Q
        if Q is None: return P
        (x1, y1), (x2, y2) = P, Q
        if x1 == x2 and (y1 + y2) % p == 0: return None
        l = (3*x1*x1*inv(2*y1, p) if P == Q else (y2 - y1)*inv(x2 - x1, p)) % p
        x3 = (l*l - x1 - x2) % p; return (x3, (l*(x1 - x3) - y1) % p)
    def ref_mul(self, k, P):
        R = None
        for bit in bin(int(k))[2:]:
            R = self.ref_add(R, R)
            if bit == '1': R = self.ref_add(R, P)
        return R

    def precompute(self, P):
        """6 affine points: {1, -2, -1-tau}P and their tau-images (+ beta*x of each)"""
        F = self.F; Ph = (P[0], P[1], 1)
        P2  = F.neg(F.dbl(Ph))                          # -2P
        TP  = F.tau(Ph)                                 # tau P
        P3  = F.neg(F.add(Ph, TP))                      # (-1 - tau) P
        base = [Ph, P2, P3]
        imgs = [TP, F.tau(P2), F.tau(P3)]
        aff = F.to_affine_batch(base + imgs)
        self.tab = [(x, y, F.M(F.beta, x)) for (x, y) in aff]   # (x, y, beta x)
        return self.tab

    def lookup(self, digit_om, odd):
        """point (unit * base)P or tau(unit * base)P from the 6-entry table, via units"""
        bi, ui = WHICH[digit_om]
        x, y, bx = self.tab[bi + 3*odd]; p = self.F.p
        u = UNITS[ui]
        if u in [(0, 1), (0, -1)]:   x = bx                              # +-w   : (beta x, y)
        elif u in [(-1, -1), (1, 1)]: x = (-x - bx) % p                   # +-w^2 : (beta^2 x, y)
        if u in [(-1, 0), (0, -1), (1, 1)]: y = (-y) % p                  # negative units
        return (x, y)

    def mul(self, k, P=None):
        P = self.G if P is None else P
        self.precompute(P)
        a, b = decompose(int(k) % self.n, self.basis)
        S = recode(a, b)
        R = (0, 1, 0)                                                     # O; formulas are complete
        if not S: return R
        top = (len(S) - 1)//2
        for m in range(top, -1, -1):
            R = self.F.tpl(R)                                             # complete: fine on O
            for i in (2*m, 2*m + 1):
                if i < len(S) and S[i] is not None:
                    # d tau^i = [d (-w)^m] tau^(i-2m) 3^m ; the bracket is again a digit (U-invariance)
                    c = tau_to_om(*S[i])
                    for _ in range(m): c = om_mul(c, (0, -1))
                    R = self.F.add_mixed(R, self.lookup(c, i - 2*m))
        return R

def to_affine(R, p):
    X, Y, Z = R
    assert (X % p, Y % p, Z % p) != (0, 0, 0), "zero vector: formulas must be complete"
    if Z % p == 0: return None
    zi = inv(Z, p); return (X*zi % p, Y*zi % p)

# ============================== 6. Sage verification ==============================
def sage_check(name, trials=200):
    c = CURVES[name]; p, b, n = c['p'], c['b'], c['n']
    K = GF(p); E = EllipticCurve(K, [0, b]); Gs = E(c['G'])
    assert n*Gs == E(0)
    xx = PolynomialRing(K, 'x').gen()
    assert not (xx**3 + b).roots(), "rational 2-torsion: complete addition needs odd #E(F_p)"
    T = TauNAF(p, b, n, c['G'])
    special = [0, 1, 2, 3, n - 1, n - 2, T.lam, n - T.lam, (1 - T.lam) % n]
    for k in special + [ZZ.random_element(n) for _ in range(trials)]:
        got = to_affine(T.mul(k), p)
        want = k*Gs
        assert (got is None and want == E(0)) or (got is not None and E(got) == want), (name, k)
    print(f"{name}: tau-NAF w=3 (complete, homogeneous) == Sage k*G on {len(special) + trials} scalars")

# ============================== 7. pure-Python self-test ==============================
def python_check(name, trials=20):
    c = CURVES[name]; p, b, n = c['p'], c['b'], c['n']
    T = TauNAF(p, b, n, c['G'])
    assert T.ref_mul(n, T.G) is None, "n*G != O"
    import random
    special = [0, 1, 2, 3, n - 1, n - 2, T.lam, n - T.lam, (1 - T.lam) % n]
    for k in special + [random.randrange(n) for _ in range(trials)]:
        assert to_affine(T.mul(k), p) == T.ref_mul(k, T.G), (name, k)
    # operation counts for one random scalar multiplication
    import random as _r
    k = _r.randrange(n)
    OPS.update(M=0, S=0, c=0); T.precompute(T.G); pre = dict(OPS)
    OPS.update(M=0, S=0, c=0); T.mul(k); tot = dict(OPS)
    loop = {key: tot[key] - pre[key] for key in tot}
    print(f"{name}: matches affine reference on {len(special) + trials} scalars;"
          f" per k*P: precomp {pre['M']}M+{pre['S']}S (+1 inversion), loop {loop['M']}M+{loop['S']}S,"
          f" small-const {loop['c']}")

# ============================== 8. G2 digit codes and recodings ==============================
# The G2 methods index digits by the code 6 * base + unit, with the unit (-1)^s w^e at index e + 3s, so that
# a lookup applies the unit as a power of beta and a sign. The NAF uses the first three bases,
# U*{1, 2, 1 + tau}, which is the G1 digit set U*{1, -2, -1 - tau} up to the unit -1; the regular recoding
# uses all six, as RELIC's TWREG does.
UNITS_ES = [(1, 0), (0, 1), (-1, -1), (-1, 0), (0, -1), (1, 1)]          # (-1)^s w^e, index e + 3s
BASES_REG = [(1, 0), (2, 0), (1, 1), (1, -2), (2, 1), (1, 2)]           # tau-coords; first 3 for the NAF
DIG = [om_to_tau(*om_mul(u, tau_to_om(*bb))) for bb in BASES_REG for u in UNITS_ES]
NAF_CODE = {}
for c in range(18):
    g, h = DIG[c]; NAF_CODE.setdefault((g % 9, h % 3), c)
REG_CODE = {}
for a9 in range(9):
    for b9 in range(9):
        if a9 % 3:
            REG_CODE[(a9, b9)] = next(c for c in range(36) if (DIG[c][0] % 9, DIG[c][1] % 3) == (a9, b9 % 3)
                                      and (DIG[c][0] % 9, DIG[c][1] % 9) != (a9, b9))

def recode_codes(a, b):
    """width-3 tau-NAF of a + b*tau as digit codes; least-significant first (None = 0)"""
    S = []
    while a or b:
        if a % 3:
            c = NAF_CODE[(a % 9, b % 3)]; g, h = DIG[c]; a -= g; b -= h; S.append(c)
        else:
            S.append(None)
        a, b = a + b, -(a // 3)
    return S

def recode_regular(a, b, L):
    """regular recoding, a not divisible by 3; digits at positions 3j, top digit a unit"""
    S = []
    for _ in range(L):
        c = REG_CODE[(a % 9, b % 9)]; g, h = DIG[c]; a -= g; b -= h; S.append(c)
        a, b = (a + 2 * b) // 3, -(2 * a + 3 * b) // 9
    u = tau_to_om(a, b); assert u in UNITS_ES, ("remainder not a unit", u)
    S.append(UNITS_ES.index(u))
    return S

# ============================== 9. G2 of BLS12-381 (Sage only) ==============================
OPS_G2 = Counter()                      # point operations: tpl, tau, add, dbl, psi, norm (affine conversions)

class TauG2:
    def __init__(self):
        p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
        r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
        Fp = GF(p); X = PolynomialRing(Fp, 'X').gen()
        K = Fp.extension(X**2 + 1, 'i'); i = K.gen()
        xi = 1 + i
        self.p, self.r, self.K, self.b2 = p, r, K, 4 * xi
        E2 = EllipticCurve(K, [0, self.b2]); self.E2 = E2
        Q0 = E2(0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
                + 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e * i,
                0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
                + 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be * i)
        assert r * Q0 == E2(0)
        self.Q0 = Q0

        # psi(x, y) = (cx * x^p, cy * y^p): pick the constants that give an endomorphism of E2 acting as p on G2
        self.psi_c = None
        for cx in (xi ** ((p - 1) // 3), 1 / xi ** ((p - 1) // 3)):
            for cy in (xi ** ((p - 1) // 2), 1 / xi ** ((p - 1) // 2)):
                x0, y0 = Q0.xy()
                try:
                    T = E2(cx * self.frob(x0), cy * self.frob(y0))
                except TypeError:
                    continue
                if T == (p % r) * Q0:
                    self.psi_c = (cx, cy)
        assert self.psi_c is not None, "no psi constants found"
        self.e_psi = p % r                                       # eigenvalue of psi on G2
        assert (self.e_psi ** 4 - self.e_psi ** 2 + 1) % r == 0  # 12th cyclotomic polynomial

        g = Fp(2)
        while g ** ((p - 1) // 3) == 1: g += 1
        self.beta = g ** ((p - 1) // 3)                          # cube root of unity in Fp
        # eigenvalue of omega on G2
        self.lam = next(l for l in [((-1 + s) * pow(2, -1, r)) % r
                                    for s in (Integers(r)(-3).sqrt(), -Integers(r)(-3).sqrt())]
                        for l in [int(l)] if E2(self.omega_aff(Q0.xy())) == l * Q0)
        # psi and omega commute (beta lies in Fp)
        assert self.psi_aff(self.omega_aff(Q0.xy())) == self.omega_aff(self.psi_aff(Q0.xy()))
        self.c1 = 1 - self.beta; self.c3 = self.c1 ** 3

        # lattice of (k0, k1, k2, k3) with k0 + k1 e + k2 e^2 + k3 e^3 = 0 mod r, LLL-reduced
        e = self.e_psi
        self.Lat = matrix(ZZ, [[r, 0, 0, 0], [-e, 1, 0, 0], [-e ** 2 % r, 0, 1, 0], [-e ** 3 % r, 0, 0, 1]]).LLL()
        self.Linv = self.Lat.inverse()
        # psi^2 acts on G2 as the unit u: find u = (-1)^s w^e with eigenvalue e_psi^2
        self.u_psi2 = next(UNITS_ES[j] for j in range(6)
                           if ((-1) ** (j // 3) * pow(self.lam, j % 3, r) - e ** 2) % r == 0)

    # endomorphisms
    def frob(self, a): return a ** self.p
    def psi_aff(self, P):
        x0, y0 = P
        return (self.psi_c[0] * self.frob(x0), self.psi_c[1] * self.frob(y0))
    def omega_aff(self, P): return (self.beta * P[0], P[1])

    # complete formulas over K
    def iso3(self, R, bb):
        """3-isogeny y^2 = x^3 + bb -> y^2 = x^3 - 27 bb, complete"""
        X, Y, Z = R; Y2 = Y * Y; t = bb * Z * Z
        return (X * (Y2 + 3 * t), Y * (Y2 - 9 * t), Z * (Y2 - t))

    def tpl(self, R):
        OPS_G2['tpl'] += 1
        X, Y, Z = self.iso3(self.iso3(R, self.b2), -27 * self.b2)
        return (3 * X, Y, 27 * Z)

    def tau(self, R):
        OPS_G2['tau'] += 1
        X, Y, Z = self.iso3(R, self.b2)
        return (self.c1 * X, Y, self.c3 * Z)

    def add(self, P, Q):
        """RCB complete addition, a = 0 (Q may be affine with Z = 1)"""
        OPS_G2['add'] += 1
        X1, Y1, Z1 = P; X2, Y2, Z2 = Q; b3 = 3 * self.b2
        t0 = X1 * X2; t1 = Y1 * Y2; t2 = Z1 * Z2
        t3 = (X1 + Y1) * (X2 + Y2) - t0 - t1
        t4 = (Y1 + Z1) * (Y2 + Z2) - t1 - t2
        Y3 = (X1 + Z1) * (X2 + Z2) - t0 - t2
        X3 = 3 * t0; t2 = b3 * t2; Z3 = t1 + t2; t1 = t1 - t2; Y3 = b3 * Y3
        return (t3 * t1 - t4 * Y3, t1 * Z3 + Y3 * X3, Z3 * t4 + X3 * t3)

    def dbl(self, P):
        OPS_G2['dbl'] += 1
        X, Y, Z = P; b3 = 3 * self.b2
        t0 = Y * Y; Z3 = 8 * t0; t1 = Y * Z; t2 = b3 * Z * Z
        X3 = t2 * Z3; Y3 = t0 + t2; Z3 = t1 * Z3; t0 = t0 - 3 * t2
        return (2 * t0 * X * Y, t0 * Y3 + X3, Z3)

    def neg(self, P): return (P[0], -P[1], P[2])
    def aff(self, P):
        X, Y, Z = P
        return None if Z == 0 else (X / Z, Y / Z)
    def proj(self, P): return (P[0], P[1], self.K(1))

    # decomposition
    def decomp4(self, k):
        v = vector(QQ, [k, 0, 0, 0]) * self.Linv
        c = vector(ZZ, [round(x) for x in v])
        ks = vector(ZZ, [k, 0, 0, 0]) - c * self.Lat
        assert (sum(int(ks[j]) * self.e_psi ** j for j in range(4)) - k) % self.r == 0
        return [int(x) for x in ks]

    def regroup(self, k):
        k0, k1, k2, k3 = self.decomp4(k); u = self.u_psi2
        A = (k0 + k2 * u[0], k2 * u[1])        # omega-coords
        B = (k1 + k3 * u[0], k3 * u[1])
        return A, B, (k0, k1, k2, k3)

    # scalar multiplications
    def table(self, Qa, s):
        """affine table: base digits times Q (s bases) and their tau images, as in RELIC's tw_tab"""
        Qp = self.proj(Qa)
        T = [Qp, self.dbl(Qp)]
        tq = self.tau(Qp); T.append(self.add(Qp, tq))
        t2q = self.tau(T[1])
        if s == 6:
            T += [self.add(Qp, self.neg(t2q)), self.add(T[1], tq), self.add(Qp, t2q)]
        imgs = [tq, t2q] + [self.tau(T[j]) for j in range(2, s)]
        OPS_G2['norm'] += 2 * s - 1
        return [self.aff(P) for P in T + imgs]

    def lookup(self, tab, s, code, odd, m):
        bi, ui = code // 6, code % 6
        e = (ui % 3 + m) % 3; sg = (ui // 3 + m) % 2
        x, y = tab[bi + s * odd]
        x = x * self.beta ** e
        return (x, -y if sg else y, self.K(1))

    def mul_twnaf(self, k, Qa):
        A, B, _ = self.regroup(k % self.r)
        TA = self.table(Qa, 3)
        TB = [self.psi_aff(P) for P in TA]; OPS_G2['psi'] += len(TB)   # psi commutes with tau and omega
        SA = recode_codes(*om_to_tau(*A)); SB = recode_codes(*om_to_tau(*B))
        l = max(len(SA), len(SB)); K = self.K; R = (K(0), K(1), K(0))
        for m in range((l - 1) // 2, -1, -1):
            R = self.tpl(R)
            for j in (2 * m, 2 * m + 1):
                for S, T in ((SA, TA), (SB, TB)):
                    if j < len(S) and S[j] is not None:
                        R = self.add(R, self.lookup(T, 3, S[j], j - 2 * m, m))
        return R, l

    def reg_len(self, bound_bits):
        return int(ceil((bound_bits + 1.3) / log(27, 2)))

    def mul_twreg(self, k, Qa, L):
        A, B, _ = self.regroup(k % self.r)
        TA = self.table(Qa, 6)
        TB = [self.psi_aff(P) for P in TA]; OPS_G2['psi'] += len(TB)
        fix = []
        S = []
        for (u, v) in (A, B):
            a, b = om_to_tau(u, v)
            odd = (a % 3 == 0); a += odd; fix.append(odd)
            S.append(recode_regular(a, b, L))
        top = 3 * L; M = top // 2; R = None
        for m in range(M, -1, -1):
            if m < M: R = self.tpl(R)
            for j in (2 * m, 2 * m + 1):
                if j % 3 == 0 and j <= top:
                    for Sx, T in zip(S, (TA, TB)):
                        q = self.lookup(T, 6, Sx[j // 3], j - 2 * m, m)
                        R = q if R is None else self.add(R, q)
        # constant-time corrections for A or B divisible by tau
        nA, nB = self.neg(self.proj(TA[0])), self.neg(self.proj(TB[0]))
        R = self.add(R, nA) if fix[0] else (self.add(R, nA), R)[1]
        R = self.add(R, nB) if fix[1] else (self.add(R, nB), R)[1]
        return R

# ============================== 10. G2 checks and operation counts (Sage only) ==============================
def g2_check(trials=30):
    G = TauG2(); r, E2 = G.r, G.E2
    print("G2: psi constants ok, e_psi = p mod r; omega eigenvalue lambda; psi^2 = unit", G.u_psi2)
    print("G2: LLL basis row lengths (bits):", [ZZ(max(abs(int(x)) for x in row)).nbits() for row in G.Lat])
    # sizes of A and B
    mx = 0; mxk = 0
    for _ in range(2000):
        A, B, ks = G.regroup(ZZ.random_element(r))
        mx = max(mx, max(abs(complex(A[0] + A[1] * (-0.5), A[1] * 0.8660254037844386)),
                         abs(complex(B[0] + B[1] * (-0.5), B[1] * 0.8660254037844386))))
        mxk = max(mxk, max(abs(x) for x in ks))
    print("G2: max |k_i| bits %.2f, max |A|,|B| bits %.2f" % (log(mxk, 2).n(), log(mx, 2).n()))
    L = G.reg_len(log(mx, 2).n() * 2 + 0.5)            # empirical bound with margin, for the check only
    print("G2: regular length L =", L)

    Qa = ((2 ** 77 + 12345) * G.Q0).xy()
    stats_naf = Counter(); stats_reg = Counter(); n = 0
    for k in [1, 2, 3, r - 1, r - 2, G.lam, G.e_psi] + [ZZ.random_element(r) for _ in range(trials)]:
        OPS_G2.clear()
        R, l = G.mul_twnaf(k, Qa)
        want = k * E2(Qa)
        got = G.aff(R)
        assert (got is None and want == E2(0)) or E2(got) == want, ("naf", k)
        stats_naf.update(OPS_G2); stats_naf['len'] += l
        OPS_G2.clear()
        R = G.mul_twreg(k, Qa, L)
        got = G.aff(R)
        assert (got is None and want == E2(0)) or E2(got) == want, ("reg", k)
        stats_reg.update(OPS_G2); n += 1
    print("G2: tau-adic NAF and regular == Sage k*Q on %d scalars" % n)
    print("G2: NAF w=3 per k*Q:", {key: round(v / n, 1) for key, v in stats_naf.items()})
    print("G2: REG w=3 per k*Q:", {key: round(v / n, 1) for key, v in stats_reg.items()})

# ============================== checks ==============================
if globals().get("RUN", True):
    try:
        EllipticCurve                                     # defined only inside Sage
        SAGE = True
    except NameError:
        SAGE = False
    if SAGE:
        for nm in CURVES: sage_check(nm)
        g2_check()
    else:
        for nm in CURVES: python_check(nm)
        print("G2 of BLS12-381: skipped, needs Sage")
