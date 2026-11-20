#!/usr/bin/env python3
"""Bounds the iterations of the cubic and quartic residue symbols by jumps of
divsteps.

Usage: tools/relic-smb-hull.py hull RING STEPS NGON OUT [DV SB SWC D0]
       tools/relic-smb-hull.py fit RING OUT

RING is 3 for the cubic symbol of relic_fp_smb3.c, in the Eisenstein integers
Z[w], and 4 for the quartic symbol of relic_fp_smb4.c, in the Gaussian
integers Z[i]. An iteration divides g by the prime l = 1 - w or 1 + i above
3 or 2 if it can, and otherwise makes g primary with a unit u and replaces it
by (u * g - f) / l^k, for k = 2 or 3, after swapping f and u * g if delta > 0.

The hull command computes a convex-hull bound of these combined divsteps, in
the manner of the safegcd-bounds analysis of Bernstein-Yang divsteps:
starting from all f and g with |f|, |g| <= 1, approximated by NGON-gons around
the disks, it runs the iterations backwards and keeps, for each doubled delta,
the convex hull in R^4 of the reachable (f, g), together with the largest over
its merged lineages of the smallest |g| seen. After B iterations, 1 / that
maximum is a lower bound M(B) on the size of inputs that B iterations take to
g = 0. It writes one line per iteration to OUT: B, log2(M(B)), the number of
deltas, the number of hull vertices and the elapsed seconds. It needs numpy
and scipy, and runs on several processes (NP in the environment, 7 by
default); 800 iterations with 12-gons take about half an hour for RING 3, and
1000 iterations with 8-gons about 45 minutes on one process for RING 4.

The update rule of the doubled delta is a division adds DV, a subtraction adds
SB, and a swap, when delta > 0, sets it to SWC - delta, from D0. The defaults
are the rules of the symbols, the best of those tried.

The fit command reads OUT and checks the formula of the number of iterations
of the symbol: as f = pi and g = a - q pi have absolute values at most
sqrt(p), a prime of b bits needs the smallest B with log2(M(B)) >= b / 2. It
prints that B for common sizes, the formula and their difference, and the
slope of the bound, which the formula must not undercut to extrapolate beyond
the computed iterations.
"""

import math
import sys
import time

# For each ring: the generator of the units, the exponent k of the
# subtraction, the default rule (DV, SB, SWC, D0), and the iterations of the
# symbol, RLC_CEIL(FP_PRIME * A + B, C), with the name of the macro.
RINGS = {
	3: dict(w=complex(-0.5, math.sqrt(3) / 2), units=6, k=2,
			rule=(2, 4, 4, 1), iters=(139, 1890, 125), name='FP_CUB_ITER'),
	4: dict(w=1j, units=4, k=3,
			rule=(2, 6, 12, 1), iters=(168, 2817, 100), name='FP_QRT_ITER'),
}


def reduce(args):
	"""Keeps the vertices of the convex hull in R^4 of the points (F, G)."""
	import numpy as np
	from scipy.spatial import ConvexHull
	d, F, G, h = args
	P = np.stack([F.real, F.imag, G.real, G.imag], axis=1)
	if len(P) > 6:
		try:
			v = ConvexHull(P, qhull_options='Q12 QJ').vertices
			F, G = F[v], G[v]
		except Exception:
			pass
	return d, F, G, h


def hull(ring, steps, ngon, out, dv=None, sb=None, swc=None, d0=None):
	import os
	import numpy as np
	from multiprocessing import Pool
	R = RINGS[ring]
	rule = R['rule']
	dv = rule[0] if dv is None else dv
	sb = rule[1] if sb is None else sb
	swc = rule[2] if swc is None else swc
	d0 = rule[3] if d0 is None else d0
	# The primes above 3 and 2 are 1 - w and 1 + i, the latter a unit times
	# 1 - i, so 1 - w generalizes to both.
	W = R['w']
	C = 1 / (1 - W) if ring == 3 else 1 / (1 + W)
	CK = C ** R['k']
	# The units are the powers of -w for Z[w] and of i for Z[i].
	g = -W if ring == 3 else W
	units = [g ** j for j in range(R['units'])]
	r0 = 1 / math.cos(math.pi / ngon)
	z = r0 * np.exp(2j * np.pi * np.arange(ngon) / ngon)
	state = {d0: (np.repeat(z, ngon), np.tile(z, ngon), float(r0))}
	pool = Pool(int(os.environ.get('NP', '7')))
	t0 = time.time()
	with open(out, 'w') as fo:
		for b in range(1, steps + 1):
			new = {}

			def put(d, F, G, h):
				hh = min(h, float(np.abs(G).max()))
				if d in new:
					F1, G1, h1 = new[d]
					new[d] = (np.concatenate([F1, F]),
							np.concatenate([G1, G]), max(h1, hh))
				else:
					new[d] = (F, G, hh)

			for d, (F, G, h) in state.items():
				# A division by l, or a subtraction with each unit, swapping
				# first when delta > 0.
				put(d + dv, F, G * C, h)
				for u in units:
					Gu = G * u
					if d > 0:
						put(swc - d, Gu, (F - Gu) * CK, h)
					else:
						put(d + sb, F, (Gu - F) * CK, h)
			res = pool.map(reduce,
					[(d, F, G, h) for d, (F, G, h) in new.items()], chunksize=4)
			state = {d: (F, G, h) for d, F, G, h in res}
			H = max(h for _, _, h in state.values())
			npts = sum(len(F) for F, _, _ in state.values())
			fo.write("%d %.6f %d %d %.0f\n" % (b, -math.log2(H), len(state),
					npts, time.time() - t0))
			fo.flush()


def fit(ring, out):
	A, B, C = RINGS[ring]['iters']
	L = {}
	for line in open(out):
		b, m = line.split()[:2]
		L[int(b)] = float(m)
	top = max(L)
	print("bits  hull  %s  over" % RINGS[ring]['name'])
	for bits in (128, 158, 254, 255, 256, 381, 446, 455, 509, 544, 575, 638,
			689):
		need = [n for n in L if L[n] >= bits / 2]
		if not need:
			print("%4d  beyond the %d iterations computed" % (bits, top))
			continue
		ex = min(need)
		f = -(-(A * bits + B) // C)
		print("%4d  %4d  %11d  %4d" % (bits, ex, f, f - ex))
	for a, b in ((200, 400), (400, 600), (600, 800), (800, 1000)):
		if a in L and b in L:
			s = (L[b] - L[a]) / (b - a)
			print("iterations per bit from %d to %d: %.5f" % (a, b, 1 / (2 * s)))
	print("iterations per bit of %s: %.5f" % (RINGS[ring]['name'], A / C))


if __name__ == '__main__':
	if len(sys.argv) >= 6 and sys.argv[1] == 'hull':
		hull(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]),
				sys.argv[5], *[int(x) for x in sys.argv[6:10]])
	elif len(sys.argv) == 4 and sys.argv[1] == 'fit':
		fit(int(sys.argv[2]), sys.argv[3])
	else:
		sys.exit(__doc__)
