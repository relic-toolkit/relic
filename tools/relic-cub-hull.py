#!/usr/bin/env python3
"""Bounds the iterations of the cubic residue symbol by jumps of divsteps.

Usage: tools/relic-cub-hull.py hull STEPS NGON OUT [DV SB SWC D0]
       tools/relic-cub-hull.py fit OUT

The hull command computes a convex-hull bound of the combined divsteps of
relic_fp_smb3.c in the Eisenstein integers, in the manner of the
safegcd-bounds analysis of Bernstein-Yang divsteps: starting from all f and g
with |f|, |g| <= 1, approximated by NGON-gons around the disks, it runs the
iterations backwards and keeps, for each doubled delta, the convex hull in R^4
of the reachable (f, g), together with the largest over its merged lineages of
the smallest |g| seen. After B iterations, 1 / that maximum is a lower bound
M(B) on the size of inputs that B iterations take to g = 0. It writes one line
per iteration to OUT: B, log2(M(B)), the number of deltas, the number of hull
vertices and the elapsed seconds. It needs numpy and scipy, and runs on
several processes (NP in the environment, 7 by default); 800 iterations with
12-gons take about half an hour.

The update rule of the doubled delta is a division adds DV, a subtraction adds
SB, and a swap, when delta > 0, sets it to SWC - delta, from D0. The defaults
2, 4, 4 and 1 are the rule of relic_fp_smb3.c, the best of the twelve rules
tried.

The fit command reads OUT and checks the formula of FP_CUB_ITER: as f = pi
and g = a - q pi have absolute values at most sqrt(p), a prime of b bits needs
the smallest B with log2(M(B)) >= b / 2. It prints that B for common sizes,
the formula and their difference, and the slope of the bound, which the
formula must not undercut to extrapolate beyond the computed iterations.
"""

import math
import sys
import time

# Iterations of FP_CUB_ITER = RLC_CEIL(FP_PRIME * ITER_A + ITER_B, ITER_C).
ITER_A, ITER_B, ITER_C = 139, 1890, 125


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


def hull(steps, ngon, out, dv=2, sb=4, swc=4, d0=1):
	import os
	import numpy as np
	from multiprocessing import Pool
	W = np.exp(2j * np.pi / 3)
	C = 1 / (1 - W)
	C2 = C * C
	units = [1, -1, W, -W, W * W, -W * W]
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
				# A division by 1 - w, or a subtraction with each unit,
				# swapping first when delta > 0.
				put(d + dv, F, G * C, h)
				for u in units:
					Gu = G * u
					if d > 0:
						put(swc - d, Gu, (F - Gu) * C2, h)
					else:
						put(d + sb, F, (Gu - F) * C2, h)
			res = pool.map(reduce,
					[(d, F, G, h) for d, (F, G, h) in new.items()], chunksize=4)
			state = {d: (F, G, h) for d, F, G, h in res}
			H = max(h for _, _, h in state.values())
			npts = sum(len(F) for F, _, _ in state.values())
			fo.write("%d %.6f %d %d %.0f\n" % (b, -math.log2(H), len(state),
					npts, time.time() - t0))
			fo.flush()


def fit(out):
	L = {}
	for line in open(out):
		b, m = line.split()[:2]
		L[int(b)] = float(m)
	top = max(L)
	print("bits  hull  FP_CUB_ITER  over")
	for bits in (128, 158, 254, 256, 381, 446, 455, 509, 544, 575, 638, 689):
		need = [B for B in L if L[B] >= bits / 2]
		if not need:
			print("%4d  beyond the %d iterations computed" % (bits, top))
			continue
		ex = min(need)
		f = -(-(ITER_A * bits + ITER_B) // ITER_C)
		print("%4d  %4d  %11d  %4d" % (bits, ex, f, f - ex))
	for a, b in ((200, 400), (400, 600), (600, 800)):
		if a in L and b in L:
			s = (L[b] - L[a]) / (b - a)
			print("iterations per bit from %d to %d: %.5f" % (a, b, 1 / (2 * s)))
	print("iterations per bit of FP_CUB_ITER: %.5f" % (ITER_A / ITER_C))


if __name__ == '__main__':
	if len(sys.argv) >= 5 and sys.argv[1] == 'hull':
		hull(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4],
				*[int(x) for x in sys.argv[5:9]])
	elif len(sys.argv) == 3 and sys.argv[1] == 'fit':
		fit(sys.argv[2])
	else:
		sys.exit(__doc__)
