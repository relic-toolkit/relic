/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of the low-level functions for elliptic curves over
 * extensions of prime fields in a Residue Number System with AVX-512 IFMA.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_epx_low.h"

#if FP_RDC == FP_RENUS

#include "relic_fp_rns_avx.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Largest b of the curve over the prime field for which the point operations
 * multiply by the coefficient 3b' of the twist with lane-wise modular
 * additions: 3b' = 3b * (s + i) for an M-type twist and 3b' = 3b / (s + i) =
 * 3b / (s^2 - q) * (s - i) for a D-type one, if s^2 - q divides 3b, with i^2 =
 * q. The chain of additions grows with the bits of 3b, so larger b, and other
 * twists, multiply by b' after a reduction.
 */
#define EPX_LOW_B		16

/**
 * Returns the integer that multiplies s + i or s - i in the lane-wise
 * multiplication by 3b' of the point operations, or zero if they multiply by
 * b' after a reduction.
 *
 * @param[in] C				- the library context.
 * @param[in] S				- the integer part of the non-residue.
 * @param[in] Q				- the square of i.
 */
#define EPX_LOW_K(C, S, Q)													\
	((C)->ep_b_dig > EPX_LOW_B ? 0 :										\
	ep2_curve_is_twist() == RLC_EP_MTYPE ? 3 * (int)(C)->ep_b_dig :			\
	ep2_curve_is_twist() == RLC_EP_DTYPE &&									\
	(3 * (int)(C)->ep_b_dig) % ((S) * (S) - (Q)) == 0 ?						\
	3 * (int)(C)->ep_b_dig / ((S) * (S) - (Q)) : 0)

/**
 * Returns the sign of i in the factor s + i or s - i of 3b'.
 */
#define EPX_LOW_D		(ep2_curve_is_twist() == RLC_EP_DTYPE ? -1 : 1)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/* The point operations run residue-wise around their reductions, in vectors,
 * so the additions of the formulas need no calls. Products of elements of Fp2
 * and sums of two of them take factors at most m, and give unreduced values
 * at most 2m. */

void ep2_dblp_low(ep2_t r, const ep2_t p) {
	ctx_t *ctx = core_get();
	const int d = EPX_LOW_D;
	fp2_t t0, t1, t2, t3, t5;
	dv2_t u[4];
	dig_t *c[8], *a[8];
	rp2_t x, y, z, e, f, g;
	__m512i m, v;
	int b, s, q;

	fp2_null_all(t0, t1, t2, t3, t5);
	dv2_null_all(u[0], u[1], u[2], u[3]);

	RLC_TRY {
		fp2_new_all(t0, t1, t2, t3, t5);
		dv2_new_all(u[0], u[1], u[2], u[3]);

		rns_nor(&s, &q);
		b = EPX_LOW_K(ctx, s, q);
		for (int i = 0; i < 4; i++) {
			a[2 * i] = u[i][0];
			a[2 * i + 1] = u[i][1];
		}
		/* Y^2, X * Y, Y * Z and Z^2, or 3b' * Z^2 when 3b' * Z comes from
		 * lane-wise additions, which saves a step between the batches. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			rp2_load(x, p->x, k);
			rp2_load(y, p->y, k);
			rp2_load(z, p->z, k);
			rp2_mul(e, y, y, NULL, NULL, q, m, v);
			rp2_stored(u[0], k, e);
			rp2_mul(e, x, y, NULL, NULL, q, m, v);
			rp2_stored(u[1], k, e);
			rp2_mul(e, y, z, NULL, NULL, q, m, v);
			rp2_stored(u[2], k, e);
			if (b) {
				rp2_mulk(f, z, b, s, q, d, m);
				rp2_mul(e, z, f, NULL, NULL, q, m, v);
			} else {
				rp2_mul(e, z, z, NULL, NULL, q, m, v);
			}
			rp2_stored(u[3], k, e);
		}
		c[0] = t0[0];
		c[1] = t0[1];
		c[2] = t3[0];
		c[3] = t3[1];
		c[4] = t1[0];
		c[5] = t1[1];
		c[6] = t2[0];
		c[7] = t2[1];
		RNS_RDCV(c, a, 8);
		/* 3b' * Z^2 otherwise. */
		if (b == 0) {
			for (size_t k = 0; k < RNS_NE; k++) {
				m = rns_load(ctx->rns.m, k);
				rp2_load(z, t2, k);
				rp2_add(e, z, z, m);
				rp2_add(e, e, z, m);
				rp2_store(t5, k, e);
			}
			ep2_curve_mul_b(t2, t5);
		}
		/* y3 = t2 * z3 + t4 * (t0 + t2), z3 = t1 * z3 and x3 = 2 * t4 * t3 for
		 * z3 = 8 * t0 and t4 = t0 - 3 * t2. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			rp2_load(x, t0, k);
			rp2_load(y, t2, k);
			rp2_add(z, x, x, m);
			rp2_add(z, z, z, m);
			rp2_add(z, z, z, m);
			rp2_add(e, x, y, m);
			rp2_add(f, y, y, m);
			rp2_add(f, f, y, m);
			rp2_sub(f, x, f, m);
			rp2_mul(g, y, z, f, e, q, m, v);
			rp2_stored(u[0], k, g);
			rp2_load(e, t1, k);
			rp2_mul(g, e, z, NULL, NULL, q, m, v);
			rp2_stored(u[1], k, g);
			rp2_add(f, f, f, m);
			rp2_load(e, t3, k);
			rp2_mul(g, f, e, NULL, NULL, q, m, v);
			rp2_stored(u[2], k, g);
		}
		c[0] = r->y[0];
		c[1] = r->y[1];
		c[2] = r->z[0];
		c[3] = r->z[1];
		c[4] = r->x[0];
		c[5] = r->x[1];
		RNS_RDCV(c, a, 6);
		r->coord = EC_PROJC;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free_all(t0, t1, t2, t3, t5);
		dv2_free_all(u[0], u[1], u[2], u[3]);
	}
}

void ep2_addp_low(ep2_t r, const ep2_t p, const ep2_t q) {
	ctx_t *ctx = core_get();
	const int d = EPX_LOW_D;
	fp2_t t0, t1, t2, t3, t4, t5, w, h;
	dv2_t u[6];
	dig_t *c[12], *a[12];
	rp2_t x, y, z, e, f, g, b0, b1, b2, b3;
	__m512i m, v;
	int b, s, n;

	fp2_null_all(t0, t1, t2, t3, t4, t5, w, h);
	dv2_null_all(u[0], u[1], u[2], u[3], u[4], u[5]);

	RLC_TRY {
		fp2_new_all(t0, t1, t2, t3, t4, t5, w, h);
		dv2_new_all(u[0], u[1], u[2], u[3], u[4], u[5]);

		rns_nor(&s, &n);
		b = EPX_LOW_K(ctx, s, n);
		for (int i = 0; i < 6; i++) {
			a[2 * i] = u[i][0];
			a[2 * i + 1] = u[i][1];
		}
		/* x1 * x2, y1 * y2, z1 * z2, (x1 + y1) * (x2 + y2),
		 * (y1 + z1) * (y2 + z2) and (x1 + z1) * (x2 + z2). */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			rp2_load(x, p->x, k);
			rp2_load(y, p->y, k);
			rp2_load(z, p->z, k);
			rp2_load(e, q->x, k);
			rp2_load(f, q->y, k);
			rp2_load(g, q->z, k);
			rp2_mul(b0, x, e, NULL, NULL, n, m, v);
			rp2_stored(u[0], k, b0);
			rp2_mul(b0, y, f, NULL, NULL, n, m, v);
			rp2_stored(u[1], k, b0);
			rp2_mul(b0, z, g, NULL, NULL, n, m, v);
			rp2_stored(u[2], k, b0);
			rp2_add(b1, x, y, m);
			rp2_add(b2, e, f, m);
			rp2_mul(b0, b1, b2, NULL, NULL, n, m, v);
			rp2_stored(u[3], k, b0);
			rp2_add(b1, y, z, m);
			rp2_add(b2, f, g, m);
			rp2_mul(b0, b1, b2, NULL, NULL, n, m, v);
			rp2_stored(u[4], k, b0);
			rp2_add(b1, x, z, m);
			rp2_add(b2, e, g, m);
			rp2_mul(b0, b1, b2, NULL, NULL, n, m, v);
			rp2_stored(u[5], k, b0);
		}
		c[0] = t0[0];
		c[1] = t0[1];
		c[2] = t1[0];
		c[3] = t1[1];
		c[4] = t2[0];
		c[5] = t2[1];
		c[6] = t3[0];
		c[7] = t3[1];
		c[8] = t4[0];
		c[9] = t4[1];
		c[10] = t5[0];
		c[11] = t5[1];
		RNS_RDCV(c, a, 12);
		/* 3 * z1 * z2 and 3 * (x1 * z2 + x2 * z1), both multiplied by b',
		 * unless that is done lane-wise. */
		if (b == 0) {
			for (size_t k = 0; k < RNS_NE; k++) {
				m = rns_load(ctx->rns.m, k);
				rp2_load(z, t2, k);
				rp2_add(e, z, z, m);
				rp2_add(e, e, z, m);
				rp2_store(w, k, e);
				rp2_load(x, t0, k);
				rp2_load(y, t5, k);
				rp2_add(x, x, z, m);
				rp2_sub(x, y, x, m);
				rp2_add(e, x, x, m);
				rp2_add(e, e, x, m);
				rp2_store(h, k, e);
			}
			ep2_curve_mul_b(w, w);
			ep2_curve_mul_b(h, h);
		}
		/* x3 = t3 * t1 - t4 * y3, y3 = y3 * t0 + t1 * z3 and z3 = z3 * t4 +
		 * t0 * t3, after the additions of the formula. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			rp2_load(b0, t0, k);
			rp2_load(b1, t1, k);
			rp2_load(b3, t3, k);
			rp2_load(x, t2, k);
			if (b) {
				/* 3b' * z1 * z2 and 3b' * (t5 - (t0 + t2)). */
				rp2_mulk(b2, x, b, s, n, d, m);
				rp2_load(y, t5, k);
				rp2_add(e, b0, x, m);
				rp2_sub(e, y, e, m);
				rp2_mulk(y, e, b, s, n, d, m);
			} else {
				rp2_load(b2, w, k);
				rp2_load(y, h, k);
			}
			/* t3 = t3 - (t0 + t1), t4 = t4 - (t1 + t2), z3 = t1 + 3b'z1z2. */
			rp2_add(e, b0, b1, m);
			rp2_sub(b3, b3, e, m);
			rp2_add(e, b1, x, m);
			rp2_load(x, t4, k);
			rp2_sub(e, x, e, m);
			rp2_add(z, b1, b2, m);
			/* t1 = t1 - 3b'z1z2 and t0 = 3 * t0. */
			rp2_sub(b1, b1, b2, m);
			rp2_add(x, b0, b0, m);
			rp2_add(b0, x, b0, m);
			/* The negated t4 is at most m, as factors need. */
			f[0] = rns_vneg(e[0], m);
			f[1] = rns_vneg(e[1], m);
			rp2_mul(g, b3, b1, f, y, n, m, v);
			rp2_stored(u[0], k, g);
			rp2_mul(g, y, b0, b1, z, n, m, v);
			rp2_stored(u[1], k, g);
			rp2_mul(g, z, e, b0, b3, n, m, v);
			rp2_stored(u[2], k, g);
		}
		c[0] = r->x[0];
		c[1] = r->x[1];
		c[2] = r->y[0];
		c[3] = r->y[1];
		c[4] = r->z[0];
		c[5] = r->z[1];
		RNS_RDCV(c, a, 6);
		r->coord = EC_PROJC;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free_all(t0, t1, t2, t3, t4, t5, w, h);
		dv2_free_all(u[0], u[1], u[2], u[3], u[4], u[5]);
	}
}

void ep2_addm_low(ep2_t r, const ep2_t p, const ep2_t q) {
	ctx_t *ctx = core_get();
	const int d = EPX_LOW_D;
	fp2_t t0, t1, t2, t3, t5, w, h;
	dv2_t u[5];
	dig_t *c[10], *a[10];
	rp2_t x, y, z, e, f, g, b0, b1, b2, b3;
	__m512i m, v;
	int b, s, n;

	fp2_null_all(t0, t1, t2, t3, t5, w, h);
	dv2_null_all(u[0], u[1], u[2], u[3], u[4]);

	RLC_TRY {
		fp2_new_all(t0, t1, t2, t3, t5, w, h);
		dv2_new_all(u[0], u[1], u[2], u[3], u[4]);

		rns_nor(&s, &n);
		b = EPX_LOW_K(ctx, s, n);
		for (int i = 0; i < 5; i++) {
			a[2 * i] = u[i][0];
			a[2 * i + 1] = u[i][1];
		}
		/* x1 * x2, y1 * y2, (x1 + y1) * (x2 + y2), y2 * z1 and x2 * z1. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			rp2_load(x, p->x, k);
			rp2_load(y, p->y, k);
			rp2_load(z, p->z, k);
			rp2_load(e, q->x, k);
			rp2_load(f, q->y, k);
			rp2_mul(b0, x, e, NULL, NULL, n, m, v);
			rp2_stored(u[0], k, b0);
			rp2_mul(b0, y, f, NULL, NULL, n, m, v);
			rp2_stored(u[1], k, b0);
			rp2_add(b1, x, y, m);
			rp2_add(b2, e, f, m);
			rp2_mul(b0, b1, b2, NULL, NULL, n, m, v);
			rp2_stored(u[2], k, b0);
			rp2_mul(b0, f, z, NULL, NULL, n, m, v);
			rp2_stored(u[3], k, b0);
			rp2_mul(b0, e, z, NULL, NULL, n, m, v);
			rp2_stored(u[4], k, b0);
		}
		c[0] = t0[0];
		c[1] = t0[1];
		c[2] = t1[0];
		c[3] = t1[1];
		c[4] = t3[0];
		c[5] = t3[1];
		c[6] = t2[0];
		c[7] = t2[1];
		c[8] = t5[0];
		c[9] = t5[1];
		RNS_RDCV(c, a, 10);
		/* 3 * z1 and 3 * (x2 * z1 + x1), both multiplied by b', unless that is
		 * done lane-wise. */
		if (b == 0) {
			for (size_t k = 0; k < RNS_NE; k++) {
				m = rns_load(ctx->rns.m, k);
				rp2_load(z, p->z, k);
				rp2_add(e, z, z, m);
				rp2_add(e, e, z, m);
				rp2_store(w, k, e);
				rp2_load(x, t5, k);
				rp2_load(y, p->x, k);
				rp2_add(x, x, y, m);
				rp2_add(e, x, x, m);
				rp2_add(e, e, x, m);
				rp2_store(h, k, e);
			}
			ep2_curve_mul_b(w, w);
			ep2_curve_mul_b(h, h);
		}
		/* x3 = t3 * t1 - t4 * y3, y3 = y3 * t0 + t1 * z3 and z3 = z3 * t4 +
		 * t0 * t3, after the additions of the formula. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			rp2_load(b0, t0, k);
			rp2_load(b1, t1, k);
			rp2_load(b3, t3, k);
			if (b) {
				/* 3b' * z1 and 3b' * (t5 + x1). */
				rp2_load(z, p->z, k);
				rp2_mulk(b2, z, b, s, n, d, m);
				rp2_load(x, t5, k);
				rp2_load(e, p->x, k);
				rp2_add(x, x, e, m);
				rp2_mulk(y, x, b, s, n, d, m);
			} else {
				rp2_load(b2, w, k);
				rp2_load(y, h, k);
			}
			/* t3 = t3 - (t0 + t1), t4 = y2 * z1 + y1, z3 = t1 + 3b'z1. */
			rp2_add(e, b0, b1, m);
			rp2_sub(b3, b3, e, m);
			rp2_load(x, t2, k);
			rp2_load(e, p->y, k);
			rp2_add(e, x, e, m);
			rp2_add(z, b1, b2, m);
			/* t1 = t1 - 3b'z1 and t0 = 3 * t0. */
			rp2_sub(b1, b1, b2, m);
			rp2_add(x, b0, b0, m);
			rp2_add(b0, x, b0, m);
			/* The negated t4 is at most m, as factors need. */
			f[0] = rns_vneg(e[0], m);
			f[1] = rns_vneg(e[1], m);
			rp2_mul(g, b3, b1, f, y, n, m, v);
			rp2_stored(u[0], k, g);
			rp2_mul(g, y, b0, b1, z, n, m, v);
			rp2_stored(u[1], k, g);
			rp2_mul(g, z, e, b0, b3, n, m, v);
			rp2_stored(u[2], k, g);
		}
		c[0] = r->x[0];
		c[1] = r->x[1];
		c[2] = r->y[0];
		c[3] = r->y[1];
		c[4] = r->z[0];
		c[5] = r->z[1];
		RNS_RDCV(c, a, 6);
		r->coord = EC_PROJC;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free_all(t0, t1, t2, t3, t5, w, h);
		dv2_free_all(u[0], u[1], u[2], u[3], u[4]);
	}
}

#endif /* FP_RDC == FP_RENUS */
