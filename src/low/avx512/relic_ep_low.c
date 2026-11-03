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
 * Implementation of the low-level prime elliptic curve functions in a Residue
 * Number System with AVX-512 IFMA.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_low.h"

#if FP_RDC == FP_RENUS

#include "relic_fp_rns_avx.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Largest b for which a doubling computes 3b * Z by lane-wise modular
 * additions, so that 3b * Z^2 joins the first batch of products. The chain of
 * additions grows with the bits of 3b, so larger b keep the separate step.
 */
#define EP_LOW_B		16

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/* The point operations run residue-wise around their reductions, in vectors,
 * so the additions of the formulas need no calls. */

void ep_dblp_low(ep_t r, const ep_t p) {
	ctx_t *ctx = core_get();
	const int b = (ctx->ep_b_dig <= EP_LOW_B ? 3 * (int)ctx->ep_b_dig : 0);
	fp_t t0, t1, t2, t3, t5;
	dv_t u[4];
	dig_t *c[4], *a[4];
	__m512i m, v, x, y, z, e, f, g;

	fp_null_all(t0, t1, t2, t3, t5);
	dv_null_all(u[0], u[1], u[2], u[3]);

	RLC_TRY {
		fp_new_all(t0, t1, t2, t3, t5);
		dv_new_all(u[0], u[1], u[2], u[3]);

		for (int i = 0; i < 4; i++) {
			a[i] = u[i];
		}
		/* Y^2, X * Y, Y * Z and Z^2, or 3b * Z^2 for a small b, with 3b * Z by
		 * lane-wise additions, which saves a step between the batches. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			x = rns_load(p->x, k);
			y = rns_load(p->y, k);
			z = rns_load(p->z, k);
			rns_store(u[0], k, rns_vmul(y, y, m, v));
			rns_store(u[1], k, rns_vmul(x, y, m, v));
			rns_store(u[2], k, rns_vmul(y, z, m, v));
			rns_store(u[3], k, rns_vmul(z, b ? rns_vsml(z, b, m) : z, m, v));
		}
		c[0] = t0;
		c[1] = t3;
		c[2] = t1;
		c[3] = t2;
		RNS_RDCV(c, a, 4);
		/* 3b * Z^2 otherwise. */
		if (b == 0) {
			for (size_t k = 0; k < RNS_NE; k++) {
				m = rns_load(ctx->rns.m, k);
				z = rns_load(t2, k);
				rns_store(t5, k, rns_vadd(rns_vadd(z, z, m), z, m));
			}
			ep_curve_mul_b(t2, t5);
		}
		/* y3 = t2 * z3 + t4 * (t0 + t2), z3 = t1 * z3 and x3 = 2 * t4 * t3 for
		 * z3 = 8 * t0 and t4 = t0 - 3 * t2. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			x = rns_load(t0, k);
			y = rns_load(t2, k);
			z = rns_vadd(x, x, m);
			z = rns_vadd(z, z, m);
			z = rns_vadd(z, z, m);
			e = rns_vadd(x, y, m);
			f = rns_vsub(x, rns_vadd(rns_vadd(y, y, m), y, m), m);
			rns_store(u[0], k, rns_vmul2(y, z, f, e, m, v));
			rns_store(u[1], k, rns_vmul(rns_load(t1, k), z, m, v));
			g = rns_vadd(f, f, m);
			rns_store(u[2], k, rns_vmul(g, rns_load(t3, k), m, v));
		}
		c[0] = r->y;
		c[1] = r->z;
		c[2] = r->x;
		RNS_RDCV(c, a, 3);
		r->coord = EC_PROJC;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free_all(t0, t1, t2, t3, t5);
		dv_free_all(u[0], u[1], u[2], u[3]);
	}
}

void ep_addp_low(ep_t r, const ep_t p, const ep_t q) {
	ctx_t *ctx = core_get();
	fp_t t0, t1, t2, t3, t4, t5, w, h;
	dv_t u[6];
	dig_t *c[6], *a[6];
	__m512i m, v, x, y, z, e, f, g, b0, b1, b2, b3;

	fp_null_all(t0, t1, t2, t3, t4, t5, w, h);
	dv_null_all(u[0], u[1], u[2], u[3], u[4], u[5]);

	RLC_TRY {
		fp_new_all(t0, t1, t2, t3, t4, t5, w, h);
		dv_new_all(u[0], u[1], u[2], u[3], u[4], u[5]);

		for (int i = 0; i < 6; i++) {
			a[i] = u[i];
		}
		/* x1 * x2, y1 * y2, z1 * z2, (x1 + y1) * (x2 + y2),
		 * (y1 + z1) * (y2 + z2) and (x1 + z1) * (x2 + z2). */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			x = rns_load(p->x, k);
			y = rns_load(p->y, k);
			z = rns_load(p->z, k);
			e = rns_load(q->x, k);
			f = rns_load(q->y, k);
			g = rns_load(q->z, k);
			rns_store(u[0], k, rns_vmul(x, e, m, v));
			rns_store(u[1], k, rns_vmul(y, f, m, v));
			rns_store(u[2], k, rns_vmul(z, g, m, v));
			rns_store(u[3], k, rns_vmul(rns_vadd(x, y, m), rns_vadd(e, f, m), m,
					v));
			rns_store(u[4], k, rns_vmul(rns_vadd(y, z, m), rns_vadd(f, g, m), m,
					v));
			rns_store(u[5], k, rns_vmul(rns_vadd(x, z, m), rns_vadd(e, g, m), m,
					v));
		}
		c[0] = t0;
		c[1] = t1;
		c[2] = t2;
		c[3] = t3;
		c[4] = t4;
		c[5] = t5;
		RNS_RDCV(c, a, 6);
		/* 3 * z1 * z2 and 3 * (x1 * z2 + x2 * z1), both multiplied by b. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			z = rns_load(t2, k);
			rns_store(w, k, rns_vadd(rns_vadd(z, z, m), z, m));
			x = rns_vsub(rns_load(t5, k), rns_vadd(rns_load(t0, k), z, m), m);
			rns_store(h, k, rns_vadd(rns_vadd(x, x, m), x, m));
		}
		ep_curve_mul_b(w, w);
		ep_curve_mul_b(h, h);
		/* x3 = t3 * t1 - t4 * y3, y3 = y3 * t0 + t1 * z3 and z3 = z3 * t4 +
		 * t0 * t3, after the additions of the formula. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			b0 = rns_load(t0, k);
			b1 = rns_load(t1, k);
			b2 = rns_load(w, k);
			b3 = rns_load(t3, k);
			/* t3 = t3 - (t0 + t1), t4 = t4 - (t1 + t2), z3 = t1 + 3bz1z2. */
			b3 = rns_vsub(b3, rns_vadd(b0, b1, m), m);
			e = rns_vsub(rns_load(t4, k), rns_vadd(b1, rns_load(t2, k), m), m);
			z = rns_vadd(b1, b2, m);
			/* t1 = t1 - 3bz1z2 and t0 = 3 * t0. */
			b1 = rns_vsub(b1, b2, m);
			b0 = rns_vadd(rns_vadd(b0, b0, m), b0, m);
			y = rns_load(h, k);
			rns_store(u[0], k, rns_vmul2(b3, b1, rns_vneg(e, m), y, m, v));
			rns_store(u[1], k, rns_vmul2(y, b0, b1, z, m, v));
			rns_store(u[2], k, rns_vmul2(z, e, b0, b3, m, v));
		}
		c[0] = r->x;
		c[1] = r->y;
		c[2] = r->z;
		RNS_RDCV(c, a, 3);
		r->coord = EC_PROJC;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free_all(t0, t1, t2, t3, t4, t5, w, h);
		dv_free_all(u[0], u[1], u[2], u[3], u[4], u[5]);
	}
}

void ep_addm_low(ep_t r, const ep_t p, const ep_t q) {
	ctx_t *ctx = core_get();
	fp_t t0, t1, t2, t3, t5, w, h;
	dv_t u[5];
	dig_t *c[5], *a[5];
	__m512i m, v, x, y, z, e, f, b0, b1, b2, b3;

	fp_null_all(t0, t1, t2, t3, t5, w, h);
	dv_null_all(u[0], u[1], u[2], u[3], u[4]);

	RLC_TRY {
		fp_new_all(t0, t1, t2, t3, t5, w, h);
		dv_new_all(u[0], u[1], u[2], u[3], u[4]);

		for (int i = 0; i < 5; i++) {
			a[i] = u[i];
		}
		/* x1 * x2, y1 * y2, (x1 + y1) * (x2 + y2), y2 * z1 and x2 * z1. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			x = rns_load(p->x, k);
			y = rns_load(p->y, k);
			z = rns_load(p->z, k);
			e = rns_load(q->x, k);
			f = rns_load(q->y, k);
			rns_store(u[0], k, rns_vmul(x, e, m, v));
			rns_store(u[1], k, rns_vmul(y, f, m, v));
			rns_store(u[2], k, rns_vmul(rns_vadd(x, y, m), rns_vadd(e, f, m), m,
					v));
			rns_store(u[3], k, rns_vmul(f, z, m, v));
			rns_store(u[4], k, rns_vmul(e, z, m, v));
		}
		c[0] = t0;
		c[1] = t1;
		c[2] = t3;
		c[3] = t2;
		c[4] = t5;
		RNS_RDCV(c, a, 5);
		/* 3 * z1 and 3 * (x2 * z1 + x1), both multiplied by b. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			z = rns_load(p->z, k);
			rns_store(w, k, rns_vadd(rns_vadd(z, z, m), z, m));
			x = rns_vadd(rns_load(t5, k), rns_load(p->x, k), m);
			rns_store(h, k, rns_vadd(rns_vadd(x, x, m), x, m));
		}
		ep_curve_mul_b(w, w);
		ep_curve_mul_b(h, h);
		/* x3 = t3 * t1 - t4 * y3, y3 = y3 * t0 + t1 * z3 and z3 = z3 * t4 +
		 * t0 * t3, after the additions of the formula. */
		for (size_t k = 0; k < RNS_NE; k++) {
			m = rns_load(ctx->rns.m, k);
			v = rns_load(ctx->rns.iv, k);
			b0 = rns_load(t0, k);
			b1 = rns_load(t1, k);
			b2 = rns_load(w, k);
			b3 = rns_load(t3, k);
			/* t3 = t3 - (t0 + t1), t4 = y2 * z1 + y1, z3 = t1 + 3bz1. */
			b3 = rns_vsub(b3, rns_vadd(b0, b1, m), m);
			e = rns_vadd(rns_load(t2, k), rns_load(p->y, k), m);
			z = rns_vadd(b1, b2, m);
			/* t1 = t1 - 3bz1 and t0 = 3 * t0. */
			b1 = rns_vsub(b1, b2, m);
			b0 = rns_vadd(rns_vadd(b0, b0, m), b0, m);
			y = rns_load(h, k);
			rns_store(u[0], k, rns_vmul2(b3, b1, rns_vneg(e, m), y, m, v));
			rns_store(u[1], k, rns_vmul2(y, b0, b1, z, m, v));
			rns_store(u[2], k, rns_vmul2(z, e, b0, b3, m, v));
		}
		c[0] = r->x;
		c[1] = r->y;
		c[2] = r->z;
		RNS_RDCV(c, a, 3);
		r->coord = EC_PROJC;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free_all(t0, t1, t2, t3, t5, w, h);
		dv_free_all(u[0], u[1], u[2], u[3], u[4]);
	}
}

#endif /* FP_RDC == FP_RENUS */
