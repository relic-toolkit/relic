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
 * Implementation of the low-level extension field multiplication in a Residue
 * Number System with AVX-512 IFMA. Each component of a product in Fp2 adds two
 * products of residues before a single Montgomery reduction.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fp_rns_avx.h"

#define FP2_ASM
#define FP12_ASM

/* Fp3 and the multiplication by a digit are the portable versions. */
#include "../easy/relic_fpx_mul_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_muln_low(dv2_t c, const fp2_t a, const fp2_t b) {
	ctx_t *ctx = core_get();
	const dig_t *_m = ctx->rns.m, *_u = ctx->rns.u;
	const int q = -fp_prime_get_qnr();
	__m512i m, u, a0, a1, b0, b1, t;

	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(_m, k);
		u = rns_load(_u, k);
		a0 = rns_load(a[0], k);
		a1 = rns_load(a[1], k);
		b0 = rns_load(b[0], k);
		b1 = rns_load(b[1], k);
		/* c_1 = a_0 * b_1 + a_1 * b_0. */
		rns_store(c[1], k, rns_vmul2(a0, b1, a1, b0, m, u));
		/* c_0 = a_0 * b_0 + u^2 * a_1 * b_1, with u^2 = -q. */
		t = rns_vneg(a1, m);
		if (q == 1) {
			t = rns_vmul2(a0, b0, t, b1, m, u);
		} else {
			t = rns_vmul(t, b1, m, u);
			b1 = rns_vmul(a0, b0, m, u);
			for (int i = 0; i < q; i++) {
				b1 = rns_vadd(b1, t, m);
			}
			t = b1;
		}
		rns_store(c[0], k, t);
	}
}

void fp12_muln_low(dv12_t c, const fp12_t a, const fp12_t b) {
	/* The coefficient of w^e, with w^2 = v, is at [I[e]][J[e]]. */
	static const int I[6] = { 0, 1, 0, 1, 0, 1 }, J[6] = { 0, 0, 1, 1, 2, 2 };
	ctx_t *ctx = core_get();
	const __m512i z = _mm512_setzero_si512();
	rp2_t x[6], y[12], l[6], h[6];
	__m512i t[12], m, u;
	int s, q;

	rns_nor(&s, &q);
	/* The whole product is computed residue-wise, vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		u = rns_load(ctx->rns.u, k);
#pragma GCC unroll 6
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				x[e][j] = rns_load(a[I[e]][J[e]][j], k);
				y[e][j] = rns_load(b[I[e]][J[e]][j], k);
				l[e][j] = h[e][j] = z;
			}
			/* With w^6 = v^3 = s + i, products wrapping around use y * w^6. */
			rp2_nor(y[e + 6], y[e], s, q, m);
		}
#pragma GCC unroll 12
		for (int e = 0; e < 12; e++) {
			t[e] = rns_vneg(rns_vsml(y[e][1], -q, m), m);
		}
		/* Schoolbook product in w: each output adds 12 products of residues
		 * below m < 2^52, so the halves of the sums stay below 2^56. */
#pragma GCC unroll 6
		for (int e1 = 0; e1 < 6; e1++) {
#pragma GCC unroll 6
			for (int e2 = 0; e2 < 6; e2++) {
				int e = e1 + e2, f = e2 + (e < 6 ? 0 : 6);
				rp2_mac(l[e % 6], h[e % 6], x[e1], y[f], t[f]);
			}
		}
#pragma GCC unroll 6
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				l[e][j] = rns_vred(l[e][j], h[e][j], m, u);
				rns_store(c[I[e]][J[e]][j], k, l[e][j]);
			}
		}
	}
}

void fp12_muld_low(dv12_t c, const fp12_t a, const fp12_t b) {
	/* The coefficient of w^e, with w^2 = v, is at [I[e]][J[e]]. */
	static const int I[6] = { 0, 1, 0, 1, 0, 1 }, J[6] = { 0, 0, 1, 1, 2, 2 };
	/* The nonzero coefficients of b are those of w^0, w^3 and w^1 for a
	 * D-type twist, or w^2 for an M-type one. */
	const int g = (ep2_curve_is_twist() == RLC_EP_DTYPE ? 1 : 2);
	ctx_t *ctx = core_get();
	const __m512i z = _mm512_setzero_si512();
	rp2_t x[6], y[12], l[6], h[6];
	__m512i t[12], m, u;
	int s, q;

	rns_nor(&s, &q);
	/* The whole product is computed residue-wise, vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		u = rns_load(ctx->rns.u, k);
#pragma GCC unroll 6
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				x[e][j] = rns_load(a[I[e]][J[e]][j], k);
				y[e][j] = rns_load(b[I[e]][J[e]][j], k);
				l[e][j] = h[e][j] = z;
			}
			/* With w^6 = v^3 = s + i, products wrapping around use y * w^6. */
			rp2_nor(y[e + 6], y[e], s, q, m);
		}
#pragma GCC unroll 12
		for (int e = 0; e < 12; e++) {
			t[e] = rns_vneg(rns_vsml(y[e][1], -q, m), m);
		}
		/* Schoolbook product in w over the nonzero coefficients of b: each
		 * output adds 6 products of residues below m < 2^52. */
#pragma GCC unroll 6
		for (int e1 = 0; e1 < 6; e1++) {
#pragma GCC unroll 6
			for (int e2 = 0; e2 < 6; e2++) {
				int e = e1 + e2, f = e2 + (e < 6 ? 0 : 6);
				if (e2 == 0 || e2 == 3 || e2 == g) {
					rp2_mac(l[e % 6], h[e % 6], x[e1], y[f], t[f]);
				}
			}
		}
#pragma GCC unroll 6
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				l[e][j] = rns_vred(l[e][j], h[e][j], m, u);
				rns_store(c[I[e]][J[e]][j], k, l[e][j]);
			}
		}
	}
}

void fp2_mulm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dv2_t t;

	dv2_null(t);

	RLC_TRY {
		dv2_new(t);
		fp2_muln_low(t, a, b);
		fp2_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free(t);
	}
}
