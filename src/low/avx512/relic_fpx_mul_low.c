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
		t = rns_vsub(_mm512_setzero_si512(), a1, m);
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
	ctx_t *ctx = core_get();
	rp6_t a0, a1, b0, b1, u0, u1, u2;
	rp2_t t;
	__m512i m, u;
	int s, q;

	rns_nor(&s, &q);
	/* The whole product is computed residue-wise, vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		u = rns_load(ctx->rns.u, k);
		for (int j = 0; j < 3; j++) {
			for (int l = 0; l < 2; l++) {
				a0[j][l] = rns_load(a[0][j][l], k);
				a1[j][l] = rns_load(a[1][j][l], k);
				b0[j][l] = rns_load(b[0][j][l], k);
				b1[j][l] = rns_load(b[1][j][l], k);
			}
		}
		/* Karatsuba algorithm. */
		rp6_mul(u0, a0, b0, s, q, m, u);
		rp6_mul(u1, a1, b1, s, q, m, u);
		rp6_add(a0, a0, a1, m);
		rp6_add(b0, b0, b1, m);
		rp6_mul(u2, a0, b0, s, q, m, u);
		/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1. */
		rp6_add(a1, u0, u1, m);
		rp6_sub(u2, u2, a1, m);
		/* c_0 = a_0b_0 + v * a_1b_1, with v * (x_0, x_1, x_2) = (v^3 * x_2,
		 * x_0, x_1). */
		rp2_nor(t, u1[2], s, q, m);
		rp2_add(u0[2], u0[2], u1[1], m);
		rp2_add(u0[1], u0[1], u1[0], m);
		rp2_add(u0[0], u0[0], t, m);
		for (int j = 0; j < 3; j++) {
			for (int l = 0; l < 2; l++) {
				rns_store(c[0][j][l], k, u0[j][l]);
				rns_store(c[1][j][l], k, u2[j][l]);
			}
		}
	}
}

void fp12_muld_low(dv12_t c, const fp12_t a, const fp12_t b) {
	ctx_t *ctx = core_get();
	const int d = (ep2_curve_is_twist() == RLC_EP_DTYPE);
	rp6_t a0, a1, u0, u1, u2;
	rp2_t b0, b1, b2, t;
	__m512i m, u;
	int s, q;

	rns_nor(&s, &q);
	/* The nonzero components of b are b_00 and b_11, with b_10 for a D-type
	 * twist and b_01 for an M-type one; the product is computed residue-wise,
	 * vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		u = rns_load(ctx->rns.u, k);
		for (int j = 0; j < 3; j++) {
			for (int l = 0; l < 2; l++) {
				a0[j][l] = rns_load(a[0][j][l], k);
				a1[j][l] = rns_load(a[1][j][l], k);
			}
		}
		for (int l = 0; l < 2; l++) {
			b0[l] = rns_load(b[0][0][l], k);
			b1[l] = rns_load(b[1][1][l], k);
			b2[l] = rns_load(d ? b[1][0][l] : b[0][1][l], k);
		}
		if (d) {
			/* u_0 = a_0 * b_00, u_1 = a_1 * (b_10 + b_11 * v). */
			for (int j = 0; j < 3; j++) {
				rp2_mul(u0[j], a0[j], b0, q, m, u);
			}
			rp6_muld(u1, a1, b2, b1, s, q, m, u);
			rp2_add(b0, b0, b2, m);
		} else {
			/* u_0 = a_0 * (b_00 + b_01 * v), u_1 = a_1 * b_11 * v. */
			rp6_muld(u0, a0, b0, b2, s, q, m, u);
			rp2_mul(t, a1[2], b1, q, m, u);
			rp2_nor(u1[0], t, s, q, m);
			rp2_mul(u1[1], a1[0], b1, q, m, u);
			rp2_mul(u1[2], a1[1], b1, q, m, u);
			rp2_add(b1, b1, b2, m);
		}
		/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1, with the components
		 * of b_0 + b_1 now in b0 and b1. */
		rp6_add(a0, a0, a1, m);
		rp6_muld(u2, a0, b0, b1, s, q, m, u);
		rp6_add(a1, u0, u1, m);
		rp6_sub(u2, u2, a1, m);
		/* c_0 = a_0b_0 + v * a_1b_1, with v * (x_0, x_1, x_2) = (v^3 * x_2,
		 * x_0, x_1). */
		rp2_nor(t, u1[2], s, q, m);
		rp2_add(u0[2], u0[2], u1[1], m);
		rp2_add(u0[1], u0[1], u1[0], m);
		rp2_add(u0[0], u0[0], t, m);
		for (int j = 0; j < 3; j++) {
			for (int l = 0; l < 2; l++) {
				rns_store(c[0][j][l], k, u0[j][l]);
				rns_store(c[1][j][l], k, u2[j][l]);
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
