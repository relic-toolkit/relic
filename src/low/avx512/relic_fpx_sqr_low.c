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
 * Implementation of the low-level extension field squaring in a Residue Number
 * System with AVX-512 IFMA.
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

/* Fp3 is the portable version. */
#include "../easy/relic_fpx_sqr_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_sqrn_low(dv2_t c, const fp2_t a) {
	ctx_t *ctx = core_get();
	const dig_t *_m = ctx->rns.m, *_u = ctx->rns.u;
	const int q = -fp_prime_get_qnr();
	__m512i m, u, a0, a1, t;

	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(_m, k);
		u = rns_load(_u, k);
		a0 = rns_load(a[0], k);
		a1 = rns_load(a[1], k);
		/* c_1 = 2 * a_0 * a_1. */
		rns_store(c[1], k, rns_vmul(rns_vadd(a0, a0, m), a1, m, u));
		/* c_0 = a_0^2 + u^2 * a_1^2, with u^2 = -q. */
		if (q == 1) {
			t = rns_vmul(rns_vadd(a0, a1, m), rns_vsub(a0, a1, m), m, u);
		} else {
			t = _mm512_setzero_si512();
			for (int i = 0; i < q; i++) {
				t = rns_vsub(t, a1, m);
			}
			t = rns_vmul2(a0, a0, t, a1, m, u);
		}
		rns_store(c[0], k, t);
	}
}

void fp12_sqrn_low(dv12_t c, const fp12_t a) {
	ctx_t *ctx = core_get();
	rp6_t a0, a1, u0, u1;
	rp2_t t;
	__m512i m, u;
	int s, q;

	rns_nor(&s, &q);
	/* The whole square is computed residue-wise, vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		u = rns_load(ctx->rns.u, k);
		for (int j = 0; j < 3; j++) {
			for (int l = 0; l < 2; l++) {
				a0.v[j].v[l] = rns_load(a[0][j][l], k);
				a1.v[j].v[l] = rns_load(a[1][j][l], k);
			}
		}
		/* Complex squaring, with v * (x_0, x_1, x_2) = (v^3 * x_2, x_0, x_1):
		 * c_0 = (a_0 + a_1)(a_0 + v * a_1) - a_0a_1 - v * a_0a_1. */
		u0 = rp6_mul(a0, a1, s, q, m, u);
		u1 = a1;
		u1.v[0] = rp2_nor(a1.v[2], s, q, m);
		u1.v[1] = a1.v[0];
		u1.v[2] = a1.v[1];
		u1 = rp6_mul(rp6_add(a0, a1, m), rp6_add(a0, u1, m), s, q, m, u);
		u1 = rp6_sub(u1, u0, m);
		t = rp2_nor(u0.v[2], s, q, m);
		u1.v[0] = rp2_sub(u1.v[0], t, m);
		u1.v[1] = rp2_sub(u1.v[1], u0.v[0], m);
		u1.v[2] = rp2_sub(u1.v[2], u0.v[1], m);
		/* c_1 = 2 * a_0a_1. */
		u0 = rp6_add(u0, u0, m);
		for (int j = 0; j < 3; j++) {
			for (int l = 0; l < 2; l++) {
				rns_store(c[0][j][l], k, u1.v[j].v[l]);
				rns_store(c[1][j][l], k, u0.v[j].v[l]);
			}
		}
	}
}

void fp2_sqrm_low(fp2_t c, const fp2_t a) {
	rlc_align dv2_t t;

	dv2_null(t);

	RLC_TRY {
		dv2_new(t);
		fp2_sqrn_low(t, a);
		fp2_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free(t);
	}
}
