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
	const dig_t *_m = ctx->rns.m, *_i = ctx->rns.iv;
	const int q = -fp_prime_get_qnr();
	__m512i m, v, a0, a1, t;

	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(_m, k);
		v = rns_load(_i, k);
		a0 = rns_load(a[0], k);
		a1 = rns_load(a[1], k);
		/* c_1 = 2 * a_0 * a_1: a factor below 2m gives a product below
		 * 2m^2 / 2^52 + m < 2m, so the sum needs no correction. */
		rns_store(c[1], k, rns_vmul(_mm512_add_epi64(a0, a0), a1, m, v));
		/* c_0 = a_0^2 + u^2 * a_1^2, with u^2 = -q. */
		if (q == 1) {
			/* (a_0 + a_1)(a_0 - a_1 + m), with factors below 2m and a product
			 * below 4m^2 / 2^52 + m < 2m. */
			t = rns_vmul(_mm512_add_epi64(a0, a1),
					_mm512_add_epi64(_mm512_sub_epi64(a0, a1), m), m, v);
		} else {
			t = _mm512_setzero_si512();
			for (int i = 0; i < q; i++) {
				t = rns_vsub(t, a1, m);
			}
			t = rns_vmul2(a0, a0, t, a1, m, v);
		}
		rns_store(c[0], k, t);
	}
}

void fp12_sqrn_low(dv12_t c, const fp12_t a) {
	/* The coefficient of w^e, with w^2 = v, is at [I[e]][J[e]]. */
	static const int I[6] = { 0, 1, 0, 1, 0, 1 }, J[6] = { 0, 0, 1, 1, 2, 2 };
	ctx_t *ctx = core_get();
	const __m512i z = _mm512_setzero_si512();
	rp2_t x[6], y[12], l[6], h[6];
	__m512i t[12], m, v;
	int s, q;

	rns_nor(&s, &q);
	/* The whole square is computed residue-wise, vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		v = rns_load(ctx->rns.iv, k);
		/* Loops are unrolled fully, so that all indices are constants and the
		 * sums stay in registers: GCC and clang do not unroll them alone. */
#pragma GCC unroll 6
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				x[e][j] = y[e][j] = rns_load(a[I[e]][J[e]][j], k);
				l[e][j] = h[e][j] = z;
			}
			/* With w^6 = v^3 = s + i, products wrapping around use y * w^6. */
			rp2_nor(y[e + 6], y[e], s, q, m);
		}
#pragma GCC unroll 12
		for (int e = 0; e < 12; e++) {
			t[e] = rns_vneg(rns_vsml(y[e][1], -q, m), m);
		}
		/* Schoolbook square in w: the products off the diagonal are summed and
		 * doubled, then those on it are added. Each output adds at most 6
		 * products of residues at most m < 2^50 off the diagonal and 2 on it,
		 * so the halves of the sums stay below 2^56, and the result is at most
		 * 14m / 4 + m, brought below 4m by one correction. */
#pragma GCC unroll 6
		for (int e1 = 0; e1 < 6; e1++) {
#pragma GCC unroll 6
			for (int e2 = e1 + 1; e2 < 6; e2++) {
				int e = e1 + e2, f = e2 + (e < 6 ? 0 : 6);
				rp2_mac(l[e % 6], h[e % 6], x[e1], y[f], t[f]);
			}
		}
#pragma GCC unroll 6
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				l[e][j] = _mm512_slli_epi64(l[e][j], 1);
				h[e][j] = _mm512_slli_epi64(h[e][j], 1);
			}
		}
#pragma GCC unroll 6
		for (int e1 = 0; e1 < 6; e1++) {
			int e = 2 * e1, f = e1 + (e < 6 ? 0 : 6);
			rp2_mac(l[e % 6], h[e % 6], x[e1], y[f], t[f]);
		}
#pragma GCC unroll 6
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				l[e][j] = rns_vcrt(rns_vmon(l[e][j], h[e][j], m, v),
						rns_vdv(m));
				rns_store(c[I[e]][J[e]][j], k, l[e][j]);
			}
		}
	}
}

void fp12_sqrc_low(dv12_t c, const fp12_t a, int pck) {
	/* For each pair, the positions (i, j) of x, y and of the results
	 * x^2 + E * y^2 and 2 * x * y, the latter times E for the second pair. */
	static const int P[3][4][2] = {
		{{0, 0}, {1, 1}, {0, 0}, {1, 1}},
		{{0, 1}, {1, 2}, {0, 2}, {1, 0}},
		{{1, 0}, {0, 2}, {0, 1}, {1, 2}}
	};
	ctx_t *ctx = core_get();
	rp2_t x, y, a0, a1, c0, c1;
	__m512i m, v, k0, k1;
	int s, q;

	rns_nor(&s, &q);
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		v = rns_load(ctx->rns.iv, k);
		/* k1 = 2 and k0 = -2, from the residues of one. */
		k1 = rns_load(ctx->one, k);
		k1 = rns_vadd(k1, k1, m);
		k0 = rns_vneg(k1, m);
#pragma GCC unroll 3
		for (int p = 0; p < 3; p++) {
			/* Compressed squaring skips the first pair. */
			if (pck && p == 0) {
				continue;
			}
			for (int l = 0; l < 2; l++) {
				x[l] = rns_load(a[P[p][0][0]][P[p][0][1]][l], k);
				y[l] = rns_load(a[P[p][1][0]][P[p][1][1]][l], k);
				a0[l] = rns_load(a[P[p][2][0]][P[p][2][1]][l], k);
				a1[l] = rns_load(a[P[p][3][0]][P[p][3][1]][l], k);
			}
			/* c_0j = 3 * t_0j - 2 * a_0j and c_1j = 3 * t_1j + 2 * a_1j,
			 * reduced once. */
			rp4_sqrf(c0, c1, x, y, a0, a1, k0, k1, p == 1, s, q, m, v);
			for (int l = 0; l < 2; l++) {
				rns_store(c[P[p][2][0]][P[p][2][1]][l], k, c0[l]);
				rns_store(c[P[p][3][0]][P[p][3][1]][l], k, c1[l]);
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
