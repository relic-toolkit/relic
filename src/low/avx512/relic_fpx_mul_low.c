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
#define FP3_ASM
#define FP8_ASM
#define FP12_ASM
#define FP16_ASM
#define FP24_ASM

/* The multiplication by a digit is the portable version. */
#include "../easy/relic_fpx_mul_low.c"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines the product without reduction of two elements of an extension field
 * in the basis w^e of D coefficients over Fp2, with w^D the non-residue of Fp2,
 * computed residue-wise as fp12_muln_low() does: each output adds 2D products
 * of residues at most m, so it is at most (D / 2 + 1) * m before the
 * corrections that bring it below 4m.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] DX		- the prefix of unreduced extension field elements.
 * @param[in] D			- the number of coefficients over Fp2.
 * @param[in] D2		- twice the number of coefficients.
 * @param[in] CO		- the macro giving the coefficient of w^e.
 */
#define RNS_FLAT_MULN(F, X, DX, D, D2, CO)									\
	void F(DX##_t c, const X##_t a, const X##_t b) {						\
		ctx_t *ctx = core_get();											\
		const __m512i z = _mm512_setzero_si512();							\
		rp2_t x[D], y[D2], l, h;											\
		__m512i t[D2], m, v;												\
		int s, q;															\
																			\
		rns_nor(&s, &q);													\
		for (size_t k = 0; k < RNS_NE; k++) {								\
			m = rns_load(ctx->rns.m, k);									\
			v = rns_load(ctx->rns.iv, k);									\
			RLC_UNROLL(D)													\
			for (int e = 0; e < D; e++) {									\
				for (int j = 0; j < 2; j++) {								\
					x[e][j] = rns_load(CO(a, e)[j], k);						\
					y[e][j] = rns_load(CO(b, e)[j], k);						\
				}															\
				/* Products wrapping around use y * w^D. */					\
				rp2_nor(y[e + D], y[e], s, q, m);							\
			}																\
			RLC_UNROLL(D2)													\
			for (int e = 0; e < D2; e++) {									\
				t[e] = rns_vneg(rns_vsml(y[e][1], -q, m), m);				\
			}																\
			/* Outputs are computed one at a time, so that only their sums	\
			 * stay in registers. */										\
			RLC_UNROLL(D)													\
			for (int e = 0; e < D; e++) {									\
				l[0] = l[1] = h[0] = h[1] = z;								\
				RLC_UNROLL(D)												\
				for (int e1 = 0; e1 < D; e1++) {							\
					int e2 = (e - e1 + D) % D;								\
					int f = e2 + (e1 + e2 < D ? 0 : D);						\
					rp2_mac(l, h, x[e1], y[f], t[f]);						\
				}															\
				for (int j = 0; j < 2; j++) {								\
					l[j] = rns_vpeel(rns_vmon(l[j], h[j], m, v),			\
							rns_vdv(m), rns_halvings(D / 2 + 1));			\
					rns_store(CO(c, e)[j], k, l[j]);						\
				}															\
			}																\
		}																	\
	}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_muln_low(dv2_t c, const fp2_t a, const fp2_t b) {
	ctx_t *ctx = core_get();
	const dig_t *_m = ctx->rns.m, *_i = ctx->rns.iv;
	const int q = -fp_prime_get_qnr();
	__m512i m, v, a0, a1, b0, b1, t;

	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(_m, k);
		v = rns_load(_i, k);
		a0 = rns_load(a[0], k);
		a1 = rns_load(a[1], k);
		b0 = rns_load(b[0], k);
		b1 = rns_load(b[1], k);
		/* c_1 = a_0 * b_1 + a_1 * b_0. */
		rns_store(c[1], k, rns_vmul2(a0, b1, a1, b0, m, v));
		/* c_0 = a_0 * b_0 + u^2 * a_1 * b_1, with u^2 = -q. */
		t = rns_vneg(a1, m);
		if (q == 1) {
			t = rns_vmul2(a0, b0, t, b1, m, v);
		} else {
			t = rns_vmul(t, b1, m, v);
			b1 = rns_vmul(a0, b0, m, v);
			/* The products are below 2m, and their sums are kept below 4m. */
			for (int i = 0; i < q; i++) {
				b1 = rns_vadd(b1, t, rns_vdv(m));
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
	__m512i t[12], m, v;
	int s, q;

	rns_nor(&s, &q);
	/* The whole product is computed residue-wise, vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		v = rns_load(ctx->rns.iv, k);
		/* Loops are unrolled fully, so that all indices are constants and the
		 * sums stay in registers: GCC and clang do not unroll them alone. */
		RLC_UNROLL(6)
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				x[e][j] = rns_load(a[I[e]][J[e]][j], k);
				y[e][j] = rns_load(b[I[e]][J[e]][j], k);
				l[e][j] = h[e][j] = z;
			}
			/* With w^6 = v^3 = s + i, products wrapping around use y * w^6. */
			rp2_nor(y[e + 6], y[e], s, q, m);
		}
		RLC_UNROLL(12)
		for (int e = 0; e < 12; e++) {
			t[e] = rns_vneg(rns_vsml(y[e][1], -q, m), m);
		}
		/* Schoolbook product in w: each output adds 12 products of residues at
		 * most m < 2^50, so the halves of the sums stay below 2^56, and the
		 * result is at most 12m / 4 + m = 4m with no correction. Outputs are
		 * computed one at a time, so that only their sums stay in registers. */
		RLC_UNROLL(6)
		for (int e = 0; e < 6; e++) {
			RLC_UNROLL(6)
			for (int e1 = 0; e1 < 6; e1++) {
				int e2 = (e - e1 + 6) % 6, f = e2 + (e1 + e2 < 6 ? 0 : 6);
				rp2_mac(l[e], h[e], x[e1], y[f], t[f]);
			}
			for (int j = 0; j < 2; j++) {
				l[e][j] = rns_vmon(l[e][j], h[e][j], m, v);
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
	__m512i t[12], m, v;
	int s, q;

	rns_nor(&s, &q);
	/* The whole product is computed residue-wise, vector by vector. */
	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(ctx->rns.m, k);
		v = rns_load(ctx->rns.iv, k);
		/* Loops are unrolled fully, so that all indices are constants and the
		 * sums stay in registers: GCC and clang do not unroll them alone. */
		RLC_UNROLL(6)
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				x[e][j] = rns_load(a[I[e]][J[e]][j], k);
				y[e][j] = rns_load(b[I[e]][J[e]][j], k);
				l[e][j] = h[e][j] = z;
			}
			/* With w^6 = v^3 = s + i, products wrapping around use y * w^6. */
			rp2_nor(y[e + 6], y[e], s, q, m);
		}
		RLC_UNROLL(12)
		for (int e = 0; e < 12; e++) {
			t[e] = rns_vneg(rns_vsml(y[e][1], -q, m), m);
		}
		/* Schoolbook product in w over the nonzero coefficients of b: each
		 * output adds 6 products of residues at most m < 2^50, and the result
		 * is at most 6m / 4 + m < 4m with no correction. Outputs are computed
		 * one at a time, so that only their sums stay in registers. */
		RLC_UNROLL(6)
		for (int e = 0; e < 6; e++) {
			RLC_UNROLL(6)
			for (int e1 = 0; e1 < 6; e1++) {
				int e2 = (e - e1 + 6) % 6, f = e2 + (e1 + e2 < 6 ? 0 : 6);
				if (e2 == 0 || e2 == 3 || e2 == g) {
					rp2_mac(l[e], h[e], x[e1], y[f], t[f]);
				}
			}
			for (int j = 0; j < 2; j++) {
				l[e][j] = rns_vmon(l[e][j], h[e][j], m, v);
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

void fp3_muln_low(dv3_t c, const fp3_t a, const fp3_t b) {
	ctx_t *ctx = core_get();
	const dig_t *_m = ctx->rns.m, *_i = ctx->rns.iv;
	const int w = fp_prime_get_cnr();
	__m512i m, v, a0, a1, a2, b0, b1, b2, t1, t2;

	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(_m, k);
		v = rns_load(_i, k);
		a0 = rns_load(a[0], k);
		a1 = rns_load(a[1], k);
		a2 = rns_load(a[2], k);
		b0 = rns_load(b[0], k);
		b1 = rns_load(b[1], k);
		b2 = rns_load(b[2], k);
		/* t_i = w * a_i for the products wrapping around, with u^3 = w. */
		t1 = rns_vsml(a1, (w < 0 ? -w : w), m);
		t2 = rns_vsml(a2, (w < 0 ? -w : w), m);
		if (w < 0) {
			t1 = rns_vneg(t1, m);
			t2 = rns_vneg(t2, m);
		}
		/* Schoolbook product: each output adds 3 products of residues at
		 * most m, so it is at most 7m / 4 with no correction. */
		rns_store(c[0], k, rns_vmul3(a0, b0, t1, b2, t2, b1, m, v));
		rns_store(c[1], k, rns_vmul3(a0, b1, a1, b0, t2, b2, m, v));
		rns_store(c[2], k, rns_vmul3(a0, b2, a1, b1, a2, b0, m, v));
	}
}

void fp3_mulm_low(fp3_t c, const fp3_t a, const fp3_t b) {
	rlc_align dv3_t t;

	dv3_null(t);

	RLC_TRY {
		dv3_new(t);
		fp3_muln_low(t, a, b);
		fp3_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv3_free(t);
	}
}

RNS_FLAT_MULN(fp8_muln_low, fp8, dv8, 4, 8, RNS_CO8)

RNS_FLAT_MULN(fp16_muln_low, fp16, dv16, 8, 16, RNS_CO16)

RNS_FLAT_MULN(fp24_muln_low, fp24, dv24, 12, 24, RNS_CO24)
