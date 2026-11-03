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
#define FP3_ASM
#define FP8_ASM
#define FP12_ASM
#define FP16_ASM
#define FP24_ASM
#define FP48_ASM

#include "../easy/relic_fpx_sqr_low.c"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines the square without reduction of an element of an extension field in
 * the basis w^e of D coefficients over Fp2, with w^D the non-residue of Fp2,
 * computed residue-wise as fp12_sqrn_low() does: the products off the diagonal
 * are summed and doubled, then those on it are added, so each output is at
 * most (D / 2 + 2) * m before the corrections that bring it below 4m.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] DX		- the prefix of unreduced extension field elements.
 * @param[in] D			- the number of coefficients over Fp2.
 * @param[in] D2		- twice the number of coefficients.
 * @param[in] CO		- the macro giving the coefficient of w^e.
 */
#define RNS_FLAT_SQRN(F, X, DX, D, D2, CO)									\
	void F(DX##_t c, const X##_t a) {										\
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
					x[e][j] = y[e][j] = rns_load(CO(a, e)[j], k);			\
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
					RLC_UNROLL(D)											\
					for (int e2 = e1 + 1; e2 < D; e2++) {					\
						int f = e2 + (e1 + e2 < D ? 0 : D);					\
						if ((e1 + e2) % D == e) {							\
							rp2_mac(l, h, x[e1], y[f], t[f]);				\
						}													\
					}														\
				}															\
				for (int j = 0; j < 2; j++) {								\
					l[j] = _mm512_slli_epi64(l[j], 1);						\
					h[j] = _mm512_slli_epi64(h[j], 1);						\
				}															\
				RLC_UNROLL(D)												\
				for (int e1 = 0; e1 < D; e1++) {							\
					int f = e1 + (2 * e1 < D ? 0 : D);						\
					if ((2 * e1) % D == e) {								\
						rp2_mac(l, h, x[e1], y[f], t[f]);					\
					}														\
				}															\
				for (int j = 0; j < 2; j++) {								\
					l[j] = rns_vpeel(rns_vmon(l[j], h[j], m, v),			\
							rns_vdv(m), rns_halvings(D / 2 + 2));			\
					rns_store(CO(c, e)[j], k, l[j]);						\
				}															\
			}																\
		}																	\
	}

/**
 * Defines the terms of a cyclotomic squaring of an extension field element, as
 * fp12_sqrc_low() computes them, for coefficients of H components over Fp2:
 * each pair x + y * w is squared as an element of 2H coefficients in w, with
 * w^(2H) the non-residue of Fp2, residue-wise, and the factor 3 and the term
 * of a are folded into the sums before a single reduction of each output.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] DX		- the prefix of unreduced extension field elements.
 * @param[in] H			- the number of components of a coefficient over Fp2.
 * @param[in] H2		- twice that number.
 * @param[in] CO		- the macro giving the component of v^e of a coefficient.
 * @param[in] L			- the layout of the field, QC or CQ.
 */
#define RNS_FLAT_CYC(F, X, DX, H, H2, CO, L)								\
	void F(DX##_t c, const X##_t a) {										\
		static const int P[3][4][2] = TMPL_CYC_PAIRS_##L;					\
		ctx_t *ctx = core_get();											\
		const __m512i z = _mm512_setzero_si512();							\
		rp2_t x[H2], x3[H2], y[2 * H2], a0[H], a1[H], l, h;					\
		__m512i t[2 * H2], m, v, k0, k1;									\
		int s, q;															\
																			\
		rns_nor(&s, &q);													\
		for (size_t k = 0; k < RNS_NE; k++) {								\
			m = rns_load(ctx->rns.m, k);									\
			v = rns_load(ctx->rns.iv, k);									\
			/* k1 = 2 and k0 = -2, from the residues of one. */				\
			k1 = rns_load(ctx->one, k);										\
			k1 = rns_vadd(k1, k1, m);										\
			k0 = rns_vneg(k1, m);											\
			RLC_UNROLL(3)													\
			for (int p = 0; p < 3; p++) {									\
				const int i0 = P[p][0][0], j0 = P[p][0][1];					\
				const int i1 = P[p][1][0], j1 = P[p][1][1];					\
				const int i2 = P[p][2][0], j2 = P[p][2][1];					\
				const int i3 = P[p][3][0], j3 = P[p][3][1];					\
																			\
				/* The pair is x + y * w with w^2 = v, flat in w. */		\
				RLC_UNROLL(H)												\
				for (int e = 0; e < H; e++) {								\
					for (int j = 0; j < 2; j++) {							\
						x[2 * e][j] = rns_load(CO(a[i0][j0], e)[j], k);		\
						x[2 * e + 1][j] = rns_load(CO(a[i1][j1], e)[j], k);	\
						a0[e][j] = rns_load(CO(a[i2][j2], e)[j], k);		\
						a1[e][j] = rns_load(CO(a[i3][j3], e)[j], k);		\
					}														\
				}															\
				/* Factors 3x below 3m, and y * w^(2H) for the products		\
				 * wrapping around. */										\
				RLC_UNROLL(H2)												\
				for (int e = 0; e < H2; e++) {								\
					for (int j = 0; j < 2; j++) {							\
						x3[e][j] = _mm512_add_epi64(x[e][j],				\
								_mm512_add_epi64(x[e][j], x[e][j]));		\
						y[e][j] = x[e][j];									\
					}														\
					rp2_nor(y[e + H2], x[e], s, q, m);						\
				}															\
				RLC_UNROLL(2 * H2)											\
				for (int f = 0; f < 2 * H2; f++) {							\
					t[f] = rns_vneg(rns_vsml(y[f][1], -q, m), m);			\
				}															\
				/* Coefficient e of c_0 is output 2e of the square, and		\
				 * of c_1 output 2e + 1, or 2e - 1 times v, the top one		\
				 * wrapping around times w^(2H). Outputs are computed		\
				 * one at a time, so that only their sums stay in			\
				 * registers. */											\
				RLC_UNROLL(2)												\
				for (int r = 0; r < 2; r++) {								\
					RLC_UNROLL(H)											\
					for (int e = 0; e < H; e++) {							\
						const int n = (r == 1 && p == 1);					\
						const int o = (r == 0 ? 2 * e : (!n ? 2 * e + 1 :	\
								(e > 0 ? 2 * e - 1 : H2 - 1)));				\
						const int g = (n && e == 0);						\
																			\
						l[0] = l[1] = h[0] = h[1] = z;						\
						RLC_UNROLL(H2)										\
						for (int e1 = 0; e1 < H2; e1++) {					\
							RLC_UNROLL(H2)									\
							for (int e2 = e1 + 1; e2 < H2; e2++) {			\
								int f = e2 + H2 * ((e1 + e2 >= H2) + g);	\
								if ((e1 + e2) % H2 == o) {					\
									rp2_mac(l, h, x3[e1], y[f], t[f]);		\
								}											\
							}												\
						}													\
						for (int j = 0; j < 2; j++) {						\
							l[j] = _mm512_slli_epi64(l[j], 1);				\
							h[j] = _mm512_slli_epi64(h[j], 1);				\
						}													\
						RLC_UNROLL(H2)										\
						for (int e1 = 0; e1 < H2; e1++) {					\
							int f = e1 + H2 * ((2 * e1 >= H2) + g);			\
							if ((2 * e1) % H2 == o) {						\
								rp2_mac(l, h, x3[e1], y[f], t[f]);			\
							}												\
						}													\
						/* At most H products of 3m * m off the				\
						 * diagonal, doubled, 2 on it and the term of		\
						 * a: at most (3H + 2) * m before the				\
						 * corrections that bring it below 4m. */			\
						for (int j = 0; j < 2; j++) {						\
							__m512i b = (r == 0 ? a0[e][j] : a1[e][j]);		\
							__m512i u = (r == 0 ? k0 : k1);					\
																			\
							l[j] = _mm512_madd52lo_epu64(l[j], b, u);		\
							h[j] = _mm512_madd52hi_epu64(h[j], b, u);		\
							l[j] = rns_vpeel(rns_vmon(l[j], h[j], m, v),	\
									rns_vdv(m), rns_halvings(3 * H + 2));	\
							if (r == 0) {									\
								rns_store(CO(c[i2][j2], e)[j], k, l[j]);	\
							} else {										\
								rns_store(CO(c[i3][j3], e)[j], k, l[j]);	\
							}												\
						}													\
					}														\
				}															\
			}																\
		}																	\
	}

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

void fp3_sqrn_low(dv3_t c, const fp3_t a) {
	ctx_t *ctx = core_get();
	const dig_t *_m = ctx->rns.m, *_i = ctx->rns.iv;
	const int w = fp_prime_get_cnr();
	__m512i m, v, a0, a1, a2, d0, t1, t2;

	for (size_t k = 0; k < RNS_NE; k++) {
		m = rns_load(_m, k);
		v = rns_load(_i, k);
		a0 = rns_load(a[0], k);
		a1 = rns_load(a[1], k);
		a2 = rns_load(a[2], k);
		/* t_i = w * a_i for the products wrapping around, with u^3 = w. */
		t1 = rns_vsml(a1, (w < 0 ? -w : w), m);
		t2 = rns_vsml(a2, (w < 0 ? -w : w), m);
		if (w < 0) {
			t1 = rns_vneg(t1, m);
			t2 = rns_vneg(t2, m);
		}
		/* Factors 2 * a_0 and 2 * t_1 below 2m keep each output, a sum of
		 * 2 products, at most 7m / 4 with no correction. */
		d0 = _mm512_add_epi64(a0, a0);
		t1 = _mm512_add_epi64(t1, t1);
		rns_store(c[0], k, rns_vmul2(a0, a0, t1, a2, m, v));
		rns_store(c[1], k, rns_vmul2(d0, a1, t2, a2, m, v));
		rns_store(c[2], k, rns_vmul2(a1, a1, d0, a2, m, v));
	}
}

void fp3_sqrm_low(fp3_t c, const fp3_t a) {
	rlc_align dv3_t t;

	dv3_null(t);

	RLC_TRY {
		dv3_new(t);
		fp3_sqrn_low(t, a);
		fp3_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv3_free(t);
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
		RLC_UNROLL(6)
		for (int e = 0; e < 6; e++) {
			for (int j = 0; j < 2; j++) {
				x[e][j] = y[e][j] = rns_load(a[I[e]][J[e]][j], k);
				l[e][j] = h[e][j] = z;
			}
			/* With w^6 = v^3 = s + i, products wrapping around use y * w^6. */
			rp2_nor(y[e + 6], y[e], s, q, m);
		}
		RLC_UNROLL(12)
		for (int e = 0; e < 12; e++) {
			t[e] = rns_vneg(rns_vsml(y[e][1], -q, m), m);
		}
		/* Schoolbook square in w: the products off the diagonal are summed and
		 * doubled, then those on it are added. Each output adds at most 6
		 * products of residues at most m < 2^50 off the diagonal and 2 on it,
		 * so the halves of the sums stay below 2^56, and the result is at most
		 * 14m / 4 + m, brought below 4m by one correction. Outputs are computed
		 * one at a time, so that only their sums stay in registers. */
		RLC_UNROLL(6)
		for (int e = 0; e < 6; e++) {
			RLC_UNROLL(6)
			for (int e1 = 0; e1 < 6; e1++) {
				RLC_UNROLL(6)
				for (int e2 = e1 + 1; e2 < 6; e2++) {
					int f = e2 + (e1 + e2 < 6 ? 0 : 6);
					if ((e1 + e2) % 6 == e) {
						rp2_mac(l[e], h[e], x[e1], y[f], t[f]);
					}
				}
			}
			for (int j = 0; j < 2; j++) {
				l[e][j] = _mm512_slli_epi64(l[e][j], 1);
				h[e][j] = _mm512_slli_epi64(h[e][j], 1);
			}
			RLC_UNROLL(6)
			for (int e1 = 0; e1 < 6; e1++) {
				int f = e1 + (2 * e1 < 6 ? 0 : 6);
				if ((2 * e1) % 6 == e) {
					rp2_mac(l[e], h[e], x[e1], y[f], t[f]);
				}
			}
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
		RLC_UNROLL(3)
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

RNS_FLAT_SQRN(fp8_sqrn_low, fp8, dv8, 4, 8, RNS_CO8)

RNS_FLAT_SQRN(fp16_sqrn_low, fp16, dv16, 8, 16, RNS_CO16)

RNS_FLAT_SQRN(fp24_sqrn_low, fp24, dv24, 12, 24, RNS_CO24)

RNS_FLAT_CYC(fp24_sqrc_low, fp24, dv24, 2, 4, RNS_CO4, CQ)

RNS_FLAT_CYC(fp48_sqrc_low, fp48, dv48, 4, 8, RNS_CO8, QC)
