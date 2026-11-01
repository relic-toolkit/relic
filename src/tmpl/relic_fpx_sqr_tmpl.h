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
 * Templates for squaring in cyclotomic subgroups of extension fields.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"
#include "relic_fpx_low.h"
#include "relic_fpx_dv_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Computes a coefficient C = 3 * T + 2 * S * A of a cyclotomic or compressed
 * squaring, from T without reduction in U. In a Residue Number System, the term
 * 2 * S * A joins 3 * U as a product by the residues of 2 * S, so that C is
 * reduced once, as a whole, and chains of squarings do not grow; otherwise, T
 * is reduced first.
 *
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] B			- the prefix of the base field with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[out] C		- the result.
 * @param[in,out] U		- the value of T without reduction, overwritten.
 * @param[in] A			- the coefficient of the input.
 * @param[in] S			- the sign of the input term, 1 or -1.
 * @param[out] T		- a temporary in the subfield.
 */
#if FP_RDC == FP_RENUS
#define TMPL_CYC_FOLD(Z, B, BD, N, C, U, A, S, T)							\
	{																		\
		rlc_align dig_t _k[RLC_FP_LEN], _w[RLC_FP_DLEN];					\
																			\
		fp_dbl(_k, core_get()->one);										\
		if ((S) < 0) {														\
			fp_neg(_k, _k);													\
		}																	\
		for (size_t _n = 0; _n < sizeof(Z##_t) / sizeof(fp_t); _n++) {		\
			fp_addc_low(_w, ((dv_t *)(U))[_n], ((dv_t *)(U))[_n]);			\
			fp_addc_low(((dv_t *)(U))[_n], ((dv_t *)(U))[_n], _w);			\
			fp_muln_low(_w, ((fp_t *)(A))[_n], _k);							\
			fp_addc_low(((dv_t *)(U))[_n], ((dv_t *)(U))[_n], _w);			\
		}																	\
		TMPL_DV_RDCN(B, BD, N, C, U);										\
	}
#else
#define TMPL_CYC_FOLD(Z, B, BD, N, C, U, A, S, T)							\
	{																		\
		TMPL_DV_RDCN(B, BD, N, T, U);										\
		if ((S) < 0) {														\
			Z##_sub(C, T, A);												\
		} else {															\
			Z##_add(C, T, A);												\
		}																	\
		Z##_dbl(C, C);														\
		Z##_add(C, T, C);													\
	}
#endif

/**
 * Brings the coefficients of a cyclotomic or compressed squaring without lazy
 * reduction back to the size of reduced ones, by multiplying each prime field
 * coefficient by one. In a Residue Number System, elements are not reduced by
 * additions, and these squarings compute coefficients as 3t +- 2a, which would
 * double in size at every squaring of a chain. All coefficients are reduced
 * together.
 *
 * @param[in] F			- the prefix of the field holding the element.
 * @param[in,out] R		- the element.
 */
#if FP_RDC == FP_RENUS
#define TMPL_CYC_NORM(F, R)													\
	{																		\
		enum { _N = sizeof(F##_t) / sizeof(fp_t) };							\
		rlc_align dig_t _t[_N][RLC_FP_DLEN];								\
		dig_t *_c[_N], *_u[_N];												\
																			\
		for (int _n = 0; _n < _N; _n++) {									\
			fp_muln_low(_t[_n], ((fp_t *)(R))[_n], core_get()->one);		\
			_c[_n] = ((fp_t *)(R))[_n];										\
			_u[_n] = _t[_n];												\
		}																	\
		fp_rdcv_low(_c, _u, _N);											\
	}
#else
#define TMPL_CYC_NORM(F, R)		/* Elements are reduced by additions. */
#endif

/**
 * Defines a template for cyclotomic squaring in an extension field built as
 * quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_SQR_CYC_QC(X, Z, NOR)											\
	void X##_sqr_cyc_basic(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		Z##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
																			\
			/* Define z = sqrt(E) */										\
																			\
			/* Now a is seen as (t0,t1) + (t2,t3) * w + (t4,t5) * w^2 */	\
																			\
			/* (t0, t1) = (a00 + a11*z)^2. */								\
			Z##_sqr(t2, a[0][0]);											\
			Z##_sqr(t3, a[1][1]);											\
			Z##_add(t1, a[0][0], a[1][1]);									\
																			\
			NOR(t0, t3);													\
			Z##_add(t0, t0, t2);											\
																			\
			Z##_sqr(t1, t1);												\
			Z##_sub(t1, t1, t2);											\
			Z##_sub(t1, t1, t3);											\
																			\
			Z##_sub(c[0][0], t0, a[0][0]);									\
			Z##_add(c[0][0], c[0][0], c[0][0]);								\
			Z##_add(c[0][0], t0, c[0][0]);									\
																			\
			Z##_add(c[1][1], t1, a[1][1]);									\
			Z##_add(c[1][1], c[1][1], c[1][1]);								\
			Z##_add(c[1][1], t1, c[1][1]);									\
																			\
			Z##_sqr(t0, a[0][1]);											\
			Z##_sqr(t1, a[1][2]);											\
			Z##_add(t5, a[0][1], a[1][2]);									\
			Z##_sqr(t2, t5);												\
																			\
			Z##_add(t3, t0, t1);											\
			Z##_sub(t5, t2, t3);											\
																			\
			Z##_add(t6, a[1][0], a[0][2]);									\
			Z##_sqr(t3, t6);												\
			Z##_sqr(t2, a[1][0]);											\
																			\
			NOR(t6, t5);													\
			Z##_add(t5, t6, a[1][0]);										\
			Z##_dbl(t5, t5);												\
			Z##_add(c[1][0], t5, t6);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t0, t4);											\
			Z##_sub(t6, t5, a[0][2]);										\
																			\
			Z##_sqr(t1, a[0][2]);											\
																			\
			Z##_dbl(t6, t6);												\
			Z##_add(c[0][2], t6, t5);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t2, t4);											\
			Z##_sub(t6, t5, a[0][1]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[0][1], t6, t5);										\
																			\
			Z##_add(t0, t2, t1);											\
			Z##_sub(t5, t3, t0);											\
			Z##_add(t6, t5, a[1][2]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[1][2], t5, t6);										\
																			\
			TMPL_CYC_NORM(X, c);											\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Defines a template for compressed squaring in an extension field built as
 * quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_SQR_PCK_QC(X, Z, NOR)											\
	void X##_sqr_pck_basic(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		Z##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
																			\
			Z##_sqr(t0, a[0][1]);											\
			Z##_sqr(t1, a[1][2]);											\
			Z##_add(t5, a[0][1], a[1][2]);									\
			Z##_sqr(t2, t5);												\
																			\
			Z##_add(t3, t0, t1);											\
			Z##_sub(t5, t2, t3);											\
																			\
			Z##_add(t6, a[1][0], a[0][2]);									\
			Z##_sqr(t3, t6);												\
			Z##_sqr(t2, a[1][0]);											\
																			\
			NOR(t6, t5);													\
			Z##_add(t5, t6, a[1][0]);										\
			Z##_dbl(t5, t5);												\
			Z##_add(c[1][0], t5, t6);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t0, t4);											\
			Z##_sub(t6, t5, a[0][2]);										\
																			\
			Z##_sqr(t1, a[0][2]);											\
																			\
			Z##_dbl(t6, t6);												\
			Z##_add(c[0][2], t6, t5);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t2, t4);											\
			Z##_sub(t6, t5, a[0][1]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[0][1], t6, t5);										\
																			\
			Z##_add(t0, t2, t1);											\
			Z##_sub(t5, t3, t0);											\
			Z##_add(t6, t5, a[1][2]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[1][2], t5, t6);										\
																			\
			TMPL_CYC_NORM(Z, c[1][0]);										\
			TMPL_CYC_NORM(Z, c[0][2]);										\
			TMPL_CYC_NORM(Z, c[0][1]);										\
			TMPL_CYC_NORM(Z, c[1][2]);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Defines a template for cyclotomic squaring in an extension field built as
 * cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_SQR_CYC_CQ(X, Z, NOR)											\
	void X##_sqr_cyc_basic(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		Z##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
																			\
			Z##_sqr(t2, a[0][0]);											\
			Z##_sqr(t3, a[0][1]);											\
			Z##_add(t1, a[0][0], a[0][1]);									\
																			\
			NOR(t0, t3);													\
			Z##_add(t0, t0, t2);											\
																			\
			Z##_sqr(t1, t1);												\
			Z##_sub(t1, t1, t2);											\
			Z##_sub(t1, t1, t3);											\
																			\
			Z##_sub(c[0][0], t0, a[0][0]);									\
			Z##_add(c[0][0], c[0][0], c[0][0]);								\
			Z##_add(c[0][0], t0, c[0][0]);									\
																			\
			Z##_add(c[0][1], t1, a[0][1]);									\
			Z##_add(c[0][1], c[0][1], c[0][1]);								\
			Z##_add(c[0][1], t1, c[0][1]);									\
																			\
			Z##_sqr(t0, a[2][0]);											\
			Z##_sqr(t1, a[2][1]);											\
			Z##_add(t5, a[2][0], a[2][1]);									\
			Z##_sqr(t2, t5);												\
																			\
			Z##_add(t3, t0, t1);											\
			Z##_sub(t5, t2, t3);											\
																			\
			Z##_add(t6, a[1][0], a[1][1]);									\
			Z##_sqr(t3, t6);												\
			Z##_sqr(t2, a[1][0]);											\
																			\
			NOR(t6, t5);													\
			Z##_add(t5, t6, a[1][0]);										\
			Z##_dbl(t5, t5);												\
			Z##_add(c[1][0], t5, t6);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t0, t4);											\
			Z##_sub(t6, t5, a[1][1]);										\
																			\
			Z##_sqr(t1, a[1][1]);											\
																			\
			Z##_dbl(t6, t6);												\
			Z##_add(c[1][1], t6, t5);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t2, t4);											\
			Z##_sub(t6, t5, a[2][0]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[2][0], t6, t5);										\
																			\
			Z##_add(t0, t2, t1);											\
			Z##_sub(t5, t3, t0);											\
			Z##_add(t6, t5, a[2][1]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[2][1], t5, t6);										\
																			\
			TMPL_CYC_NORM(X, c);											\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Defines a template for compressed squaring in an extension field built as
 * cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_SQR_PCK_CQ(X, Z, NOR)											\
	void X##_sqr_pck_basic(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2, t3, t4, t5, t6;									\
																			\
		Z##_null_all(t0, t1, t2, t3, t4, t5, t6);							\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2, t3, t4, t5, t6);						\
																			\
			Z##_sqr(t0, a[2][0]);											\
			Z##_sqr(t1, a[2][1]);											\
			Z##_add(t5, a[2][0], a[2][1]);									\
			Z##_sqr(t2, t5);												\
																			\
			Z##_add(t3, t0, t1);											\
			Z##_sub(t5, t2, t3);											\
																			\
			Z##_add(t6, a[1][0], a[1][1]);									\
			Z##_sqr(t3, t6);												\
			Z##_sqr(t2, a[1][0]);											\
																			\
			NOR(t6, t5);													\
			Z##_add(t5, t6, a[1][0]);										\
			Z##_dbl(t5, t5);												\
			Z##_add(c[1][0], t5, t6);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t0, t4);											\
			Z##_sub(t6, t5, a[1][1]);										\
																			\
			Z##_sqr(t1, a[1][1]);											\
																			\
			Z##_dbl(t6, t6);												\
			Z##_add(c[1][1], t6, t5);										\
																			\
			NOR(t4, t1);													\
			Z##_add(t5, t2, t4);											\
			Z##_sub(t6, t5, a[2][0]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[2][0], t6, t5);										\
																			\
			Z##_add(t0, t2, t1);											\
			Z##_sub(t5, t3, t0);											\
			Z##_add(t6, t5, a[2][1]);										\
			Z##_dbl(t6, t6);												\
			Z##_add(c[2][1], t5, t6);										\
																			\
			TMPL_CYC_NORM(Z, c[1][0]);										\
			TMPL_CYC_NORM(Z, c[1][1]);										\
			TMPL_CYC_NORM(Z, c[2][0]);										\
			TMPL_CYC_NORM(Z, c[2][1]);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Defines a template for cyclotomic squaring with lazy reduction in an
 * extension field built as quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] D			- the prefix of the double-precision subfield type.
 * @param[in] B			- the prefix of the base field with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] SQRU		- the squaring in the subfield without reduction.
 */
#define TMPL_SQR_CYC_LAZYR_QC(X, Z, D, B, BD, N, Q, SQRU)					\
	void X##_sqr_cyc_lazyr(X##_t c, const X##_t a) {						\
		Z##_t t;															\
		D##_t u0, u1, u2, u3;												\
																			\
		Z##_null(t);														\
		D##_null_all(u0, u1, u2, u3);										\
																			\
		RLC_TRY {															\
			Z##_new(t);														\
			D##_new_all(u0, u1, u2, u3);									\
																			\
			SQRU(u2, a[0][0]);												\
			SQRU(u3, a[1][1]);												\
			Z##_add(t, a[0][0], a[1][1]);									\
			SQRU(u1, t);													\
																			\
			/* c_00 = 3 * (a_00^2 + a_11^2 * v) - 2 * a_00. */				\
			TMPL_DV_NADD(B, BD, N, Q, u0, u2, u3);							\
			TMPL_CYC_FOLD(Z, B, BD, N, c[0][0], u0, a[0][0], -1, t);		\
			/* c_11 = 3 * 2 * a_00 * a_11 + 2 * a_11. */					\
			TMPL_DV_ADDC(B, BD, N, u2, u2, u3);								\
			TMPL_DV_SUBC(B, BD, N, u1, u1, u2);								\
			TMPL_CYC_FOLD(Z, B, BD, N, c[1][1], u1, a[1][1], 1, t);			\
																			\
			/* The other coefficients come from compressed squaring. */		\
			X##_sqr_pck_lazyr(c, a);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free(t);													\
			D##_free_all(u0, u1, u2, u3);									\
		}																	\
	}

/**
 * Defines a template for compressed squaring with lazy reduction in an
 * extension field built as quadratic over cubic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] D			- the prefix of the double-precision subfield type.
 * @param[in] B			- the prefix of the base field with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] SQRU		- the squaring in the subfield without reduction.
 */
#define TMPL_SQR_PCK_LAZYR_QC(X, Z, D, B, BD, N, Q, SQRU)					\
	void X##_sqr_pck_lazyr(X##_t c, const X##_t a) {						\
		Z##_t t;															\
		D##_t u0, u1, u2, u3, u4, u5, u6;									\
																			\
		Z##_null(t);														\
		D##_null_all(u0, u1, u2, u3, u4, u5, u6);							\
																			\
		RLC_TRY {															\
			Z##_new(t);														\
			D##_new_all(u0, u1, u2, u3, u4, u5, u6);						\
																			\
			/* All squares come first, as c and a may be the same. */		\
			SQRU(u0, a[0][1]);												\
			SQRU(u1, a[1][2]);												\
			Z##_add(t, a[0][1], a[1][2]);									\
			SQRU(u2, t);													\
			SQRU(u3, a[1][0]);												\
			SQRU(u4, a[0][2]);												\
			Z##_add(t, a[1][0], a[0][2]);									\
			SQRU(u5, t);													\
																			\
			/* c_02 = 3 * (a_01^2 + a_12^2 * v) - 2 * a_02. */				\
			TMPL_DV_NADD(B, BD, N, Q, u6, u0, u1);							\
			TMPL_CYC_FOLD(Z, B, BD, N, c[0][2], u6, a[0][2], -1, t);		\
			/* c_10 = 3 * 2 * a_01 * a_12 * v + 2 * a_10. */				\
			TMPL_DV_ADDC(B, BD, N, u1, u0, u1);								\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u1);								\
			TMPL_DV_NOR(B, BD, N, Q, u6, u2);								\
			TMPL_CYC_FOLD(Z, B, BD, N, c[1][0], u6, a[1][0], 1, t);			\
			/* c_01 = 3 * (a_10^2 + a_02^2 * v) - 2 * a_01. */				\
			TMPL_DV_NADD(B, BD, N, Q, u6, u3, u4);							\
			TMPL_CYC_FOLD(Z, B, BD, N, c[0][1], u6, a[0][1], -1, t);		\
			/* c_12 = 3 * 2 * a_10 * a_02 + 2 * a_12. */					\
			TMPL_DV_ADDC(B, BD, N, u3, u3, u4);								\
			TMPL_DV_SUBC(B, BD, N, u5, u5, u3);								\
			TMPL_CYC_FOLD(Z, B, BD, N, c[1][2], u5, a[1][2], 1, t);			\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free(t);													\
			D##_free_all(u0, u1, u2, u3, u4, u5, u6);						\
		}																	\
	}

/**
 * Defines a template for cyclotomic squaring with lazy reduction in an
 * extension field built as cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] D			- the prefix of the double-precision subfield type.
 * @param[in] B			- the prefix of the base field with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] SQRU		- the squaring in the subfield without reduction.
 */
#define TMPL_SQR_CYC_LAZYR_CQ(X, Z, D, B, BD, N, Q, SQRU)					\
	void X##_sqr_cyc_lazyr(X##_t c, const X##_t a) {						\
		Z##_t t;															\
		D##_t u0, u1, u2, u3;												\
																			\
		Z##_null(t);														\
		D##_null_all(u0, u1, u2, u3);										\
																			\
		RLC_TRY {															\
			Z##_new(t);														\
			D##_new_all(u0, u1, u2, u3);									\
																			\
			SQRU(u2, a[0][0]);												\
			SQRU(u3, a[0][1]);												\
			Z##_add(t, a[0][0], a[0][1]);									\
			SQRU(u1, t);													\
																			\
			/* c_00 = 3 * (a_00^2 + a_01^2 * v) - 2 * a_00. */				\
			TMPL_DV_NADD(B, BD, N, Q, u0, u2, u3);							\
			TMPL_CYC_FOLD(Z, B, BD, N, c[0][0], u0, a[0][0], -1, t);		\
			/* c_01 = 3 * 2 * a_00 * a_01 + 2 * a_01. */					\
			TMPL_DV_ADDC(B, BD, N, u2, u2, u3);								\
			TMPL_DV_SUBC(B, BD, N, u1, u1, u2);								\
			TMPL_CYC_FOLD(Z, B, BD, N, c[0][1], u1, a[0][1], 1, t);			\
																			\
			/* The other coefficients come from compressed squaring. */		\
			X##_sqr_pck_lazyr(c, a);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free(t);													\
			D##_free_all(u0, u1, u2, u3);									\
		}																	\
	}

/**
 * Defines a template for compressed squaring with lazy reduction in an
 * extension field built as cubic over quadratic.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] D			- the prefix of the double-precision subfield type.
 * @param[in] B			- the prefix of the base field with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] SQRU		- the squaring in the subfield without reduction.
 */
#define TMPL_SQR_PCK_LAZYR_CQ(X, Z, D, B, BD, N, Q, SQRU)					\
	void X##_sqr_pck_lazyr(X##_t c, const X##_t a) {						\
		Z##_t t;															\
		D##_t u0, u1, u2, u3, u4, u5, u6;									\
																			\
		Z##_null(t);														\
		D##_null_all(u0, u1, u2, u3, u4, u5, u6);							\
																			\
		RLC_TRY {															\
			Z##_new(t);														\
			D##_new_all(u0, u1, u2, u3, u4, u5, u6);						\
																			\
			/* All squares come first, as c and a may be the same. */		\
			SQRU(u0, a[2][0]);												\
			SQRU(u1, a[2][1]);												\
			Z##_add(t, a[2][0], a[2][1]);									\
			SQRU(u2, t);													\
			SQRU(u3, a[1][0]);												\
			SQRU(u4, a[1][1]);												\
			Z##_add(t, a[1][0], a[1][1]);									\
			SQRU(u5, t);													\
																			\
			/* c_11 = 3 * (a_20^2 + a_21^2 * v) - 2 * a_11. */				\
			TMPL_DV_NADD(B, BD, N, Q, u6, u0, u1);							\
			TMPL_CYC_FOLD(Z, B, BD, N, c[1][1], u6, a[1][1], -1, t);		\
			/* c_10 = 3 * 2 * a_20 * a_21 * v + 2 * a_10. */				\
			TMPL_DV_ADDC(B, BD, N, u1, u0, u1);								\
			TMPL_DV_SUBC(B, BD, N, u2, u2, u1);								\
			TMPL_DV_NOR(B, BD, N, Q, u6, u2);								\
			TMPL_CYC_FOLD(Z, B, BD, N, c[1][0], u6, a[1][0], 1, t);			\
			/* c_20 = 3 * (a_10^2 + a_11^2 * v) - 2 * a_20. */				\
			TMPL_DV_NADD(B, BD, N, Q, u6, u3, u4);							\
			TMPL_CYC_FOLD(Z, B, BD, N, c[2][0], u6, a[2][0], -1, t);		\
			/* c_21 = 3 * 2 * a_10 * a_11 + 2 * a_21. */					\
			TMPL_DV_ADDC(B, BD, N, u3, u3, u4);								\
			TMPL_DV_SUBC(B, BD, N, u5, u5, u3);								\
			TMPL_CYC_FOLD(Z, B, BD, N, c[2][1], u5, a[2][1], 1, t);			\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free(t);													\
			D##_free_all(u0, u1, u2, u3, u4, u5, u6);						\
		}																	\
	}
