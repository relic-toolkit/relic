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

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

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
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2, t3, t4, t5, t6);						\
		}																	\
	}

/**
 * Adds two double-precision elements made of N components in a base field.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[out] C		- the result.
 * @param[in] A			- the first element.
 * @param[in] E			- the second element.
 */
#define TMPL_DV_ADDC(B, BD, N, C, A, E)										\
	for (int _i = 0; _i < (N); _i++) {										\
		B##_addc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],				\
				((BD##_t *)(E))[_i]);										\
	}

/**
 * Subtracts two double-precision elements made of N components in a base
 * field.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[out] C		- the result.
 * @param[in] A			- the first element.
 * @param[in] E			- the second element.
 */
#define TMPL_DV_SUBC(B, BD, N, C, A, E)										\
	for (int _i = 0; _i < (N); _i++) {										\
		B##_subc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],				\
				((BD##_t *)(E))[_i]);										\
	}

/**
 * Reduces a double-precision element made of N components in a base field.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[out] C		- the result.
 * @param[in] A			- the element to reduce.
 */
#define TMPL_DV_RDCN(B, BD, N, C, A)										\
	for (int _i = 0; _i < (N); _i++) {										\
		B##_rdcn_low(((B##_t *)(C))[_i], ((BD##_t *)(A))[_i]);				\
	}

/**
 * Computes C = A + E * v for double-precision elements made of N components
 * in a base field, where v generates the extension. Multiplying by v moves
 * each component one power of v up, and the top one wraps around times the
 * non-residue. Component p in powers of v is stored at index
 * (p mod Q) * (N / Q) + p / Q, where Q is the number of outer components.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[in] Q			- the number of outer components.
 * @param[out] C		- the result.
 * @param[in] A			- the first element.
 * @param[in] E			- the second element.
 */
#define TMPL_DV_NADD(B, BD, N, Q, C, A, E)									\
	for (int _p = 0; _p < (N); _p++) {										\
		int _i = (_p % (Q)) * ((N) / (Q)) + _p / (Q);						\
		int _j = (((_p + (N) - 1) % (N)) % (Q)) * ((N) / (Q)) +				\
				((_p + (N) - 1) % (N)) / (Q);								\
		if (_p == 0) {														\
			B##_nord_low(((BD##_t *)(C))[_i], ((BD##_t *)(E))[_j]);			\
			B##_addc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],			\
					((BD##_t *)(C))[_i]);									\
		} else {															\
			B##_addc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],			\
					((BD##_t *)(E))[_j]);									\
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
		Z##_t t0, t1;														\
		D##_t u0, u1, u2, u3;												\
																			\
		Z##_null_all(t0, t1);												\
		D##_null_all(u0, u1, u2, u3);										\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1);											\
			D##_new_all(u0, u1, u2, u3);									\
																			\
			SQRU(u2, a[0][0]);												\
			SQRU(u3, a[1][1]);												\
			Z##_add(t1, a[0][0], a[1][1]);									\
																			\
			TMPL_DV_NADD(B, BD, N, Q, u0, u2, u3);							\
			TMPL_DV_RDCN(B, BD, N, t0, u0);									\
																			\
			SQRU(u1, t1);													\
			TMPL_DV_ADDC(B, BD, N, u2, u2, u3);								\
			TMPL_DV_SUBC(B, BD, N, u1, u1, u2);								\
			TMPL_DV_RDCN(B, BD, N, t1, u1);									\
																			\
			Z##_sub(c[0][0], t0, a[0][0]);									\
			Z##_dbl(c[0][0], c[0][0]);										\
			Z##_add(c[0][0], t0, c[0][0]);									\
																			\
			Z##_add(c[1][1], t1, a[1][1]);									\
			Z##_dbl(c[1][1], c[1][1]);										\
			Z##_add(c[1][1], t1, c[1][1]);									\
																			\
			/* The other coefficients come from compressed squaring. */		\
			X##_sqr_pck_lazyr(c, a);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1);											\
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
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_SQR_PCK_LAZYR_QC(X, Z, D, B, BD, N, Q, SQRU, NOR)				\
	void X##_sqr_pck_lazyr(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2;													\
		D##_t u0, u1, u2, u3;												\
																			\
		Z##_null_all(t0, t1, t2);											\
		D##_null_all(u0, u1, u2, u3);										\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2);										\
			D##_new_all(u0, u1, u2, u3);									\
																			\
			SQRU(u0, a[0][1]);												\
			SQRU(u1, a[1][2]);												\
			Z##_add(t0, a[0][1], a[1][2]);									\
			SQRU(u2, t0);													\
																			\
			TMPL_DV_ADDC(B, BD, N, u3, u0, u1);								\
			TMPL_DV_SUBC(B, BD, N, u3, u2, u3);								\
			TMPL_DV_RDCN(B, BD, N, t0, u3);									\
																			\
			Z##_add(t1, a[1][0], a[0][2]);									\
			Z##_sqr(t2, t1);												\
			SQRU(u2, a[1][0]);												\
																			\
			NOR(t1, t0);													\
			Z##_add(t0, t1, a[1][0]);										\
			Z##_dbl(t0, t0);												\
			Z##_add(c[1][0], t0, t1);										\
																			\
			TMPL_DV_NADD(B, BD, N, Q, u3, u0, u1);							\
			SQRU(u1, a[0][2]);												\
			TMPL_DV_RDCN(B, BD, N, t0, u3);									\
			Z##_sub(t1, t0, a[0][2]);										\
			Z##_dbl(t1, t1);												\
			Z##_add(c[0][2], t1, t0);										\
																			\
			TMPL_DV_ADDC(B, BD, N, u0, u2, u1);								\
			TMPL_DV_RDCN(B, BD, N, t0, u0);									\
			Z##_sub(t0, t2, t0);											\
			Z##_add(t1, t0, a[1][2]);										\
			Z##_dbl(t1, t1);												\
			Z##_add(c[1][2], t0, t1);										\
																			\
			TMPL_DV_NADD(B, BD, N, Q, u3, u2, u1);							\
			TMPL_DV_RDCN(B, BD, N, t0, u3);									\
			Z##_sub(t1, t0, a[0][1]);										\
			Z##_dbl(t1, t1);												\
			Z##_add(c[0][1], t1, t0);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2);										\
			D##_free_all(u0, u1, u2, u3);									\
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
		Z##_t t0, t1;														\
		D##_t u0, u1, u2, u3;												\
																			\
		Z##_null_all(t0, t1);												\
		D##_null_all(u0, u1, u2, u3);										\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1);											\
			D##_new_all(u0, u1, u2, u3);									\
																			\
			SQRU(u2, a[0][0]);												\
			SQRU(u3, a[0][1]);												\
			Z##_add(t1, a[0][0], a[0][1]);									\
																			\
			TMPL_DV_NADD(B, BD, N, Q, u0, u2, u3);							\
			TMPL_DV_RDCN(B, BD, N, t0, u0);									\
																			\
			SQRU(u1, t1);													\
			TMPL_DV_ADDC(B, BD, N, u2, u2, u3);								\
			TMPL_DV_SUBC(B, BD, N, u1, u1, u2);								\
			TMPL_DV_RDCN(B, BD, N, t1, u1);									\
																			\
			Z##_sub(c[0][0], t0, a[0][0]);									\
			Z##_dbl(c[0][0], c[0][0]);										\
			Z##_add(c[0][0], t0, c[0][0]);									\
																			\
			Z##_add(c[0][1], t1, a[0][1]);									\
			Z##_dbl(c[0][1], c[0][1]);										\
			Z##_add(c[0][1], t1, c[0][1]);									\
																			\
			/* The other coefficients come from compressed squaring. */		\
			X##_sqr_pck_lazyr(c, a);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1);											\
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
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_SQR_PCK_LAZYR_CQ(X, Z, D, B, BD, N, Q, SQRU, NOR)				\
	void X##_sqr_pck_lazyr(X##_t c, const X##_t a) {						\
		Z##_t t0, t1, t2;													\
		D##_t u0, u1, u2, u3;												\
																			\
		Z##_null_all(t0, t1, t2);											\
		D##_null_all(u0, u1, u2, u3);										\
																			\
		RLC_TRY {															\
			Z##_new_all(t0, t1, t2);										\
			D##_new_all(u0, u1, u2, u3);									\
																			\
			SQRU(u0, a[2][0]);												\
			SQRU(u1, a[2][1]);												\
			Z##_add(t1, a[2][0], a[2][1]);									\
			SQRU(u2, t1);													\
																			\
			TMPL_DV_ADDC(B, BD, N, u3, u0, u1);								\
			TMPL_DV_SUBC(B, BD, N, u3, u2, u3);								\
			TMPL_DV_RDCN(B, BD, N, t1, u3);									\
																			\
			Z##_add(t0, a[1][0], a[1][1]);									\
			Z##_sqr(t2, t0);												\
			SQRU(u2, a[1][0]);												\
																			\
			NOR(t0, t1);													\
			Z##_add(t1, t0, a[1][0]);										\
			Z##_dbl(t1, t1);												\
			Z##_add(c[1][0], t1, t0);										\
																			\
			TMPL_DV_NADD(B, BD, N, Q, u3, u0, u1);							\
			SQRU(u1, a[1][1]);												\
			TMPL_DV_RDCN(B, BD, N, t1, u3);									\
			Z##_sub(t0, t1, a[1][1]);										\
			Z##_dbl(t0, t0);												\
			Z##_add(c[1][1], t0, t1);										\
																			\
			TMPL_DV_NADD(B, BD, N, Q, u3, u2, u1);							\
			TMPL_DV_RDCN(B, BD, N, t1, u3);									\
			Z##_sub(t0, t1, a[2][0]);										\
			Z##_dbl(t0, t0);												\
			Z##_add(c[2][0], t0, t1);										\
																			\
			TMPL_DV_ADDC(B, BD, N, u3, u2, u1);								\
			TMPL_DV_RDCN(B, BD, N, t0, u3);									\
			Z##_sub(t1, t2, t0);											\
			Z##_add(t0, t1, a[2][1]);										\
			Z##_dbl(t0, t0);												\
			Z##_add(c[2][1], t1, t0);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Z##_free_all(t0, t1, t2);										\
			D##_free_all(u0, u1, u2, u3);									\
		}																	\
	}
