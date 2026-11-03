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
 * Templates for multiplication, squaring, inversion and exponentiation in
 * extension fields.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"
#include "relic_fpx_dv_tmpl.h"
#include "relic_fpx_lazyr_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Defines a template for Karatsuba multiplication in a quadratic extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_MUL_QUAD(X, S, NOR)										\
	void X##_mul_basic(X##_t c, const X##_t a, const X##_t b) {				\
		S##_t t0, t1, t2;													\
																			\
		S##_null_all(t0, t1, t2);											\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1, t2);										\
																			\
			/* Karatsuba algorithm. */										\
																			\
			/* t0 = a_0 * b_0. */											\
			S##_mul(t0, a[0], b[0]);										\
			/* t1 = a_1 * b_1. */											\
			S##_mul(t1, a[1], b[1]);										\
			/* t2 = b_0 + b_1. */											\
			S##_add(t2, b[0], b[1]);										\
																			\
			/* c_1 = a_0 + a_1. */											\
			S##_add(c[1], a[0], a[1]);										\
																			\
			/* c_1 = (a_0 + a_1) * (b_0 + b_1) */							\
			S##_mul(c[1], c[1], t2);										\
			S##_sub(c[1], c[1], t0);										\
			S##_sub(c[1], c[1], t1);										\
																			\
			/* c_0 = a_0b_0 + v * a_1b_1. */								\
			NOR(t2, t1);													\
			S##_add(c[0], t0, t2);											\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1, t2);										\
		}																	\
	}

/**
 * Defines a template for Karatsuba multiplication in a cubic extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_MUL_CUBIC(X, S, NOR)										\
	void X##_mul_basic(X##_t c, const X##_t a, const X##_t b) {				\
		S##_t v0, v1, v2, t0, t1, t2;										\
																			\
		S##_null_all(v0, v1, v2, t0, t1, t2);								\
																			\
		RLC_TRY {															\
			S##_new_all(v0, v1, v2, t0, t1, t2);							\
																			\
			/* v0 = a_0b_0 */												\
			S##_mul(v0, a[0], b[0]);										\
																			\
			/* v1 = a_1b_1 */												\
			S##_mul(v1, a[1], b[1]);										\
																			\
			/* v2 = a_2b_2 */												\
			S##_mul(v2, a[2], b[2]);										\
																			\
			/* t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */		\
			S##_add(t0, a[1], a[2]);										\
			S##_add(t1, b[1], b[2]);										\
			S##_mul(t2, t0, t1);											\
			S##_sub(t2, t2, v1);											\
			S##_sub(t2, t2, v2);											\
			NOR(t0, t2);													\
			S##_add(t2, t0, v0);											\
																			\
			/* c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */				\
			S##_add(t0, a[0], a[1]);										\
			S##_add(t1, b[0], b[1]);										\
			S##_mul(c[1], t0, t1);											\
			S##_sub(c[1], c[1], v0);										\
			S##_sub(c[1], c[1], v1);										\
			NOR(t0, v2);													\
			S##_add(c[1], c[1], t0);										\
																			\
			/* c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */				\
			S##_add(t0, a[0], a[2]);										\
			S##_add(t1, b[0], b[2]);										\
			S##_mul(c[2], t0, t1);											\
			S##_sub(c[2], c[2], v0);										\
			S##_add(c[2], c[2], v1);										\
			S##_sub(c[2], c[2], v2);										\
																			\
			/* c_0 = t2 */													\
			S##_copy(c[0], t2);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t2, t1, t0, v2, v1, v0);							\
		}																	\
	}

/**
 * Defines a template for squaring in a quadratic extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_SQR_QUAD(X, S, NOR)										\
	void X##_sqr_basic(X##_t c, const X##_t a) {							\
		S##_t t0, t1;														\
																			\
		S##_null_all(t0, t1);												\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1);											\
																			\
			S##_add(t0, a[0], a[1]);										\
			NOR(t1, a[1]);													\
			S##_add(t1, a[0], t1);											\
			S##_mul(t0, t0, t1);											\
			S##_mul(c[1], a[0], a[1]);										\
			S##_sub(c[0], t0, c[1]);										\
			NOR(t1, c[1]);													\
			S##_sub(c[0], c[0], t1);										\
			S##_dbl(c[1], c[1]);											\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1);											\
		}																	\
	}

/**
 * Defines a template for squaring in a cubic extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 * @param[in] H			- the number of prime field coefficients in the subfield.
 */
#define TMPL_FPX_SQR_CUBIC(X, S, NOR, H)									\
	void X##_sqr_basic(X##_t c, const X##_t a) {							\
		S##_t t0, t1, t2, t3, t4;											\
																			\
		S##_null_all(t0, t1, t2, t3, t4);									\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1, t2, t3, t4);								\
																			\
			/* t0 = a_0^2 */												\
			S##_sqr(t0, a[0]);												\
																			\
			/* t1 = 2 * a_1 * a_2 */										\
			S##_mul(t1, a[1], a[2]);										\
			S##_dbl(t1, t1);												\
																			\
			/* t2 = a_2^2. */												\
			S##_sqr(t2, a[2]);												\
																			\
			/* c2 = a_0 + a_2. */											\
			S##_add(c[2], a[0], a[2]);										\
																			\
			/* t3 = (a_0 + a_2 + a_1)^2. */									\
			S##_add(t3, c[2], a[1]);										\
			S##_sqr(t3, t3);												\
																			\
			/* c2 = (a_0 + a_2 - a_1)^2. */									\
			S##_sub(c[2], c[2], a[1]);										\
			S##_sqr(c[2], c[2]);											\
																			\
			/* c2 = (c2 + t3)/2. */											\
			S##_add(c[2], c[2], t3);										\
			for (int i = 0; i < (H); i++) {									\
				fp_hlv(((fp_t *)c[2])[i], ((fp_t *)c[2])[i]);				\
			}																\
																			\
			/* t3 = t3 - c2 - t1. */										\
			S##_sub(t3, t3, c[2]);											\
			S##_sub(t3, t3, t1);											\
																			\
			/* c2 = c2 - t0 - t2. */										\
			S##_sub(c[2], c[2], t0);										\
			S##_sub(c[2], c[2], t2);										\
																			\
			/* c0 = t0 + t1 * E. */											\
			NOR(t4, t1);													\
			S##_add(c[0], t0, t4);											\
																			\
			/* c1 = t3 + t2 * E. */											\
			NOR(t4, t2);													\
			S##_add(c[1], t3, t4);											\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1, t2, t3, t4);								\
		}																	\
	}

/**
 * Defines a template for multiplication by the adjoined root in a quadratic
 * extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_MUL_ART_QUAD(X, S, NOR)									\
	void X##_mul_art(X##_t c, const X##_t a) {								\
		S##_t t0;															\
																			\
		S##_null(t0);														\
																			\
		RLC_TRY {															\
			S##_new(t0);													\
																			\
			/* (a_0 + a_1 * v) * v = a_0 * v + a_1 * v^2 */					\
			S##_copy(t0, a[0]);												\
			NOR(c[0], a[1]);												\
			S##_copy(c[1], t0);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free(t0);													\
		}																	\
	}

/**
 * Defines a template for multiplication by the adjoined root in a cubic
 * extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_MUL_ART_CUBIC(X, S, NOR)									\
	void X##_mul_art(X##_t c, const X##_t a) {								\
		S##_t t0;															\
																			\
		S##_null(t0);														\
																			\
		RLC_TRY {															\
			S##_new(t0);													\
																			\
			/* (a_0 + a_1 * v + a_2 * v^2) * v =							\
			 * a_2 * E + a_0 * v + a_1 * v^2. */							\
			S##_copy(t0, a[0]);												\
			NOR(c[0], a[2]);												\
			S##_copy(c[2], a[1]);											\
			S##_copy(c[1], t0);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free(t0);													\
		}																	\
	}

/**
 * Defines a template for inversion in a quadratic extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_INV_QUAD(X, S, NOR)										\
	void X##_inv(X##_t c, const X##_t a) {									\
		S##_t t0;															\
		S##_t t1;															\
																			\
		S##_null_all(t0, t1);												\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1);											\
																			\
			S##_sqr(t0, a[0]);												\
			S##_sqr(t1, a[1]);												\
			NOR(t1, t1);													\
			S##_sub(t0, t0, t1);											\
			S##_inv(t0, t0);												\
																			\
			S##_mul(c[0], a[0], t0);										\
			S##_neg(c[1], a[1]);											\
			S##_mul(c[1], c[1], t0);										\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1);											\
		}																	\
	}

/**
 * Defines a template for inversion in a cubic extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_INV_CUBIC(X, S, NOR)										\
	void X##_inv(X##_t c, const X##_t a) {									\
		S##_t v0;															\
		S##_t v1;															\
		S##_t v2;															\
		S##_t t0;															\
																			\
		S##_null_all(v0, v1, v2, t0);										\
																			\
		RLC_TRY {															\
			S##_new_all(v0, v1, v2, t0);									\
																			\
			/* v0 = a_0^2 - E * a_1 * a_2. */								\
			S##_sqr(t0, a[0]);												\
			S##_mul(v0, a[1], a[2]);										\
			NOR(v2, v0);													\
			S##_sub(v0, t0, v2);											\
																			\
			/* v1 = E * a_2^2 - a_0 * a_1. */								\
			S##_sqr(t0, a[2]);												\
			NOR(v2, t0);													\
			S##_mul(v1, a[0], a[1]);										\
			S##_sub(v1, v2, v1);											\
																			\
			/* v2 = a_1^2 - a_0 * a_2. */									\
			S##_sqr(t0, a[1]);												\
			S##_mul(v2, a[0], a[2]);										\
			S##_sub(v2, t0, v2);											\
																			\
			S##_mul(t0, a[1], v2);											\
			NOR(c[1], t0);													\
																			\
			S##_mul(c[0], a[0], v0);										\
																			\
			S##_mul(t0, a[2], v1);											\
			NOR(c[2], t0);													\
																			\
			S##_add(t0, c[0], c[1]);										\
			S##_add(t0, t0, c[2]);											\
			S##_inv(t0, t0);												\
																			\
			S##_mul(c[0], v0, t0);											\
			S##_mul(c[1], v1, t0);											\
			S##_mul(c[2], v2, t0);											\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(v0, v1, v2, t0);									\
		}																	\
	}

/**
 * Defines a template for inversion of a unitary element in a quadratic
 * extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 */
#define TMPL_FPX_INV_CYC_QUAD(X, S)											\
	void X##_inv_cyc(X##_t c, const X##_t a) {								\
		S##_copy(c[0], a[0]);												\
		S##_neg(c[1], a[1]);												\
	}

/**
 * Defines a template for inversion of a unitary element in a cubic
 * extension.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 */
#define TMPL_FPX_INV_CYC_CUBIC(X, S)										\
	void X##_inv_cyc(X##_t c, const X##_t a) {								\
		S##_inv_cyc(c[0], a[0]);											\
		S##_inv_cyc(c[1], a[1]);											\
		S##_neg(c[1], c[1]);												\
		S##_inv_cyc(c[2], a[2]);											\
	}

/**
 * Defines a template for exponentiation in an extension field.
 *
 * @param[in] X			- the extension field prefix.
 */
#define TMPL_FPX_EXP(X)														\
	void X##_exp(X##_t c, const X##_t a, const bn_t b) {					\
		X##_t t;															\
																			\
		if (bn_is_zero(b)) {												\
			X##_set_dig(c, 1);												\
			return;															\
		}																	\
																			\
		X##_null(t);														\
																			\
		RLC_TRY {															\
			X##_new(t);														\
																			\
			X##_copy(t, a);													\
																			\
			for (int i = bn_bits(b) - 2; i >= 0; i--) {						\
				X##_sqr(t, t);												\
				if (bn_get_bit(b, i)) {										\
					X##_mul(t, t, a);										\
				}															\
			}																\
																			\
			if (bn_sign(b) == RLC_NEG) {									\
				X##_inv(c, t);												\
			} else {														\
				X##_copy(c, t);												\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			X##_free(t);													\
		}																	\
	}

/**
 * Defines a template for exponentiation in an extension field, switching to
 * faster exponentiation for elements in the cyclotomic subgroup.
 *
 * @param[in] X			- the extension field prefix.
 */
#define TMPL_FPX_EXP_CYC(X)													\
	void X##_exp(X##_t c, const X##_t a, const bn_t b) {					\
		X##_t t;															\
																			\
		if (bn_is_zero(b)) {												\
			X##_set_dig(c, 1);												\
			return;															\
		}																	\
																			\
		X##_null(t);														\
																			\
		RLC_TRY {															\
			X##_new(t);														\
																			\
			if (X##_test_cyc(a)) {											\
				X##_exp_cyc(c, a, b);										\
			} else {														\
				X##_copy(t, a);												\
																			\
				for (int i = bn_bits(b) - 2; i >= 0; i--) {					\
					X##_sqr(t, t);											\
					if (bn_get_bit(b, i)) {									\
						X##_mul(t, t, a);									\
					}														\
				}															\
																			\
				if (bn_sign(b) == RLC_NEG) {								\
					X##_inv(c, t);											\
				} else {													\
					X##_copy(c, t);											\
				}															\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			X##_free(t);													\
		}																	\
	}

/**
 * Defines a template for exponentiation by a digit in an extension field,
 * switching to faster arithmetic in the cyclotomic subgroup.
 *
 * @param[in] X			- the extension field prefix.
 */
#define TMPL_FPX_EXP_DIG(X)													\
	void X##_exp_dig(X##_t c, const X##_t a, dig_t b) {						\
		bn_t _b;															\
		X##_t t, v;															\
		int8_t u, naf[RLC_DIG + 1];											\
		size_t l;															\
																			\
		if (b == 0) {														\
			X##_set_dig(c, 1);												\
			return;															\
		}																	\
																			\
		bn_null(_b);														\
		X##_null_all(t, v);													\
																			\
		RLC_TRY {															\
			bn_new(_b);														\
			X##_new_all(t, v);												\
																			\
			X##_copy(t, a);													\
																			\
			if (X##_test_cyc(a)) {											\
				X##_inv_cyc(v, a);											\
				bn_set_dig(_b, b);											\
																			\
				l = RLC_DIG + 1;											\
				bn_rec_naf(naf, &l, _b, 2);									\
																			\
				for (int i = l - 2; i >= 0; i--) {							\
					X##_sqr_cyc(t, t);										\
																			\
					u = naf[i];												\
					if (u > 0) {											\
						X##_mul(t, t, a);									\
					} else if (u < 0) {										\
						X##_mul(t, t, v);									\
					}														\
				}															\
			} else {														\
				for (int i = util_bits_dig(b) - 2; i >= 0; i--) {			\
					X##_sqr(t, t);											\
					if (b & ((dig_t)1 << i)) {								\
						X##_mul(t, t, a);									\
					}														\
				}															\
			}																\
																			\
			X##_copy(c, t);													\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(_b);													\
			X##_free_all(t, v);												\
		}																	\
	}

/**
 * Computes two products of extension field elements, reduced together in a
 * Residue Number System (BAT), or one after the other for fields without
 * operations on unreduced elements (SEQ). The second product must not read C0.
 *
 * @param[in] X			- the extension field prefix.
 * @param[out] U		- the scratch for two unreduced elements.
 * @param[out] C0		- the first result.
 * @param[in] A0		- the first element of the first product.
 * @param[in] B0		- the second element of the first product.
 * @param[out] C1		- the second result.
 * @param[in] A1		- the first element of the second product.
 * @param[in] B1		- the second element of the second product.
 */
/** @{ */
#define TMPL_FPX_MUL2_BAT(X, U, C0, A0, B0, C1, A1, B1)						\
	TMPL_LAZYR_MULP(X, TMPL_LAZYR_DSTS(C0, C1), TMPL_LAZYR_PTRS(A0, A1),	\
		TMPL_LAZYR_PTRS(B0, B1), U, 2)
#define TMPL_FPX_MUL2_SEQ(X, U, C0, A0, B0, C1, A1, B1)						\
	X##_mul(C0, A0, B0);													\
	X##_mul(C1, A1, B1)
/** @} */

/**
 * Defines a template for simultaneous inversion in an extension field.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] MUL2		- the computation of the two products of each step
 * 						back, TMPL_FPX_MUL2_BAT or TMPL_FPX_MUL2_SEQ.
 */
#define TMPL_FPX_INV_SIM(X, D, MUL2)										\
	void X##_inv_sim(X##_t *c, const X##_t *a, int n) {						\
		int i;																\
		X##_t u, *t = RLC_ALLOCA(X##_t, n);									\
		D##_t v[2];															\
																			\
		for (i = 0; i < n; i++) {											\
			X##_null(t[i]);													\
		}																	\
		X##_null(u);														\
		D##_null_all(v[0], v[1]);											\
																			\
		RLC_TRY {															\
			for (i = 0; i < n; i++) {										\
				X##_new(t[i]);												\
			}																\
			X##_new(u);														\
			D##_new_all(v[0], v[1]);										\
																			\
			X##_copy(c[0], a[0]);											\
			X##_copy(t[0], a[0]);											\
																			\
			for (i = 1; i < n; i++) {										\
				X##_copy(t[i], a[i]);										\
				X##_mul(c[i], c[i - 1], t[i]);								\
			}																\
																			\
			X##_inv(u, c[n - 1]);											\
																			\
			for (i = n - 1; i > 0; i--) {									\
				MUL2(X, v, c[i], c[i - 1], u, u, u, t[i]);					\
			}																\
			X##_copy(c[0], u);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			for (i = 0; i < n; i++) {										\
				X##_free(t[i]);												\
			}																\
			X##_free(u);													\
			D##_free_all(v[0], v[1]);										\
			RLC_FREE(t);													\
		}																	\
	}

/**
 * Gives the pairs of coefficients that cyclotomic squaring combines, in an
 * extension field built as quadratic over cubic (QC) or cubic over quadratic
 * (CQ): for each pair, the positions of x and y and of the coefficients that
 * x^2 + v * y^2 and 2 * x * y define, the latter times v for the second pair.
 */
/** @{ */
#define TMPL_CYC_PAIRS_QC	{ { {0, 0}, {1, 1}, {0, 0}, {1, 1} },			\
	{ {0, 1}, {1, 2}, {0, 2}, {1, 0} }, { {1, 0}, {0, 2}, {0, 1}, {1, 2} } }
#define TMPL_CYC_PAIRS_CQ	{ { {0, 0}, {0, 1}, {0, 0}, {0, 1} },			\
	{ {2, 0}, {2, 1}, {1, 1}, {1, 0} }, { {1, 0}, {1, 1}, {2, 0}, {2, 1} } }
/** @} */

/**
 * Defines a template for the terms of a cyclotomic squaring without reduction,
 * as fp12_sqrc_low() computes them: each pair (x, y) is squared as x + y * w
 * in the quadratic extension of the subfield, and the results go to the
 * coefficients they define. In a Residue Number System, the terms t are
 * combined with a into the whole unreduced square, c_0 = 3 * t_0 - 2 * a_0 and
 * c_1 = 3 * t_1 + 2 * a_1, so that each squaring is reduced once.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] Z			- the prefix of the subfield holding the coefficients.
 * @param[in] DZ		- the double-precision subfield prefix.
 * @param[in] Y			- the prefix of the quadratic extension of the subfield.
 * @param[in] DY		- the double-precision prefix of that extension.
 * @param[in] B			- the base field prefix with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] SQRU		- the squaring in that extension without reduction.
 * @param[in] L			- the layout of the field, QC or CQ.
 */
#define TMPL_FPX_SQR_CYC_UNR(F, X, D, Z, DZ, Y, DY, B, BD, N, Q, SQRU, L)	\
	void F(D##_t c, const X##_t a) {										\
		static const int _pairs[3][4][2] = TMPL_CYC_PAIRS_##L;				\
		const size_t _n = sizeof(DZ##_t) / sizeof(dv_t);					\
		Y##_t t;															\
		DY##_t u;															\
		fp_t k;																\
																			\
		Y##_null(t);														\
		DY##_null(u);														\
		fp_null(k);															\
																			\
		RLC_TRY {															\
			Y##_new(t);														\
			DY##_new(u);													\
			fp_new(k);														\
																			\
			for (int _p = 0; _p < 3; _p++) {								\
				int _i = _pairs[_p][2][0], _j = _pairs[_p][2][1];			\
				int _r = _pairs[_p][3][0], _s = _pairs[_p][3][1];			\
																			\
				Z##_copy(t[0], a[_pairs[_p][0][0]][_pairs[_p][0][1]]);		\
				Z##_copy(t[1], a[_pairs[_p][1][0]][_pairs[_p][1][1]]);		\
				/* (x + y * w)^2 gives x^2 + v * y^2 and 2 * x * y. */		\
				SQRU(u, t);													\
				for (size_t _l = 0; _l < _n; _l++) {						\
					dv_copy(((dv_t *)c[_i][_j])[_l], ((dv_t *)u[0])[_l],	\
							RLC_FP_DLEN);									\
				}															\
				if (_p == 1) {												\
					TMPL_DV_NOR(B, BD, N, Q, c[_r][_s], u[1]);				\
				} else {													\
					for (size_t _l = 0; _l < _n; _l++) {					\
						dv_copy(((dv_t *)c[_r][_s])[_l], ((dv_t *)u[1])[_l],\
								RLC_FP_DLEN);								\
					}														\
				}															\
			}																\
			/* c_0 = 3 * t_0 - 2 * a_0 and c_1 = 3 * t_1 + 2 * a_1 for each	\
			 * pair, with 2 * a as a product, so that the square needs one	\
			 * reduction. */												\
			for (int _p = 0; _p < 3; _p++) {								\
				for (int _r = 0; _r < 2; _r++) {							\
					int _i = _pairs[_p][2 + _r][0];							\
					int _j = _pairs[_p][2 + _r][1];							\
					dv_t *_c = (dv_t *)c[_i][_j];							\
					const fp_t *_a = (const fp_t *)a[_i][_j];				\
																			\
					fp_add(k, core_get()->one, core_get()->one);			\
					if (_r == 0) {											\
						fp_neg(k, k);										\
					}														\
					for (size_t _l = 0; _l < _n; _l++) {					\
						rlc_align dig_t _w[RLC_FP_DLEN];					\
																			\
						fp_addc_low(_w, _c[_l], _c[_l]);					\
						fp_addc_low(_c[_l], _c[_l], _w);					\
						fp_muln_low(_w, _a[_l], k);							\
						fp_addc_low(_c[_l], _c[_l], _w);					\
					}														\
				}															\
			}																\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			Y##_free(t);													\
			DY##_free(u);													\
			fp_free(k);														\
		}																	\
	}

/**
 * Defines a template for testing quadratic residuosity in an extension field
 * of degree K, by testing the norm in the prime field.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] K			- the degree of the extension.
 */
#define TMPL_FPX_IS_SQR(X, K)												\
	int X##_is_sqr(const X##_t a) {											\
		X##_t t, u;															\
		int r;																\
																			\
		X##_null_all(t, u);													\
																			\
		RLC_TRY {															\
			X##_new_all(t, u);												\
																			\
			X##_frb(u, a, 1);												\
			X##_mul(t, u, a);												\
			for (int i = 2; i < (K); i++) {									\
				X##_frb(u, u, 1);											\
				X##_mul(t, t, u);											\
			}																\
			r = fp_is_sqr(((fp_t *)t)[0]);									\
		} RLC_CATCH_ANY {													\
			r = 0;															\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			X##_free_all(t, u);												\
		}																	\
																			\
		return r;															\
	}

/**
 * Defines a template for computing square roots in a quadratic extension field,
 * using the norm to reduce to square roots in the subfield.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 * @param[in] H			- the number of prime field coefficients in the subfield.
 */
#define TMPL_FPX_SRT_QUAD(X, S, NOR, H)										\
	int X##_srt(X##_t c, const X##_t a) {									\
		int c0, r = 0;														\
		S##_t t0, t1, t2;													\
																			\
		S##_null_all(t0, t1, t2);											\
																			\
		if (X##_is_zero(a)) {												\
			X##_zero(c);													\
			return 1;														\
		}																	\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1, t2);										\
																			\
			if (S##_is_zero(a[1])) {										\
				/* Either a[0] is a square and the root is purely 'real',	\
				 * or it is not and the root is purely 'imaginary'. The		\
				 * square root tells which. */								\
				r = 1;														\
				if (S##_srt(t0, a[0])) {									\
					/* Through t0, as c may alias a. */						\
					S##_copy(c[0], t0);										\
					S##_zero(c[1]);											\
				} else {													\
					/* Compute a[0]/s^2. */									\
					S##_set_dig(t0, 1);										\
					NOR(t0, t0);											\
					S##_inv(t0, t0);										\
					S##_mul(t0, a[0], t0);									\
					S##_zero(c[0]);											\
					if (!S##_srt(c[1], t0)) {								\
						/* should never happen! */							\
						RLC_THROW(ERR_NO_VALID);							\
					}														\
				}															\
			} else {														\
				/* t0 = a[0]^2 - s^2 * a[1]^2 */							\
				S##_sqr(t0, a[0]);											\
				S##_sqr(t1, a[1]);											\
				NOR(t2, t1);												\
				S##_sub(t0, t0, t2);										\
																			\
				/* The square root tells whether t0 is a square. */			\
				if (S##_srt(t1, t0)) {										\
					/* t0 = (a_0 + sqrt(t0)) / 2 */							\
					S##_add(t0, a[0], t1);									\
					for (int i = 0; i < (H); i++) {							\
						fp_hlv(((fp_t *)t0)[i], ((fp_t *)t0)[i]);			\
					}														\
					c0 = S##_is_sqr(t0);									\
					/* t0 = (a_0 - sqrt(t0)) / 2 */							\
					S##_sub(t1, a[0], t1);									\
					for (int i = 0; i < (H); i++) {							\
						fp_hlv(((fp_t *)t1)[i], ((fp_t *)t1)[i]);			\
					}														\
					S##_copy_sec(t0, t1, !c0);								\
					/* Should always be a quadratic residue. */				\
					S##_srt(t2, t0);										\
					/* c_0 = sqrt(t0) */									\
					S##_copy(c[0], t2);										\
																			\
					/* c_1 = a_1 / (2 * sqrt(t0)) */						\
					S##_dbl(t2, t2);										\
					S##_inv(t2, t2);										\
					S##_mul(c[1], a[1], t2);								\
					r = 1;													\
				}															\
			}																\
		} RLC_CATCH_ANY {													\
			r = 0;															\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1, t2);										\
		}																	\
		return r;															\
	}

/**
 * Defines a template for multiplication with lazy reduction, computing the
 * result without reduction and reducing each base field component once.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] B			- the base field prefix with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components.
 */
#define TMPL_FPX_MUL_LAZYR(X, D, B, BD, N)									\
	void X##_mul_lazyr(X##_t c, const X##_t a, const X##_t b) {				\
		D##_t t;															\
																			\
		D##_null(t);														\
																			\
		RLC_TRY {															\
			D##_new(t);														\
			X##_mul_unr(t, a, b);											\
			B##_rdcv_low((B##_t *)c, (BD##_t *)t, (N));						\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			D##_free(t);													\
		}																	\
	}

/**
 * Defines a template for squaring with lazy reduction, computing the
 * result without reduction and reducing each base field component once.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] B			- the base field prefix with low-level arithmetic.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of base field components.
 */
#define TMPL_FPX_SQR_LAZYR(X, D, B, BD, N)									\
	void X##_sqr_lazyr(X##_t c, const X##_t a) {							\
		D##_t t;															\
																			\
		D##_null(t);														\
																			\
		RLC_TRY {															\
			D##_new(t);														\
			X##_sqr_unr(t, a);												\
			B##_rdcv_low((B##_t *)c, (BD##_t *)t, (N));						\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			D##_free(t);													\
		}																	\
	}

/**
 * Defines a template for the sum and the difference of two products with lazy
 * reduction, adding the products before reducing them once.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] D			- the double-precision extension field prefix.
 */
#define TMPL_FPX_MUL_ADD_LAZYR(X, D)										\
	void X##_mul_add(X##_t c, const X##_t a, const X##_t b, const X##_t d,	\
			const X##_t e) {												\
		D##_t t, u;															\
																			\
		D##_null_all(t, u);													\
																			\
		RLC_TRY {															\
			D##_new_all(t, u);												\
			X##_muln_low(t, a, b);											\
			X##_muln_low(u, d, e);											\
			X##_addc_low(t, t, u);											\
			X##_rdcn_low(c, t);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			D##_free_all(t, u);												\
		}																	\
	}																		\
																			\
	void X##_mul_sub(X##_t c, const X##_t a, const X##_t b, const X##_t d,	\
			const X##_t e) {												\
		D##_t t, u;															\
																			\
		D##_null_all(t, u);													\
																			\
		RLC_TRY {															\
			D##_new_all(t, u);												\
			X##_muln_low(t, a, b);											\
			X##_muln_low(u, d, e);											\
			X##_subc_low(t, t, u);											\
			X##_rdcn_low(c, t);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			D##_free_all(t, u);												\
		}																	\
	}

/**
 * Defines a template for the sum and the difference of two products, reducing
 * each product.
 *
 * @param[in] X			- the extension field prefix.
 */
#define TMPL_FPX_MUL_ADD(X)													\
	void X##_mul_add(X##_t c, const X##_t a, const X##_t b, const X##_t d,	\
			const X##_t e) {												\
		X##_t t;															\
																			\
		X##_null(t);														\
																			\
		RLC_TRY {															\
			X##_new(t);														\
			X##_mul(t, a, b);												\
			X##_mul(c, d, e);												\
			X##_add(c, t, c);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			X##_free(t);													\
		}																	\
	}																		\
																			\
	void X##_mul_sub(X##_t c, const X##_t a, const X##_t b, const X##_t d,	\
			const X##_t e) {												\
		X##_t t;															\
																			\
		X##_null(t);														\
																			\
		RLC_TRY {															\
			X##_new(t);														\
			X##_mul(t, a, b);												\
			X##_mul(c, d, e);												\
			X##_sub(c, t, c);												\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			X##_free(t);													\
		}																	\
	}

/**
 * Defines a template for Karatsuba multiplication in a quadratic extension
 * without reduction.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] DS			- the double-precision subfield prefix.
 * @param[in] B			- the base field prefix with low-level arithmetic.
 * @param[in] BD			- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] MULU		- the multiplication in the subfield without reduction.
 */
#define TMPL_FPX_MUL_UNR_QUAD(F, X, S, D, DS, B, BD, N, Q, MULU)			\
	void F(D##_t c, const X##_t a, const X##_t b) {							\
		S##_t t0, t1;														\
		DS##_t u0, u1, u2;													\
																			\
		S##_null_all(t0, t1);												\
		DS##_null_all(u0, u1, u2);											\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1);											\
			DS##_new_all(u0, u1, u2);										\
																			\
			/* Karatsuba algorithm. */										\
			MULU(u0, a[0], b[0]);											\
			MULU(u1, a[1], b[1]);											\
			S##_add(t0, a[0], a[1]);										\
			S##_add(t1, b[0], b[1]);										\
			MULU(u2, t0, t1);												\
			/* c_1 = (a_0 + a_1)(b_0 + b_1) - a_0b_0 - a_1b_1. */			\
			TMPL_DV_SUBC(B, BD, N, c[1], u2, u0);							\
			TMPL_DV_SUBC(B, BD, N, c[1], c[1], u1);							\
			/* c_0 = a_0b_0 + v * a_1b_1. */								\
			TMPL_DV_NADD(B, BD, N, Q, c[0], u0, u1);						\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1);											\
			DS##_free_all(u0, u1, u2);										\
		}																	\
	}

/**
 * Defines a template for squaring in a quadratic extension without reduction.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] DS			- the double-precision subfield prefix.
 * @param[in] B			- the base field prefix with low-level arithmetic.
 * @param[in] BD			- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] SQRU		- the squaring in the subfield without reduction.
 */
#define TMPL_FPX_SQR_UNR_QUAD(F, X, S, D, DS, B, BD, N, Q, SQRU)			\
	void F(D##_t c, const X##_t a) {										\
		S##_t t;															\
		DS##_t u0, u1;														\
																			\
		S##_null_all(t);													\
		DS##_null_all(u0, u1);												\
																			\
		RLC_TRY {															\
			S##_new_all(t);													\
			DS##_new_all(u0, u1);											\
																			\
			SQRU(u0, a[0]);													\
			SQRU(u1, a[1]);													\
			S##_add(t, a[0], a[1]);											\
			/* c_0 = a_0^2 + v * a_1^2. */									\
			TMPL_DV_NADD(B, BD, N, Q, c[0], u0, u1);						\
			/* c_1 = (a_0 + a_1)^2 - a_0^2 - a_1^2. */						\
			TMPL_DV_ADDC(B, BD, N, u1, u1, u0);								\
			SQRU(u0, t);													\
			TMPL_DV_SUBC(B, BD, N, c[1], u0, u1);							\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t);												\
			DS##_free_all(u0, u1);											\
		}																	\
	}

/**
 * Defines a template for Chung-Hasan squaring in a cubic extension without
 * reduction.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] DS			- the double-precision subfield prefix.
 * @param[in] B			- the base field prefix with low-level arithmetic.
 * @param[in] BD			- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] SQRU		- the squaring in the subfield without reduction.
 * @param[in] MULU		- the multiplication in the subfield without reduction.
 * @param[in] H			- the number of prime field coefficients in the subfield.
 */
#define TMPL_FPX_SQR_UNR_CUBIC(F, X, S, D, DS, B, BD, N, Q, SQRU, MULU, H)	\
	void F(D##_t c, const X##_t a) {										\
		S##_t t0, t1, t2;													\
		DS##_t u0, u1, u2, u3, u4, u5;										\
																			\
		S##_null_all(t0, t1, t2);											\
		DS##_null_all(u0, u1, u2, u3, u4, u5);								\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1, t2);										\
			DS##_new_all(u0, u1, u2, u3, u4, u5);							\
																			\
			/* u0 = a_0^2, u1 = 2 * a_1 * a_2, u2 = a_2^2. */				\
			SQRU(u0, a[0]);													\
			S##_dbl(t0, a[1]);												\
			MULU(u1, t0, a[2]);												\
			SQRU(u2, a[2]);													\
			/* u3 = (a_0 + a_2 + a_1)^2, u4 = (a_0 + a_2 - a_1)^2. */		\
			S##_add(t2, a[0], a[2]);										\
			S##_add(t1, t2, a[1]);											\
			SQRU(u3, t1);													\
			S##_sub(t1, t2, a[1]);											\
			SQRU(u4, t1);													\
			/* u4 = (u4 + u3)/2. */											\
			TMPL_DV_ADDC(B, BD, N, u4, u4, u3);								\
			for (int i = 0; i < (H); i++) {									\
				fp_hlvd_low(((dv_t *)u4)[i], ((dv_t *)u4)[i]);				\
			}																\
			/* u3 = u3 - u4 - u1. */										\
			TMPL_DV_ADDC(B, BD, N, u5, u1, u4);								\
			TMPL_DV_SUBC(B, BD, N, u3, u3, u5);								\
			/* c_2 = u4 - u0 - u2. */										\
			TMPL_DV_ADDC(B, BD, N, u5, u0, u2);								\
			TMPL_DV_SUBC(B, BD, N, c[2], u4, u5);							\
			/* c_0 = u0 + v * u1, c_1 = u3 + v * u2. */						\
			TMPL_DV_NADD(B, BD, N, Q, c[0], u0, u1);						\
			TMPL_DV_NADD(B, BD, N, Q, c[1], u3, u2);						\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1, t2);										\
			DS##_free_all(u0, u1, u2, u3, u4, u5);							\
		}																	\
	}

/**
 * Defines a template for Karatsuba multiplication in a cubic extension without
 * reduction.
 *
 * @param[in] F			- the name of the function.
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] D			- the double-precision extension field prefix.
 * @param[in] DS			- the double-precision subfield prefix.
 * @param[in] B			- the base field prefix with low-level arithmetic.
 * @param[in] BD			- the double-precision base field prefix.
 * @param[in] N			- the number of base field components in the subfield.
 * @param[in] Q			- the number of outer components in the subfield.
 * @param[in] MULU		- the multiplication in the subfield without reduction.
 */
#define TMPL_FPX_MUL_UNR_CUBIC(F, X, S, D, DS, B, BD, N, Q, MULU)			\
	void F(D##_t c, const X##_t a, const X##_t b) {							\
		S##_t t0, t1;														\
		DS##_t u0, u1, u2, u3, u4;											\
																			\
		S##_null_all(t0, t1);												\
		DS##_null_all(u0, u1, u2, u3, u4);									\
																			\
		RLC_TRY {															\
			S##_new_all(t0, t1);											\
			DS##_new_all(u0, u1, u2, u3, u4);								\
																			\
			/* Karatsuba algorithm. */										\
			MULU(u0, a[0], b[0]);											\
			MULU(u1, a[1], b[1]);											\
			MULU(u2, a[2], b[2]);											\
			/* c_0 = a_0b_0 + v * (a_1b_2 + a_2b_1). */						\
			S##_add(t0, a[1], a[2]);										\
			S##_add(t1, b[1], b[2]);										\
			MULU(u3, t0, t1);												\
			TMPL_DV_SUBC(B, BD, N, u3, u3, u1);								\
			TMPL_DV_SUBC(B, BD, N, u3, u3, u2);								\
			TMPL_DV_NADD(B, BD, N, Q, c[0], u0, u3);						\
			/* c_1 = a_0b_1 + a_1b_0 + v * a_2b_2. */						\
			S##_add(t0, a[0], a[1]);										\
			S##_add(t1, b[0], b[1]);										\
			MULU(u4, t0, t1);												\
			TMPL_DV_SUBC(B, BD, N, u4, u4, u0);								\
			TMPL_DV_SUBC(B, BD, N, u4, u4, u1);								\
			TMPL_DV_NADD(B, BD, N, Q, c[1], u4, u2);						\
			/* c_2 = a_0b_2 + a_1b_1 + a_2b_0. */							\
			S##_add(t0, a[0], a[2]);										\
			S##_add(t1, b[0], b[2]);										\
			MULU(u4, t0, t1);												\
			TMPL_DV_SUBC(B, BD, N, u4, u4, u0);								\
			TMPL_DV_ADDC(B, BD, N, u4, u4, u1);								\
			TMPL_DV_SUBC(B, BD, N, c[2], u4, u2);							\
		} RLC_CATCH_ANY {													\
			RLC_THROW(ERR_CAUGHT);											\
		} RLC_FINALLY {														\
			S##_free_all(t0, t1);											\
			DS##_free_all(u0, u1, u2, u3, u4);								\
		}																	\
	}

/**
 * Defines a template for testing quadratic residuosity and extracting square
 * roots in a quadratic extension of a subfield.
 *
 * @param[in] X			- the extension field prefix.
 * @param[in] S			- the subfield prefix.
 * @param[in] NOR		- the multiplication by the non-residue in the subfield.
 */
#define TMPL_FPX_SRT(X, S, NOR)												\
	TMPL_FPX_IS_SQR(X, (int)(sizeof(X##_t) / sizeof(fp_t)))					\
	TMPL_FPX_SRT_QUAD(X, S, NOR, (int)(sizeof(S##_t) / sizeof(fp_t)))
