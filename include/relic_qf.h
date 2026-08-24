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
 * @defgroup qf Quadratic form arithmetic
 */

/**
 * @file
 *
 * Interface of the module for binary quadratic form arithmetic.
 *
 * The implementation is partially inspired by the BICYCL library:
 * "BICYCL Implements CryptographY in CLass groups" by Cyril Bouvier,
 * Guilhem Castagnos, Laurent Imbert, and Fabien Laguillaumie.
 * https://eprint.iacr.org/2022/1466
 *
 * Binary quadratic forms are represented as triples (a, b, c)
 * corresponding to the polynomial
 *
 *     ax^2 + bxy + cy^2
 *
 * with discriminant
 *
 *     D = b^2 - 4ac.
 *
 * The implementation operates primarily on positive definite forms.
 * Public operations return reduced forms whenever applicable. Reduced
 * forms provide canonical representatives of ideal classes, allowing
 * qf_cmp() to be used for class equality.
 *
 * @ingroup qf
 */

#ifndef RLC_QF_H
#define RLC_QF_H

#include "relic_conf.h"
#include "relic_bn.h"
#include "relic_util.h"
#include "relic_types.h"
#include "relic_label.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/


/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Binary quadratic form (a, b, c).
 *
 * Represents the quadratic polynomial
 *
 *     ax^2 + bxy + cy^2
 *
 * of discriminant b^2 - 4ac. For positive definite forms, a > 0 and
 * the discriminant is negative. Forms manipulated by the public API are
 * normally reduced, providing canonical representatives of their classes.
 */
typedef struct {
	/** The first coefficient of the quadratic form. */
	bn_t a;
	/** The middle coefficient of the quadratic form. */
	bn_t b;
	/** The third coefficient of the quadratic form. */
	bn_t c;
} qf_st;

/**
 * Pointer to a binary quadratic form structure.
 */
#if ALLOC == AUTO
typedef qf_st qf_t[1];
#elif ALLOC == DYNAMIC
#ifdef CHECK
typedef qf_st *volatile qf_t;
#else
typedef qf_st *qf_t;
#endif
#endif

/*============================================================================*/
/* Macro definitions                                                         */
/*============================================================================*/

/**
 * Initializes a quadratic form with a null value.
 *
 * @param[out] A			- the quadratic form to initialize.
 */
#define qf_null(A)			RLC_NULL(A)

/**
 * Calls a function to allocate and initialize a quadratic form.
 *
 * @param[out] A			- the new quadratic form.
 */
#if ALLOC == DYNAMIC
#define qf_new(A)															\
	A = (qf_t)calloc(1, sizeof(qf_st));										\
	if (A == NULL) {														\
		RLC_THROW(ERR_NO_MEMORY);											\
	}																		\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);

#elif ALLOC == AUTO
#define qf_new(A)															\
	bn_new((A)->a);															\
	bn_new((A)->b);															\
	bn_new((A)->c);

#endif

/**
 * Calls a function to clean and free a quadratic form.
 *
 * @param[out] A			- the quadratic form to clean and free.
 */
#if ALLOC == DYNAMIC
#define qf_free(A)															\
	if (A != NULL) {														\
		bn_free((A)->a);													\
		bn_free((A)->b);													\
		bn_free((A)->c);													\
		free(A);															\
		A = NULL;															\
	}

#elif ALLOC == AUTO
#define qf_free(A)				/* empty */

#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the class group represented in binary quadratic form.
 */
void qf_group_init(void);

/**
 * Finalizes the class group represented in binary quradratic form.
 */
void qf_group_clean(void);

/**
 * Builds a pair of discriminants for an imaginary quadratic order and its
 * maximal order.
 *
 * Taking Delta_K = -p*q and Delta = Delta_K*q^2 puts the two in
 * the relation the order maps expect, and Delta_K = 1 mod 4 requires p*q = 3
 * mod 4, so exactly one of the two primes is 3 mod 4.
 *
 * @param[in] cond			- the bit length of the conductor q.
 * @param[in] bits			- the bit length of the discriminant.
 * @return RLC_OK if it was possible to find discriminants, RLC_ERR otherwise.
 */
int qf_group_gen(size_t cond, size_t bits);

/**
 * Generates a discriminant for an imaginary quadratic order and its
 * maximal order, given a predefined conductor.
 *
 * @param[in] q				- the bit length of the conductor q.
 * @param[in] bits			- the bit length of the discriminant.
 * @return RLC_OK if it was possible to find discriminants, RLC_ERR otherwise.
 */
int qf_group_set_cond(const bn_t q, size_t bits);

int qf_group_set_both(const bn_t q, const bn_t p);

/**
 * Copies a quadratic form.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the quadratic form to copy.
 */
void qf_copy(qf_t c, const qf_t a);

/**
 * Negates a quadratic form.
 *
 * Given a form (a, b, c), computes its inverse class by negating the
 * middle coefficient, producing (a, -b, c).
 *
 * @param[out] f			- the result.
 * @param[in] g				- the quadratic form to negate.
 */
void qf_neg(qf_t f, const qf_t g);

/**
 * Compares two quadratic forms.
 *
 * The comparison is performed on the reduced representatives of the
 * corresponding classes. Consequently, a zero return value indicates
 * equality of the represented classes.
 *
 * @param[in] f				- the first quadratic form.
 * @param[in] g				- the second quadratic form.
 * @return 0 if the forms represent the same class, a negative value if
 *		f is smaller than g, and a positive value otherwise.
 */
int qf_cmp(const qf_t f, const qf_t g);

/**
 * Tests whether a quadratic form represents the identity class.
 *
 * @param[in] f				- the quadratic form to test.
 * @return 1 if the form is the identity, 0 otherwise.
 */
int qf_is_one(const qf_t f);

/**
 * Sets a quadratic form from machine-word integers.
 *
 * The resulting form is (a, b, c).
 *
 * @param[out] f			- the quadratic form to set.
 * @param[in] a				- the first coefficient.
 * @param[in] b				- the middle coefficient.
 * @param[in] c				- the third coefficient.
 */
void qf_set_dig(qf_t f, dig_t a, dig_t b, dig_t c);

/**
 * Sets a quadratic form from signed integers.
 *
 * The resulting form is (a, b, c).
 *
 * @param[out] f			- the quadratic form to set.
 * @param[in] a				- the first coefficient.
 * @param[in] b				- the middle coefficient.
 * @param[in] c				- the third coefficient.
 */
void qf_set_int(qf_t f, int a, int b, int c);

/**
 * Sets a quadratic form to the identity class.
 *
 * The identity form is constructed for the specified discriminant.
 *
 * @param[out] r			- the identity quadratic form.
 * @param[in] d				- the discriminant.
 */
void qf_set_one(qf_t r, const bn_t d);

/**
 * Sets a quadratic form from two coefficients and its discriminant.
 *
 * Computes a form (a, b, c) satisfying
 *
 *     b^2 - 4ac = d.
 *
 * @param[out] f			- the quadratic form to set.
 * @param[in] a				- the first coefficient.
 * @param[in] b				- the middle coefficient.
 * @param[in] d				- the discriminant.
 */
void qf_set_dsc(qf_t f, const bn_t a, const bn_t b, const bn_t d);

/**
 * Compute the discriminant of a quadratic binary form.
 *
 * @param[out] d			- the computed discriminant.
 * @param[in] f				- the binary quadratic form to compute.
 */
void qf_get_dsc(bn_t d, const qf_t f);

/**
 * Tests if a quadratic binary form has the correct discrimnant.
 *
 * @param[in] f				- the binary quadratic form to test.
 * @param[in] d				- the discriminant.
 * @return a boolean value indicating if the discrimnant is correct.
 */
int qf_has_dsc(const qf_t f, const bn_t d);

/**
 * Generates a random element of the group with the given discriminant.
 *
 * @param[out] f			- the generated random element.
 * @param[in] d				- the discriminant.
 */
void qf_rand(qf_t f, const bn_t d);

/**
 * Prints a quadratic form.
 *
 * @param[in] f				- the quadratic form to print.
 */
void qf_print(const qf_t f);

/**
 * Composes two binary quadratic forms.
 *
 * Computes the class group composition of f and g and stores the result
 * in r. The result is reduced according to the supplied discriminant
 * bound.
 *
 * If neg is non-zero, the second operand is first replaced by its inverse
 * class.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the first quadratic form to compose.
 * @param[in] g				- the second quadratic form to compose.
 * @param[in] neg			- the flag to negate the second operand.
 * @param[in] d				- the discriminant bound.
 */
void qf_com(qf_t r, const qf_t f, const qf_t g, int neg, const bn_t d);

/**
 * Duplicates a binary quadratic form.
 *
 * Computes the class-group square of f.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the quadratic form to duplicate.
 * @param[in] d				- the discriminant bound.
 */
void qf_dup(qf_t r, const qf_t f, const bn_t d);

/**
 * Normalizes a quadratic form.
 *
 * Adjusts the representation of a quadratic form without changing its
 * represented class.
 *
 * @param[out] f			- the normalized quadratic form.
 * @param[in] g				- the quadratic form to normalize.
 */
void qf_norm(qf_t f, const qf_t g);

/**
 * Lifts a quadratic form with respect to a prime or modulus.
 *
 * Constructs a form representing the corresponding lifted class for the
 * supplied integer.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the quadratic form to lift.
 */
void qf_lift(qf_t r, const qf_t f);

/**
 * Constructs a quadratic form associated with a prime.
 *
 * Constructs a form representing the class associated with the supplied
 * prime and discriminant.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] l				- the prime.
 * @param[in] dsc			- the discriminant.
 */
void qf_prime(qf_t r, dig_t l, const bn_t dsc);

/**
 * Computes the coprime adjustment of a quadratic form.
 *
 * Modifies f so that its leading coefficient satisfies the required
 * coprimality condition with respect to the conductor.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the quadratic form to adjust.
 */
void qf_copa(qf_t r, const qf_t f);

/**
 * Moves a quadratic form to the maximal order.
 *
 * Given a quadratic form in an order of the quadratic field, transforms
 * it into the corresponding form in the maximal order by removing the
 * conductor contribution from its representation.
 *
 * If rdc is non-zero, the resulting form is reduced.
 *
 * @param[out] f			- the resulting quadratic form.
 * @param[in] f				- the quadratic form to transform.
 * @param[in] rdc			- the flag indicating whether to reduce the result.
 */
void qf_phi(qf_t r, const qf_t f, int rdc);

/**
 * Maps a form from the maximal order into the order of the given conductor,
 * as a group homomorphism.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the form to map.
 * @param[in] l				- the conductor.
 * @param[in] d				- the discriminant of the order of conductor q.
 * @param[in] b				- the bound for arithmetic.
 */
void qf_psi(qf_t r, const qf_t f, const bn_t d, const bn_t b);

/**
 * Computes a kernel representative.
 *
 * Computes the representative associated with the kernel of the class-group
 * action induced by the quadratic form.
 *
 * @param[out] r			- the kernel representative.
 * @param[in] f				- the quadratic form representing the class action.
 */
void qf_kern(bn_t r, const qf_t f);

/**
 * Reduces a binary quadratic form.
 *
 * Computes the canonical reduced representative equivalent to a.
 *
 * @param[out] c			- the reduced quadratic form.
 * @param[in] a				- the quadratic form to reduce.
 */
void qf_rdc(qf_t c, const qf_t a);

/* Computes an Upper bound on the class number h(\Delta).
 *
 * It approximates (1/\pi)·sqrt(|\Delta|) * ln|\Delta|, using integer only.
 *
 * @param[out] bound			- the computed class number bound.
 * @param[in] dsc				- the discriminant.
 */
void qf_class(bn_t bound, const bn_t dsc);

/**
 * Raises a quadratic form to an integer power.
 *
 * Computes the class-group exponentiation
 *
 *     r = f^n.
 *
 * The result is reduced according to the supplied bound.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the quadratic form to exponentiate.
 * @param[in] n				- the exponent.
 * @param[in] bound			- the reduction bound.
 */
void qf_exp(qf_t r, const qf_t f, const bn_t n, const bn_t dsc,
		const bn_t bnd);

/**
 * Simultaneously raises two quadratic forms to integer powers.
 *
 * Computes
 *
 *     r = f0^n0 * f1^n1.
 *
 * The operation uses a joint exponentiation strategy and reduces the
 * result according to the supplied bound.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f0			- the first quadratic form.
 * @param[in] n0			- the first exponent.
 * @param[in] f1			- the second quadratic form.
 * @param[in] n1			- the second exponent.
 * @param[in] bound			- the reduction bound.
 */
void qf_exp_sim(qf_t r, const qf_t f0, const bn_t n0, const qf_t f1,
		const bn_t n1, const bn_t dsc, const bn_t bnd);

/**
 * Raises a quadratic form to an integer power using a fixed
 * precomputation table.
 *
 * Computes f^n using precomputed powers supplied by the caller.
 * The parameters d and e describe the decomposition used by the
 * fixed-window exponentiation strategy.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the quadratic form to exponentiate.
 * @param[in] n				- the exponent.
 * @param[in] d				- the number of precomputation entries.
 * @param[in] e				- the window size.
 * @param[in] fe			- the precomputed form f^e.
 * @param[in] fd			- the precomputed form f^d.
 * @param[in] fde			- the precomputed form f^(d*e).
 * @param[in] bound			- the reduction bound.
 */
void qf_exp_fix(qf_t r, const qf_t f, const bn_t n, size_t d, size_t e,
		const qf_t fe, const qf_t fd, const qf_t fde, const bn_t dsc,
		const bn_t bnd);

#endif /* !RLC_QF_H */