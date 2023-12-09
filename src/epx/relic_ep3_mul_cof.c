/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of point multiplication of a prime elliptic curve over a
 * quadratic extension by the curve cofactor.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_tmpl_map.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies a point by the cofactor in a KSS18 curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep3_mul_cof_k18(ep3_t r, const ep3_t p) {
	ep3_t t0, t1, t2, t3, t4, t5;
	bn_t x;

	ep3_null(t0);
	ep3_null(t1);
	ep3_null(t2);
	ep3_null(t3);
	ep3_null(t4);
	ep3_null(t5);
	bn_null(x);

	RLC_TRY {
		ep3_new(t0);
		ep3_new(t1);
		ep3_new(t2);
		ep3_new(t3);
		ep3_new(t4);
		ep3_new(t5);
		bn_new(x);

		/* Method from "Faster Hashing to G2" by Laura Fuentes-Castañeda,
		 * Edward Knapp and Francisco Rodríguez-Henríquez.
		. */

		/* Compute multi-addition-subtraction chain \sum \lambda_i \psi^P, where
		 * \lambda_0 = 5u + 18
		 * \lambda_1 = (u^3+3u^2+1)
		 * \lambda_2 = -(3u^2+8*u)
		 * \lambda_3 = (3u+1)
		 * \lambda_4 = -(u^2+2)
		 * \lambda_5 = (u^2+5u)

		 * We will write the subscalars below as vectors for simplicity.
		 */

		fp_prime_get_par(x);

		/* t0 = [u]P, t4 = [u^2]P, later t2 = [u^3]P. */
		ep3_mul_basic(t0, p, x);
		ep3_mul_basic(t4, t0, x);

		/* t1 = [1, 0, -u, 0, 0, 0]. */
		ep3_frb(t1, t0, 2);
		/* t2 = [u, 0, 0, 0, 0, u]. */
		ep3_frb(t2, t1, 3);
		ep3_add(t2, t2, t0);
		/* t3 = [0, 0, 0, -u, 0, 0]. */
		ep3_frb(t3, t1, 1);
		ep3_neg(t1, t1);
		ep3_add(t1, t1, p);
		/* t0 = [u+3, 0, -u, 0, 0, u]. */
		ep3_dbl(t0, p);
		ep3_add(t0, t0, t2);
		ep3_add(t0, t0, t1);

		/* t2 = [0, 0, u^2, 0, 0, 0], t3 = [0, u^2, -u^2, -u, 0, 0]. */
		ep3_frb(t2, t4, 1);
		ep3_add(t3, t3, t2);
		ep3_frb(t2, t2, 1);
		ep3_sub(t3, t3, t2);

		/* t5 = [0, u^3 + 1, 0, 1, -u^2, u^2] */
		ep3_frb(t5, p, 1);
		ep3_frb(t2, t5, 2);
		ep3_add(t5, t5, t2);
		ep3_frb(t2, t4, 4);
		ep3_sub(t5, t5, t2);
		ep3_frb(t2, t2, 1);
		ep3_add(t5, t5, t2);
		ep3_mul_basic(t2, t4, x);
		ep3_frb(t2, t2, 1);
		ep3_add(t5, t5, t2);

		/* t4 = [0, 0, 0, 0, -1, 0], t3 = [1, u^2, -u^2-u, -u, 0, 0]. */
		ep3_frb(t4, p, 4);
		ep3_neg(t4, t4);
		ep3_add(t3, t3, t1);
		/* t4 = [u+3, 0, -u, 0, -1, u]. */
		ep3_add(t4, t4, t0);
		/* t3 = [u+4, u^2, -u^2-2u, -u, -1, u]. */
		ep3_add(t3, t3, t0);
		/* t4 = [2u+7, u^2, -u^2-3u, -u, -1, 2u]. */
		ep3_add(t4, t4, t3);
		/* t3 = [u+4, u^3+u^2+1, -u^2-2u, -u+1, -u^2, u^2+u]. */
		ep3_add(t3, t3, t5);
		/* t4 = [4u+14, 2u^2, -2u^2-6u, -2u, -2, 4u]. */
		ep3_dbl(t4, t4);
		/* r = [5u+18, u^3+3u^2+1, -3u^2-8u, -3u+1, -u^2-2, u^2+5u]. */
		ep3_add(r, t4, t3);
		ep3_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t0);
		ep3_free(t1);
		ep3_free(t2);
		ep3_free(t3);
		ep3_free(t4);
		ep3_free(t5);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a Scott-Guillevic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep3_mul_cof_sg18(ep3_t r, const ep3_t p) {
	ep3_t t0, t1, t2, t3, t4;
	bn_t x;

	ep3_null(t0);
	ep3_null(t1);
	ep3_null(t2);
	ep3_null(t3);
	ep3_null(t4);
	bn_null(x);

	RLC_TRY {
		ep3_new(t0);
		ep3_new(t1);
		ep3_new(t2);
		ep3_new(t3);
		ep3_new(t4);
		bn_new(x);

		/* Vector computed by Guillevic's MAGMA script:
		[9*u^4-3*u^2+u, 3*u^2-1, -6*u^3 + 2*u, -2*u, 0, 3*u^3-u+1] */
		fp_prime_get_par(x);

		/* t0 = [u]P, t1 = [3u^2]P, t2 = [3u^3]P, t3 = [9u^4]P. */
		ep3_mul_basic(t0, p, x);
		bn_mul_dig(x, x, 3);
		ep3_mul_basic(t1, t0, x);
		bn_div_dig(x, x, 3);
		ep3_mul_basic(t2, t1, x);
		bn_mul_dig(x, x, 3);
		ep3_mul_basic(t3, t2, x);
		ep3_sub(t3, t3, t1);
		ep3_add(t3, t3, t0);

		ep3_sub(t4, t1, p),
		ep3_frb(t4, t4, 1);
		ep3_add(t3, t3, t4);

		ep3_sub(t2, t2, t0);
		ep3_frb(t4, t2, 2);
		ep3_dbl(t4, t4);
		ep3_sub(t3, t3, t4);
		ep3_add(t2, t2, p);
		ep3_frb(t2, t2, 5);
		ep3_add(t3, t3, t2);

		ep3_dbl(t4, t0);
		ep3_frb(t4, t4, 3);
		ep3_sub(r, t3, t4);
		ep3_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t0);
		ep3_free(t1);
		ep3_free(t2);
		ep3_free(t3);
		ep3_free(t4);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a Fotiadis-Mardindale curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep3_mul_cof_fm18(ep3_t r, const ep3_t p) {
	ep3_t t0, t1, t2, t3, t4;
	bn_t x;

	ep3_null(t0);
	ep3_null(t1);
	ep3_null(t2);
	ep3_null(t3);
	ep3_null(t4);
	bn_null(x);

	RLC_TRY {
		ep3_new(t0);
		ep3_new(t1);
		ep3_new(t2);
		ep3_new(t3);
		ep3_new(t4);
		bn_new(x);

		/* Vector computed by Guillevic's MAGMA script:
		[2*x*(x+2)/3, x^3-(x+2)/3, -2*x^2*(x+2)/3, -x*(x^3+(x+2)/3), 2*(x+2)/3, x^2*(x^3+(x+2)/3)-1] */
		fp_prime_get_par(x);

		/* t0 = [(x+2)/3]P, t1 = [x]P. */
		bn_add_dig(x, x, 2);
		bn_div_dig(x, x, 3);
		ep3_mul_basic(t0, p, x);
		ep3_dbl(t1, t0);
		ep3_add(t1, t1, t0);
		ep3_dbl(t2, p);
		ep3_sub(t1, t1, t2);

		/* Compute t2 = [x*(x+2)/3]P, t1 = [3*x*(x+2)/3-2x]P = [x^2]P. */
		fp_prime_get_par(x);
		ep3_frb(t3, t0, 4);
		ep3_mul_basic(t2, t0, x);
		ep3_add(t3, t3, t2);
		ep3_dbl(t4, t2);
		ep3_add(t4, t4, t2);
		ep3_dbl(t1, t1);
		ep3_sub(t1, t4, t1);
		ep3_norm(t1, t1);
		/* Compute t2 = [x^2*(x+2)/3]P, */
		ep3_mul_basic(t2, t2, x);
		ep3_frb(t4, t2, 2);
		ep3_sub(t3, t3, t4);
		ep3_dbl(t3, t3);
		ep3_mul_basic(t2, t1, x);
		ep3_sub(t4, t2, t0);
		ep3_frb(t4, t4, 1);
		ep3_add(t3, t3, t4);
		ep3_add(t4, t2, t0);
		ep3_norm(t4, t4);
		ep3_mul_basic(t2, t4, x);
		ep3_frb(t4, t2, 3);
		ep3_sub(t3, t3, t4);
		ep3_mul_basic(t2, t2, x);
		ep3_sub(t2, t2, p);
		ep3_frb(t2, t2, 5);
		ep3_add(t3, t3, t2);
		ep3_norm(r, t3);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t0);
		ep3_free(t1);
		ep3_free(t2);
		ep3_free(t3);
		ep3_free(t4);
		bn_free(x);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep3_mul_cof(ep3_t r, const ep3_t p) {
	bn_t k;

	bn_null(k);

	RLC_TRY {
		switch (ep_curve_is_pairf()) {
			case EP_K18:
				ep3_mul_cof_k18(r, p);
				break;
			case EP_SG18:
				ep3_mul_cof_sg18(r, p);
				break;
			case EP_FM18:
				ep3_mul_cof_fm18(r, p);
				break;
			default:
				/* Now, multiply by cofactor to get the correct group. */
				ep3_curve_get_cof(k);
				ep3_mul_basic(r, p, k);
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(k);
	}
}
