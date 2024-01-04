/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of doubling on elliptic prime curves over quartic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the resulting slope.
 * @param[in] p				- the point to double.
 */
static void ep8_dbl_basic_imp(ep8_t r, fp8_t s, const ep8_t p) {
	fp8_t t0, t1, t2;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);

		/* t0 = 1/(2 * y1). */
		fp8_dbl(t0, p->y);
		fp8_inv(t0, t0);

		/* t1 = 3 * x1^2 + a. */
		fp8_sqr(t1, p->x);
		fp8_copy(t2, t1);
		fp8_dbl(t1, t1);
		fp8_add(t1, t1, t2);

		ep8_curve_get_a(t2);
		fp8_add(t1, t1, t2);

		/* t1 = (3 * x1^2 + a)/(2 * y1). */
		fp8_mul(t1, t1, t0);

		if (s != NULL) {
			fp8_copy(s, t1);
		}

		/* t2 = t1^2. */
		fp8_sqr(t2, t1);

		/* x3 = t1^2 - 2 * x1. */
		fp8_dbl(t0, p->x);
		fp8_sub(t0, t2, t0);

		/* y3 = t1 * (x1 - x3) - y1. */
		fp8_sub(t2, p->x, t0);
		fp8_mul(t1, t1, t2);

		fp8_sub(r->y, t1, p->y);

		fp8_copy(r->x, t0);
		fp8_copy(r->z, p->z);

		r->coord = BASIC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
	}
}

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r				- the result.
 * @param[in] p					- the point to double.
 */
static void ep8_dbl_projc_imp(ep8_t r, const ep8_t p) {
	fp8_t t0, t1, t2, t3, t4, t5;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);
	fp8_null(t3);
	fp8_null(t4);
	fp8_null(t5);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);
		fp8_new(t3);
		fp8_new(t4);
		fp8_new(t5);

		if (ep_curve_opt_a() == RLC_ZERO) {
			fp8_sqr(t0, p->x);
			fp8_add(t2, t0, t0);
			fp8_add(t0, t2, t0);

			fp8_sqr(t3, p->y);
			fp8_mul(t1, t3, p->x);
			fp8_add(t1, t1, t1);
			fp8_add(t1, t1, t1);
			fp8_sqr(r->x, t0);
			fp8_add(t2, t1, t1);
			fp8_sub(r->x, r->x, t2);
			fp8_mul(r->z, p->z, p->y);
			fp8_add(r->z, r->z, r->z);
			fp8_add(t3, t3, t3);

			fp8_sqr(t3, t3);
			fp8_add(t3, t3, t3);
			fp8_sub(t1, t1, r->x);
			fp8_mul(r->y, t0, t1);
			fp8_sub(r->y, r->y, t3);
		} else {
			/* dbl-2007-bl formulas: 1M + 8S + 1*a + 10add + 1*8 + 2*2 + 1*3 */
			/* http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl */

			/* t0 = x1^2, t1 = y1^2, t2 = y1^4. */
			fp8_sqr(t0, p->x);
			fp8_sqr(t1, p->y);
			fp8_sqr(t2, t1);

			if (p->coord != BASIC) {
				/* t3 = z1^2. */
				fp8_sqr(t3, p->z);

				if (ep_curve_get_a() == RLC_ZERO) {
					/* z3 = 2 * y1 * z1. */
					fp8_mul(r->z, p->y, p->z);
					fp8_dbl(r->z, r->z);
				} else {
					/* z3 = (y1 + z1)^2 - y1^2 - z1^2. */
					fp8_add(r->z, p->y, p->z);
					fp8_sqr(r->z, r->z);
					fp8_sub(r->z, r->z, t1);
					fp8_sub(r->z, r->z, t3);
				}
			} else {
				/* z3 = 2 * y1. */
				fp8_dbl(r->z, p->y);
			}

			/* t4 = S = 2*((x1 + y1^2)^2 - x1^2 - y1^4). */
			fp8_add(t4, p->x, t1);
			fp8_sqr(t4, t4);
			fp8_sub(t4, t4, t0);
			fp8_sub(t4, t4, t2);
			fp8_dbl(t4, t4);

			/* t5 = M = 3 * x1^2 + a * z1^4. */
			fp8_dbl(t5, t0);
			fp8_add(t5, t5, t0);
			if (p->coord != BASIC) {
				fp8_sqr(t3, t3);
				ep8_curve_get_a(t1);
				fp8_mul(t1, t3, t1);
				fp8_add(t5, t5, t1);
			} else {
				ep8_curve_get_a(t1);
				fp8_add(t5, t5, t1);
			}

			/* x3 = T = M^2 - 2 * S. */
			fp8_sqr(r->x, t5);
			fp8_dbl(t1, t4);
			fp8_sub(r->x, r->x, t1);

			/* y3 = M * (S - T) - 8 * y1^4. */
			fp8_dbl(t2, t2);
			fp8_dbl(t2, t2);
			fp8_dbl(t2, t2);
			fp8_sub(t4, t4, r->x);
			fp8_mul(t5, t5, t4);
			fp8_sub(r->y, t5, t2);
		}

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
		fp8_free(t3);
		fp8_free(t4);
		fp8_free(t5);
	}
}

#endif /* EP_ADD == PROJC */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep8_dbl_basic(ep8_t r, const ep8_t p) {
	if (ep8_is_infty(p)) {
		ep8_set_infty(r);
		return;
	}

	ep8_dbl_basic_imp(r, NULL, p);
}

void ep8_dbl_slp_basic(ep8_t r, fp8_t s, const ep8_t p) {
	if (ep8_is_infty(p)) {
		ep8_set_infty(r);
		return;
	}

	ep8_dbl_basic_imp(r, s, p);
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

void ep8_dbl_projc(ep8_t r, const ep8_t p) {
	if (ep8_is_infty(p)) {
		ep8_set_infty(r);
		return;
	}

	ep8_dbl_projc_imp(r, p);
}

#endif
