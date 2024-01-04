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
 * Implementation of addition on prime elliptic curves over quadratic
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
 * Adds two points represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param s					- the resulting slope.
 * @param p					- the first point to add.
 * @param q					- the second point to add.
 */
static void ep3_add_basic_imp(ep3_t r, fp3_t s, const ep3_t p, const ep3_t q) {
	fp3_t t0, t1, t2;

	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);

		/* t0 = x2 - x1. */
		fp3_sub(t0, q->x, p->x);
		/* t1 = y2 - y1. */
		fp3_sub(t1, q->y, p->y);

		/* If t0 is zero. */
		if (fp3_is_zero(t0)) {
			if (fp3_is_zero(t1)) {
				/* If t1 is zero, q = p, should have doubled. */
				ep3_dbl_slp_basic(r, s, p);
			} else {
				/* If t1 is not zero and t0 is zero, q = -p and r = infty. */
				ep3_set_infty(r);
			}
		} else {
			/* t2 = 1/(x2 - x1). */
			fp3_inv(t2, t0);
			/* t2 = lambda = (y2 - y1)/(x2 - x1). */
			fp3_mul(t2, t1, t2);

			/* x3 = lambda^2 - x2 - x1. */
			fp3_sqr(t1, t2);
			fp3_sub(t0, t1, p->x);
			fp3_sub(t0, t0, q->x);

			/* y3 = lambda * (x1 - x3) - y1. */
			fp3_sub(t1, p->x, t0);
			fp3_mul(t1, t2, t1);
			fp3_sub(r->y, t1, p->y);

			fp3_copy(r->x, t0);
			fp3_copy(r->z, p->z);

			if (s != NULL) {
				fp3_copy(s, t2);
			}

			r->coord = BASIC;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
	}
}

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

#if defined(EP_MIXED) || !defined(STRIP)

/**
 * Adds a point represented in affine coordinates to a point represented in
 * projective coordinates.
 *
 * @param r					- the result.
 * @param s					- the slope.
 * @param p					- the affine point.
 * @param q					- the projective point.
 */
static void ep3_add_projc_mix(ep3_t r, const ep3_t p, const ep3_t q) {
	fp3_t t0, t1, t2, t3, t4, t5, t6;

	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);
	fp3_null(t3);
	fp3_null(t4);
	fp3_null(t5);
	fp3_null(t6);

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);
		fp3_new(t3);
		fp3_new(t4);
		fp3_new(t5);
		fp3_new(t6);

		if (p->coord != BASIC) {
			/* t0 = z1^2. */
			fp3_sqr(t0, p->z);

			/* t3 = U2 = x2 * z1^2. */
			fp3_mul(t3, q->x, t0);

			/* t1 = S2 = y2 * z1^3. */
			fp3_mul(t1, t0, p->z);
			fp3_mul(t1, t1, q->y);

			/* t3 = H = U2 - x1. */
			fp3_sub(t3, t3, p->x);

			/* t1 = R = 2 * (S2 - y1). */
			fp3_sub(t1, t1, p->y);
		} else {
			/* H = x2 - x1. */
			fp3_sub(t3, q->x, p->x);

			/* t1 = R = 2 * (y2 - y1). */
			fp3_sub(t1, q->y, p->y);
		}

		/* t2 = HH = H^2. */
		fp3_sqr(t2, t3);

		/* If E is zero. */
		if (fp3_is_zero(t3)) {
			if (fp3_is_zero(t1)) {
				/* If I is zero, p = q, should have doubled. */
				ep3_dbl_projc(r, p);
			} else {
				/* If I is not zero, q = -p, r = infinity. */
				ep3_set_infty(r);
			}
		} else {
			/* t5 = J = H * HH. */
			fp3_mul(t5, t3, t2);

			/* t4 = V = x1 * HH. */
			fp3_mul(t4, p->x, t2);

			/* x3 = R^2 - J - 2 * V. */
			fp3_sqr(r->x, t1);
			fp3_sub(r->x, r->x, t5);
			fp3_dbl(t6, t4);
			fp3_sub(r->x, r->x, t6);

			/* y3 = R * (V - x3) - Y1 * J. */
			fp3_sub(t4, t4, r->x);
			fp3_mul(t4, t4, t1);
			fp3_mul(t1, p->y, t5);
			fp3_sub(r->y, t4, t1);

			if (p->coord != BASIC) {
				/* z3 = z1 * H. */
				fp3_mul(r->z, p->z, t3);
			} else {
				/* z3 = H. */
				fp3_copy(r->z, t3);
			}
		}
		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
		fp3_free(t3);
		fp3_free(t4);
		fp3_free(t5);
		fp3_free(t6);
	}
}

#endif

/**
 * Adds two points represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the first point to add.
 * @param q					- the second point to add.
 */
static void ep3_add_projc_imp(ep3_t r, const ep3_t p, const ep3_t q) {
#if defined(EP_MIXED) && defined(STRIP)
	ep3_add_projc_mix(r, p, q);
#else /* General addition. */
	fp3_t t0, t1, t2, t3, t4, t5, t6;

	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);
	fp3_null(t3);
	fp3_null(t4);
	fp3_null(t5);
	fp3_null(t6);

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);
		fp3_new(t3);
		fp3_new(t4);
		fp3_new(t5);
		fp3_new(t6);

		if (q->coord == BASIC) {
			ep3_add_projc_mix(r, p, q);
		} else {
			/* t0 = z1^2. */
			fp3_sqr(t0, p->z);

			/* t1 = z2^2. */
			fp3_sqr(t1, q->z);

			/* t2 = U1 = x1 * z2^2. */
			fp3_mul(t2, p->x, t1);

			/* t3 = U2 = x2 * z1^2. */
			fp3_mul(t3, q->x, t0);

			/* t6 = z1^2 + z2^2. */
			fp3_add(t6, t0, t1);

			/* t0 = S2 = y2 * z1^3. */
			fp3_mul(t0, t0, p->z);
			fp3_mul(t0, t0, q->y);

			/* t1 = S1 = y1 * z2^3. */
			fp3_mul(t1, t1, q->z);
			fp3_mul(t1, t1, p->y);

			/* t3 = H = U2 - U1. */
			fp3_sub(t3, t3, t2);

			/* t0 = R = 2 * (S2 - S1). */
			fp3_sub(t0, t0, t1);

			fp3_dbl(t0, t0);

			/* If E is zero. */
			if (fp3_is_zero(t3)) {
				if (fp3_is_zero(t0)) {
					/* If I is zero, p = q, should have doubled. */
					ep3_dbl_projc(r, p);
				} else {
					/* If I is not zero, q = -p, r = infinity. */
					ep3_set_infty(r);
				}
			} else {
				/* t4 = I = (2*H)^2. */
				fp3_dbl(t4, t3);
				fp3_sqr(t4, t4);

				/* t5 = J = H * I. */
				fp3_mul(t5, t3, t4);

				/* t4 = V = U1 * I. */
				fp3_mul(t4, t2, t4);

				/* x3 = R^2 - J - 2 * V. */
				fp3_sqr(r->x, t0);
				fp3_sub(r->x, r->x, t5);
				fp3_dbl(t2, t4);
				fp3_sub(r->x, r->x, t2);

				/* y3 = R * (V - x3) - 2 * S1 * J. */
				fp3_sub(t4, t4, r->x);
				fp3_mul(t4, t4, t0);
				fp3_mul(t1, t1, t5);
				fp3_dbl(t1, t1);
				fp3_sub(r->y, t4, t1);

				/* z3 = ((z1 + z2)^2 - z1^2 - z2^2) * H. */
				fp3_add(r->z, p->z, q->z);
				fp3_sqr(r->z, r->z);
				fp3_sub(r->z, r->z, t6);
				fp3_mul(r->z, r->z, t3);
			}
		}
		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
		fp3_free(t3);
		fp3_free(t4);
		fp3_free(t5);
		fp3_free(t6);
	}
#endif
}

#endif /* EP_ADD == PROJC */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep3_add_basic(ep3_t r, const ep3_t p, const ep3_t q) {
	if (ep3_is_infty(p)) {
		ep3_copy(r, q);
		return;
	}

	if (ep3_is_infty(q)) {
		ep3_copy(r, p);
		return;
	}

	ep3_add_basic_imp(r, NULL, p, q);
}

void ep3_add_slp_basic(ep3_t r, fp3_t s, const ep3_t p, const ep3_t q) {
	if (ep3_is_infty(p)) {
		ep3_copy(r, q);
		return;
	}

	if (ep3_is_infty(q)) {
		ep3_copy(r, p);
		return;
	}

	ep3_add_basic_imp(r, s, p, q);
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

void ep3_add_projc(ep3_t r, const ep3_t p, const ep3_t q) {
	if (ep3_is_infty(p)) {
		ep3_copy(r, q);
		return;
	}

	if (ep3_is_infty(q)) {
		ep3_copy(r, p);
		return;
	}

	if (p == q) {
		/* TODO: This is a quick hack. Should we fix this? */
		ep3_dbl(r, p);
		return;
	}

	ep3_add_projc_imp(r, p, q);
}

#endif

void ep3_sub(ep3_t r, const ep3_t p, const ep3_t q) {
	ep3_t t;

	ep3_null(t);

	if (p == q) {
		ep3_set_infty(r);
		return;
	}

	RLC_TRY {
		ep3_new(t);

		ep3_neg(t, q);
		ep3_add(r, p, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep3_free(t);
	}
}
