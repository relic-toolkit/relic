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
 * Implementation of Miller doubling for curves of embedding degree 16.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void pp_dbl_k16_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t s;
	ep4_t t;
	int one = 1, zero = 0;

	fp4_null(s);
	ep4_null(t);

	RLC_TRY {
		fp4_new(s);
		ep4_new(t);
		ep4_copy(t, q);
		ep4_dbl_slp_basic(r, s, q);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		fp_mul(l[one][zero][0][0], s[0][0], p->x);
		fp_mul(l[one][zero][0][1], s[0][1], p->x);
		fp_mul(l[one][zero][1][0], s[1][0], p->x);
		fp_mul(l[one][zero][1][1], s[1][1], p->x);		
		fp4_mul(l[one][one], s, t->x);
		fp4_sub(l[one][one], t->y, l[one][one]);
		fp_copy(l[zero][zero][0][0], p->y);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(s);
		ep4_free(t);
	}
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

#if PP_EXT == BASIC || !defined(STRIP)

void pp_dbl_k16_projc_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3, t4, t5, t6;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);
	fp4_null(t5);
	fp4_null(t6);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);
		fp4_new(t5);
		fp4_new(t6);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* t0 = A = X1^2, t1 = B = Y1^2, t2 = C = Z1^2, t3 = D = a*C. */
		fp4_sqr(t0, q->x);
		fp4_sqr(t1, q->y);
		fp4_sqr(t2, q->z);
		switch (ep_curve_opt_a()) {
			case RLC_ZERO:
				fp4_zero(t3);
				break;
			case RLC_ONE:
				fp4_copy(t3, t2);
				break;
#if FP_RDC != MONTY
			case RLC_TINY:
				fp_mul_dig(t3[0][0], t2[0][0], ep_curve_get_a()[0]);
				fp_mul_dig(t3[0][1], t2[0][1], ep_curve_get_a()[0]);
				fp_mul_dig(t3[1][0], t2[1][0], ep_curve_get_a()[0]);
				fp_mul_dig(t3[1][1], t2[1][1], ep_curve_get_a()[0]);
				break;
#endif
			default:
				fp_mul(t3[0][0], t2[0][0], ep_curve_get_a());
				fp_mul(t3[0][1], t2[0][1], ep_curve_get_a());
				fp_mul(t3[1][0], t2[1][0], ep_curve_get_a());
				fp_mul(t3[1][1], t2[1][1], ep_curve_get_a());
				break;
		}
		fp4_mul_art(t3, t3);

		/* x3 = (A - D)^2, l11 = (A - D + x1)^2 - x3 - A. */
		fp4_sub(t5, t0, t3);
		fp4_add(l[one][one], t5, q->x);
		fp4_sqr(r->x, t5);
		fp4_sqr(l[one][one], l[one][one]);
		fp4_sub(l[one][one], l[one][one], r->x);
		fp4_sub(l[one][one], l[one][one], t0);

		/* l10 := -xp*z1*2*(3A + D). */
		fp4_add(t6, t0, t3);
		fp4_dbl(t0, t0);
		fp4_add(t0, t0, t6);
		fp4_dbl(t0, t0);
		fp4_mul(l[one][zero], t0, q->z);
		fp_mul(l[one][zero][0][0], l[one][zero][0][0], p->x);
		fp_mul(l[one][zero][0][1], l[one][zero][0][1], p->x);
		fp_mul(l[one][zero][1][0], l[one][zero][1][0], p->x);
		fp_mul(l[one][zero][1][1], l[one][zero][1][1], p->x);

		/* l01 = 2*((y1 + z1)^2 - B - C)*yP. */
		fp4_add(l[zero][zero], q->y, q->z);
		fp4_sqr(l[zero][zero], l[zero][zero]);
		fp4_sub(l[zero][zero], l[zero][zero], t1);
		fp4_sub(l[zero][zero], l[zero][zero], t2);
		fp4_dbl(l[zero][zero], l[zero][zero]);
		fp_mul(l[zero][zero][0][0], l[zero][zero][0][0], p->y);
		fp_mul(l[zero][zero][0][1], l[zero][zero][0][1], p->y);
		fp_mul(l[zero][zero][1][0], l[zero][zero][1][0], p->y);
		fp_mul(l[zero][zero][1][1], l[zero][zero][1][1], p->y);

		/* t4 = E = 2*(A + D)^2 - x3. */
		fp4_sqr(t4, t6);
		fp4_dbl(t4, t4);
		fp4_sub(t4, t4, r->x);
		/* y3 = E * ((A - D + y1)^2 - B - x3). */
		fp4_add(r->y, t5, q->y);
		fp4_sqr(r->y, r->y);
		fp4_sub(r->y, r->y, t1);
		fp4_sub(r->y, r->y, r->x);
		fp4_mul(r->y, r->y, t4);
		/* z3 = 4*B. */
		fp4_dbl(r->z, t1);
		fp4_dbl(r->z, r->z);

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
		fp4_free(t3);
		fp4_free(t4);
		fp4_free(t5);
		fp4_free(t6);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void pp_dbl_k16_projc_lazyr(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3, t4, t5, t6;
	dv4_t u0, u1;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);
	fp4_null(t5);
	fp4_null(t6);
	dv4_null(u0);
	dv4_null(u1);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);
		fp4_new(t5);
		fp4_new(t6);
		dv4_new(u0);
		dv4_new(u1);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* t0 = A = X1^2, t1 = B = Y1^2, t2 = C = Z1^2, t3 = D = a*C. */
		fp4_sqr(t0, q->x);
		fp4_sqr(t1, q->y);
		fp4_sqr(t2, q->z);
		switch (ep_curve_opt_a()) {
			case RLC_ZERO:
				fp4_zero(t3);
				break;
			case RLC_ONE:
				fp4_copy(t3, t2);
				break;
#if FP_RDC != MONTY
			case RLC_TINY:
				fp_mul_dig(t3[0][0], t2[0][0], ep_curve_get_a()[0]);
				fp_mul_dig(t3[0][1], t2[0][1], ep_curve_get_a()[0]);
				fp_mul_dig(t3[1][0], t2[1][0], ep_curve_get_a()[0]);
				fp_mul_dig(t3[1][1], t2[1][1], ep_curve_get_a()[0]);
				break;
#endif
			default:
				fp_mul(t3[0][0], t2[0][0], ep_curve_get_a());
				fp_mul(t3[0][1], t2[0][1], ep_curve_get_a());
				fp_mul(t3[1][0], t2[1][0], ep_curve_get_a());
				fp_mul(t3[1][1], t2[1][1], ep_curve_get_a());
				break;
		}
		fp4_mul_art(t3, t3);

		/* x3 = (A - D)^2, l11 = (A - D + x1)^2 - x3 - A. */
		fp4_sub(t5, t0, t3);
		fp4_add(l[one][one], t5, q->x);
		fp4_sqr(r->x, t5);
		fp4_sqr(l[one][one], l[one][one]);
		fp4_sub(l[one][one], l[one][one], r->x);
		fp4_sub(l[one][one], l[one][one], t0);

		/* l10 := -xp*z1*2*(3A + D). */
		fp4_add(t6, t0, t3);
		fp4_dbl(t0, t0);
		fp4_add(t0, t0, t6);
		fp4_dbl(t0, t0);
		fp4_mul(l[one][zero], t0, q->z);
		fp_mul(l[one][zero][0][0], l[one][zero][0][0], p->x);
		fp_mul(l[one][zero][0][1], l[one][zero][0][1], p->x);
		fp_mul(l[one][zero][1][0], l[one][zero][1][0], p->x);
		fp_mul(l[one][zero][1][1], l[one][zero][1][1], p->x);

		/* l01 = 2*((y1 + z1)^2 - B - C)*yP. */
		fp4_add(l[zero][zero], q->y, q->z);
		fp4_sqr(l[zero][zero], l[zero][zero]);
		fp4_sub(l[zero][zero], l[zero][zero], t1);
		fp4_sub(l[zero][zero], l[zero][zero], t2);
		fp4_dbl(l[zero][zero], l[zero][zero]);
		fp_mul(l[zero][zero][0][0], l[zero][zero][0][0], p->y);
		fp_mul(l[zero][zero][0][1], l[zero][zero][0][1], p->y);
		fp_mul(l[zero][zero][1][0], l[zero][zero][1][0], p->y);
		fp_mul(l[zero][zero][1][1], l[zero][zero][1][1], p->y);

		/* t4 = E = 2*(A + D)^2 - x3. */
		fp4_sqr(t4, t6);
		fp4_dbl(t4, t4);
		fp4_sub(t4, t4, r->x);
		/* y3 = E * ((A - D + y1)^2 - B - x3). */
		fp4_add(r->y, t5, q->y);
		fp4_sqr(r->y, r->y);
		fp4_sub(r->y, r->y, t1);
		fp4_sub(r->y, r->y, r->x);
		fp4_mul(r->y, r->y, t4);
		/* z3 = 4*B. */
		fp4_dbl(r->z, t1);
		fp4_dbl(r->z, r->z);
		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
		fp4_free(t3);
		fp4_free(t4);
		fp4_free(t5);
		fp4_free(t6);
		dv4_free(u0);
		dv4_free(u1);
	}
}

#endif

#endif

void pp_dbl_lit_k16(fp16_t l, ep_t r, const ep_t p, const ep4_t q) {
	fp_t t0, t1, t2, t3, t4, t5, t6;
	int one = 1, zero = 0;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	fp_null(t6);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);
		fp_new(t6);

		fp_sqr(t0, p->x);
		fp_sqr(t1, p->y);
		fp_sqr(t2, p->z);

		fp_mul(t4, ep_curve_get_b(), t2);

		fp_dbl(t3, t4);
		fp_add(t3, t3, t4);

		fp_add(t4, p->x, p->y);
		fp_sqr(t4, t4);
		fp_sub(t4, t4, t0);
		fp_sub(t4, t4, t1);
		fp_add(t5, p->y, p->z);
		fp_sqr(t5, t5);
		fp_sub(t5, t5, t1);
		fp_sub(t5, t5, t2);
		fp_dbl(t6, t3);
		fp_add(t6, t6, t3);
		fp_sub(r->x, t1, t6);
		fp_mul(r->x, r->x, t4);
		fp_add(r->y, t1, t6);
		fp_sqr(r->y, r->y);
		fp_sqr(t4, t3);
		fp_dbl(t6, t4);
		fp_add(t6, t6, t4);
		fp_dbl(t6, t6);
		fp_dbl(t6, t6);
		fp_sub(r->y, r->y, t6);
		fp_mul(r->z, t1, t5);
		fp_dbl(r->z, r->z);
		fp_dbl(r->z, r->z);
		r->coord = PROJC;

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		fp4_dbl(l[zero][one], q->x);
		fp4_add(l[zero][one], l[zero][one], q->x);
		fp_mul(l[zero][one][0][0], l[zero][one][0][0], t0);
		fp_mul(l[zero][one][0][1], l[zero][one][0][1], t0);
		fp_mul(l[zero][one][1][0], l[zero][one][1][0], t0);
		fp_mul(l[zero][one][1][1], l[zero][one][1][1], t0);

		fp_sub(l[zero][zero][0][0], t3, t1);

		fp_mul(l[one][one][0][0], q->y[0][0], t5);
		fp_mul(l[one][one][0][1], q->y[0][1], t5);
		fp_mul(l[one][one][1][0], q->y[1][0], t5);
		fp_mul(l[one][one][1][1], q->y[1][1], t5);

	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
		fp_free(t6);
	}
}
