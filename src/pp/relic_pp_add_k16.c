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
 * Implementation of Miller addition for curves of embedding degree 16.
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

void pp_add_k16_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	int one = 1, zero = 0;
	fp4_t s;
	ep4_t t;

	fp4_null(s);
	ep4_null(t);

	RLC_TRY {
		fp4_new(s);
		ep4_new(t);

		ep4_copy(t, r);
		ep4_add_slp_basic(r, s, r, q);

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

void pp_add_k16_projc_basic(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3, t4, t5;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);
		fp4_new(t5);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* t0 = A = Z1^2, t1 = B = X2*Z1. */
		fp4_sqr(t0, r->z);
		fp4_mul(t1, r->z, q->x);

		/* t0 = C = y2*A, t2 = D = (x1 - B) */
		fp4_mul(t0, t0, q->y);
		fp4_sub(t2, r->x, t1);

		/* t3 = E = 2*(y1 - C), t4 = F = 2*D*z1, t2 = G = 4*D*F. */
		fp4_sub(t3, r->y, t0);
		fp4_dbl(t3, t3);
		fp4_dbl(t2, t2);
		fp4_mul(t4, t2, r->z);
		fp4_mul(t2, t2, t4);
		fp4_dbl(t2, t2);

		/* l = E*X2 - F*Y2 - E*xQ + F*yQ. */
		fp4_mul(l[one][one], t3, q->x);
		fp4_mul(t0, t4, q->y);
		fp4_sub(l[one][one], l[one][one], t0);
		fp_mul(l[one][zero][0][0], t3[0][0], p->x);
		fp_mul(l[one][zero][0][1], t3[0][1], p->x);
		fp_mul(l[one][zero][1][0], t3[1][0], p->x);
		fp_mul(l[one][zero][1][1], t3[1][1], p->x);
		fp_mul(l[zero][zero][0][0], t4[0][0], p->y);
		fp_mul(l[zero][zero][0][1], t4[0][1], p->y);
		fp_mul(l[zero][zero][1][0], t4[1][0], p->y);
		fp_mul(l[zero][zero][1][1], t4[1][1], p->y);

		/* z3 = F^2, t4 = (F + E)^2, t3 = E^2. */
		fp4_sqr(r->z, t4);
		fp4_add(t4, t4, t3);
		fp4_sqr(t4, t4);
		fp4_sqr(t3, t3);

		/* t5 = x3 = 2*E^2 - (x1 + B)*G. */
		fp4_add(t1, t1, r->x);
		fp4_mul(t1, t1, t2);
		fp4_dbl(t5, t3);
		fp4_sub(t5, t5, t1);

		/* y3 = ((F + E)^2 - E^2 - F^2)*(x1*G - x3) - y1*G^2. */
		fp4_sub(t4, t4, r->z);
		fp4_sub(t4, t4, t3);
		fp4_mul(t1, r->x, t2);
		fp4_sub(t1, t1, t5);
		fp4_mul(t4, t4, t1);
		fp4_sqr(t2, t2);
		fp4_mul(r->y, r->y, t2);
		fp4_sub(r->y, t4, r->y);

		/* Z3 = 2*F^2. */
		fp4_dbl(r->z, r->z);
		fp4_copy(r->x, t5);

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
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void pp_add_k16_projc_lazyr(fp16_t l, ep4_t r, const ep4_t q, const ep_t p) {
	fp4_t t0, t1, t2, t3, t4, t5;
	int one = 1, zero = 0;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);
	fp4_null(t3);
	fp4_null(t4);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);
		fp4_new(t3);
		fp4_new(t4);
		fp4_new(t5);

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* t0 = A = Z1^2, t1 = B = X2*Z1. */
		fp4_sqr(t0, r->z);
		fp4_mul(t1, r->z, q->x);

		/* t0 = C = y2*A, t2 = D = (x1 - B) */
		fp4_mul(t0, t0, q->y);
		fp4_sub(t2, r->x, t1);

		/* t3 = E = 2*(y1 - C), t4 = F = 2*D*z1, t2 = G = 4*D*F. */
		fp4_sub(t3, r->y, t0);
		fp4_dbl(t3, t3);
		fp4_dbl(t2, t2);
		fp4_mul(t4, t2, r->z);
		fp4_mul(t2, t2, t4);
		fp4_dbl(t2, t2);

		/* l = E*X2 - F*Y2 - E*xQ + F*yQ. */
		fp4_mul(l[one][one], t3, q->x);
		fp4_mul(t0, t4, q->y);
		fp4_sub(l[one][one], l[one][one], t0);
		fp_mul(l[one][zero][0][0], t3[0][0], p->x);
		fp_mul(l[one][zero][0][1], t3[0][1], p->x);
		fp_mul(l[one][zero][1][0], t3[1][0], p->x);
		fp_mul(l[one][zero][1][1], t3[1][1], p->x);
		fp_mul(l[zero][zero][0][0], t4[0][0], p->y);
		fp_mul(l[zero][zero][0][1], t4[0][1], p->y);
		fp_mul(l[zero][zero][1][0], t4[1][0], p->y);
		fp_mul(l[zero][zero][1][1], t4[1][1], p->y);

		/* z3 = F^2, t4 = (F + E)^2, t3 = E^2. */
		fp4_sqr(r->z, t4);
		fp4_add(t4, t4, t3);
		fp4_sqr(t4, t4);
		fp4_sqr(t3, t3);

		/* t5 = x3 = 2*E^2 - (x1 + B)*G. */
		fp4_add(t1, t1, r->x);
		fp4_mul(t1, t1, t2);
		fp4_dbl(t5, t3);
		fp4_sub(t5, t5, t1);

		/* y3 = ((F + E)^2 - E^2 - F^2)*(x1*G - x3) - y1*G^2. */
		fp4_sub(t4, t4, r->z);
		fp4_sub(t4, t4, t3);
		fp4_mul(t1, r->x, t2);
		fp4_sub(t1, t1, t5);
		fp4_mul(t4, t4, t1);
		fp4_sqr(t2, t2);
		fp4_mul(r->y, r->y, t2);
		fp4_sub(r->y, t4, r->y);

		/* Z3 = 2*F^2. */
		fp4_dbl(r->z, r->z);
		fp4_copy(r->x, t5);

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
	}
}

#endif

#endif

void pp_add_lit_k16(fp16_t l, ep_t r, const ep_t p, const ep4_t q) {
	fp_t t0, t1, t2, t3;
	int one = 1, zero = 0;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);

		fp_mul(t0, r->z, p->x);
		fp_sub(t0, r->x, t0);
		fp_mul(t1, r->z, p->y);
		fp_sub(t1, r->y, t1);
		fp_mul(t2, p->x, t1);
		r->coord = PROJC;

		if (ep4_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		fp_mul(l[zero][zero][0][0], t0, p->y);
		fp_sub(l[zero][zero][0][0], t2, l[zero][zero][0][0]);

		fp_mul(l[zero][one][0][0], q->x[0][0], t1);
		fp_mul(l[zero][one][0][1], q->x[0][1], t1);
		fp_mul(l[zero][one][1][0], q->x[1][0], t1);
		fp_mul(l[zero][one][1][1], q->x[1][1], t1);
		fp4_neg(l[zero][one], l[zero][one]);

		fp_mul(l[one][one][0][0], q->y[0][0], t0);
		fp_mul(l[one][one][0][1], q->y[0][1], t0);
		fp_mul(l[one][one][1][0], q->y[1][0], t0);
		fp_mul(l[one][one][1][1], q->y[1][1], t0);

		fp_sqr(t2, t0);
		fp_mul(r->x, t2, r->x);
		fp_mul(t2, t0, t2);
		fp_sqr(t3, t1);
		fp_mul(t3, t3, r->z);
		fp_add(t3, t2, t3);
		fp_sub(t3, t3, r->x);
		fp_sub(t3, t3, r->x);
		fp_sub(r->x, r->x, t3);
		fp_mul(t1, t1, r->x);
		fp_mul(r->y, t2, r->y);
		fp_sub(r->y, t1, r->y);
		fp_mul(r->x, t0, t3);
		fp_mul(r->z, r->z, t2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
	}
}
