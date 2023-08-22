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
 * Implementation of Miller addition for curves of embedding degree 1.
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

void pp_add_k1_basic(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q) {
	fp_t s;

	fp_null(s);

	RLC_TRY {
		fp_new(s);

		if (fp_cmp(r->x, p->x) == RLC_EQ) {
			fp_set_dig(m, 1);
			fp_sub(l, q->x, p->x);
		} else {
			fp_sub(l, q->x, p->x);
			ep_add_slp_basic(r, s, r, p);
			fp_mul(l, l, s);
			fp_sub(l, q->y, l);
			fp_sub(l, l, p->y);
			if (fp_is_zero(l)) {
				fp_set_dig(l, 1);
			}
			fp_sub(m, q->x, r->x);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(s);
	}
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

void pp_add_k1_projc(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q) {
	fp_t t0, t1, t2, t3, t4, t5;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);

		fp_sqr(l, r->z);
		fp_mul(l, l, p->x);
		if (fp_cmp(l, r->x) == RLC_EQ) {
			fp_set_dig(m, 1);
			fp_sub(l, q->x, p->x);
		} else {
			/* t0 = z1^2. */
			fp_sqr(t0, r->z);

			/* t3 = U = x2 * z1^2. */
			fp_mul(t3, p->x, t0);

			/* t1 = S = y2 * z1^3. */
			fp_mul(t1, t0, r->z);
			fp_mul(t1, t1, p->y);

			/* t2 = H = U - x1. */
			fp_sub(t2, t3, r->x);

			/* t4 = L = S - y1. */
			fp_sub(t4, t1, r->y);

			/* t5 = H_2 = 2H, t3 = I = 4H^2. */
			fp_dbl(t5, t2);
			fp_sqr(t3, t5);

			/* Z3 = (Z1 + H)^2 - Z1^2 - H^2 = 2 * z1 * H. */
			fp_mul(r->z, r->z, t5);

			/* t4 = M = 2L, t5 = M3 = (L + Z3)^2 - L^2 - Z3^2 = 2 * L * Z3. */
			fp_dbl(t4, t4);
			fp_mul(t5, t4, r->z);

			/* l = Z3^2 * (yQ - y2) - M3*(xQ - x2). */
			fp_sqr(m, r->z);
			fp_sub(l, q->y, p->y);
			fp_mul(l, l, m);
			fp_sub(t0, q->x, p->x);
			fp_mul(t0, t0, t5);
			fp_sub(l, l, t0);
			if (fp_is_zero(l)) {
				fp_set_dig(l, 1);
			}

			/* t0 = V = x1 * I, t3 = J = HI, x3 = 4L^2 - J - 2V*/
			fp_mul(t0, r->x, t3);
			fp_mul(t3, t3, t2);
			fp_sqr(r->x, t4);
			fp_sub(r->x, r->x, t3);
			fp_sub(r->x, r->x, t0);
			fp_sub(r->x, r->x, t0);

			/* y3 = M * (V - X3) - 2y1 * J. */
			fp_mul(r->y, r->y, t3);
			fp_dbl(r->y, r->y);
			fp_sub(t0, t0, r->x);
			fp_mul(t0, t4, t0);
			fp_sub(r->y, t0, r->y);

			/* v = Z3^2 * xQ - X3. */
			fp_mul(m, m, q->x);
			fp_sub(m, m, r->x);

			r->coord = JACOB;
		}
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
	}
}

#endif
