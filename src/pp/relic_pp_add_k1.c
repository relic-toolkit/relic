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

		/* t0 = z1^2. */
		fp_sqr(t0, r->z);

		/* t3 = x2 * z1^2. */
		fp_mul(t3, p->x, t0);

		/* t1 = y2 * z1^3. */
		fp_mul(t1, t0, r->z);
		fp_mul(t1, t1, p->y);

		/* t2 = x1 - t3. */
		fp_sub(t2, r->x, t3);

		/* t4 = y1 - t1. */
		fp_sub(t4, r->y, t1);

		/* l0 = slope * (x2 + xq) - z3 * y2. */
		fp_sub(l, p->x, q->x);
		fp_mul(l, l, t4);

		fp_dbl(t0, t3);
		fp_add(t3, t0, t2);
		fp_dbl(t0, t1);
		fp_add(t1, t0, t4);

		fp_mul(r->z, t2, r->z);
		fp_sqr(t0, t2);
		fp_mul(t2, t0, t2);
		fp_mul(t0, t0, t3);
		fp_sqr(t3, t4);

		fp_sub(r->x, t3, t0);
		fp_sub(t0, t0, r->x);
		fp_sub(t0, t0, r->x);
		fp_mul(t5, t0, t4);
		fp_mul(t2, t2, t1);
		fp_sub(t1, t5, t2);

		fp_mul(t5, r->z, p->y);
		fp_sub(l, l, t5);

		fp_mul(t0, r->z, q->y);
		fp_mul(t0, t0, ep_curve_get_beta());
		fp_add(l, l, t0);

		fp_hlv(r->y, t1);

		r->coord = JACOB;
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
