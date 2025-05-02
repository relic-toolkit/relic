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
 * Implementation of Miller doubling for curves of embedding degree 1.
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

/* Formulas from "Generation and Tate Pairing Computation
 * of Ordinary Elliptic Curves with Embedding Degree One", by Hu et al. */

void pp_dbl_k1_basic(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q) {
	fp_t s;

	fp_null(s);

	RLC_TRY {
		fp_new(s);

		ep_dbl_slp_basic(r, s, p);
		fp_sub(m, q->x, r->x);
		fp_mul(l, m, s);
		fp_sub(l, r->y, l);
		fp_add(l, l, q->y);
		if (fp_is_zero(l)) {
			fp_set_dig(l, 1);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(s);
	}
}

#endif

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

void pp_dbl_k1_projc(fp_t l, fp_t m, ep_t r, fp_t w, const ep_t p, const fp_t v,
		const ep_t q) {
	fp_t t0, t1, t2, t3, t4;

	fp_null(t0);
	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);

		/* dbl-2007-bl formulas 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8 */
		/* with the extended coordinate optimization w = z^2 applied.  */

		/* t0 = y1^2. */
		fp_sqr(t0, p->y);

		/* t1 = x1^2. */
		fp_sqr(t1, p->x);

		/* t2 = y1^4.*/
		fp_sqr(t2, t0);

		/* t3 = S = 2*((X1+YY)^2-XX-YYYY). */
		fp_add(t3, p->x, t0);
		fp_sqr(t3, t3);
		fp_sub(t3, t3, t1);
		fp_sub(t3, t3, t2);
		fp_dbl(t3, t3);

		/* z3 = (Y1+Z1)^2-YY-ZZ, */
		fp_add(r->z, p->y, p->z);
		fp_sqr(r->z, r->z);
		fp_sub(r->z, r->z, t0);
		fp_sub(r->z, r->z, v);

		/* t4 = M = 3*XX+a*ZZ^2. */
		fp_dbl(t4, t1);
		fp_add(t4, t4, t1);
		fp_sqr(t1, v);
		/* We could use ep_curve_mul_a(t0, t1), but optimize for a = -4. */
		fp_dbl(t0, t1);
		fp_dbl(t0, t0);
		fp_neg(t0, t0);
		fp_add(t4, t4, t0);

		/* x3 = T = M^2 - 2S. */
		fp_sqr(r->x, t4);
		fp_sub(r->x, r->x, t3);
		fp_sub(r->x, r->x, t3);

		/* y3 = M*(S-T)-8*YYYY. */
		fp_sub(t0, t3, r->x);
		fp_mul(t0, t4, t0);
		fp_dbl(t2, t2);
		fp_dbl(t2, t2);
		fp_dbl(t2, t2);
		fp_sub(r->y, t0, t2);

		/* l = z3*z3^2*yQ + y3 − t4*(z3^2*xQ - x3), v = z3*(z3^2*xQ - x3)). */
		fp_sqr(w, r->z);
		fp_mul(l, r->z, w);
		fp_mul(l, l, q->y);
		fp_add(l, l, r->y);
		fp_mul(t1, w, q->x);
		fp_sub(t1, t1, r->x);
		fp_mul(m, r->z, t1);
		fp_mul(t1, t1, t4);
		fp_sub(l, l, t1);
		if (fp_is_zero(l)) {
			fp_set_dig(l, 1);
		}

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
	}
}

#endif
