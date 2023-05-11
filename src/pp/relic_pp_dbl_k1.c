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

void pp_dbl_k1_projc(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q) {
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

		/* dbl-2007-bl formulas 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8 */

		/* t0 = z1^2. */
		fp_sqr(t0, p->z);

		/* t1 = y1^2. */
		fp_sqr(t1, p->y);

		/* t2 = x1^2. */
		fp_sqr(t2, p->x);

		/* t3 = y1^4.*/
		fp_sqr(t3, t1);

		/* t4 = S = 2*((X1+YY)^2-XX-YYYY). */
		fp_add(t4, p->x, t1);
		fp_sqr(t4, t4);
		fp_sub(t4, t4, t2);
		fp_sub(t4, t4, t3);
		fp_dbl(t4, t4);

		/* t5 = M = 3*XX+a*ZZ^2. */
		fp_dbl(t5, t2);
		fp_add(t5, t5, t2);
		fp_sqr(t2, t0);
		fp_mul(t2, t2, ep_curve_get_a());
		fp_add(t5, t5, t2);

		/* z3 = (Y1+Z1)^2-YY-ZZ, */
		fp_add(r->z, p->y, p->z);
		fp_sqr(r->z, r->z);
		fp_sub(r->z, r->z, t1);
		fp_sub(r->z, r->z, t0);

		/* l = z3*t0*yQ − (2t1 − t5*(t0*xQ + x1)). */
		/* Consider \psi(xQ, yQ) = (-xQ, A * yQ).  */
		fp_mul(t2, t0, q->x);
		fp_sub(t2, p->x, t2);
		fp_mul(t2, t2, t5);
		fp_dbl(t1, t1);
		fp_sub(t1, t1, t2);
		fp_mul(l, r->z, q->y);
		fp_mul(l, l, t0);
		fp_mul(l, l, core_get()->beta);
		fp_sub(l, l, t1);

		/* x3 = T = M^2 - 2S. */
		fp_sqr(r->x, t5);
		fp_sub(r->x, r->x, t4);
		fp_sub(r->x, r->x, t4);

		/* y3 = M*(S-T)-8*YYYY. */
		fp_sub(t2, t4, r->x);
		fp_mul(t5, t5, t2);
		fp_dbl(t3, t3);
		fp_dbl(t3, t3);
		fp_dbl(t3, t3);
		fp_sub(r->y, t5, t3);

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
