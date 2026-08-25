/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of the binary quadratic form reduction.
 *
 * @ingroup qf
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Normalizes a form, taking its scratch from the caller.
 *
 * Reduction calls this once per rho step, so allocating the three temporaries
 * inside would pay for a full set on every iteration. That is nearly free when
 * a bn_t holds its digits inline, but a calloc and a free apiece otherwise, and
 * a reduction runs a few dozen steps, so the caller hands them down instead.
 *
 * The destination may be the source, in which case the first coefficient is
 * already in place and is not touched.
 *
 * @param[out] f			- the normalized form.
 * @param[in] g				- the form to normalize.
 * @param[in] t				- scratch.
 * @param[in] q				- scratch for the quotient.
 * @param[in] r				- scratch for the remainder.
 */
static void qf_norm_imp(qf_t f, const qf_t g, bn_t t, bn_t q, bn_t r) {
	/* b = q*a + r with -a < r <= 0, which is what rounding up gives */
	bn_div_rem_rup(q, r, g->b, g->a);
	if (!bn_is_even(q)) {
		bn_add(r, r, g->a);				/* now -a < r <= a */
	}
	bn_hlv(q, q);						/* b = (2a)*q + r */
	bn_add(t, r, g->b);					/* w = b_new + b_old, even */
	bn_hlv(t, t);
	bn_mul(t, q, t);
	bn_sub(f->c, g->c, t);
#if ALLOC == DYNAMIC
	bn_swap(f->b, r);
#else
	bn_copy(f->b, r);
#endif
	if (f != g) {
		bn_copy(f->a, g->a);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void qf_norm(qf_t f, const qf_t g) {
	bn_t t, q, r;

	bn_null(t);
	bn_null(q);
	bn_null(r);

	RLC_TRY {
		bn_new(t);
		bn_new(q);
		bn_new(r);

		qf_norm_imp(f, g, t, q, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
		bn_free(q);
		bn_free(r);
	}
}

void qf_rdc(qf_t f, const qf_t g) {
	int cmp;
	bn_t t, q, r;

	bn_null(t);
	bn_null(q);
	bn_null(r);

	RLC_TRY {
		bn_new(t);
		bn_new(q);
		bn_new(r);

		/* the scratch is allocated once and reused by every step below */
		qf_norm_imp(f, g, t, q, r);

		/* While a > c, normalize. */
		while ((cmp = bn_cmp_abs(f->a, f->c)) == RLC_GT) {
			bn_swap(f->a, f->c);
			bn_neg(f->b, f->b);
			qf_norm_imp(f, f, t, q, r);
		}

		if (cmp == RLC_EQ && bn_sign(f->b) == RLC_NEG) {
			bn_neg(f->b, f->b);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
		bn_free(q);
		bn_free(r);
	}
}