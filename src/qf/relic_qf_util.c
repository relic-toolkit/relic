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
 * Implementation of the binary quadratic form utilities.
 *
 * @ingroup qf
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void qf_copy(qf_t f, const qf_t g) {
	bn_copy(f->a, g->a);
	bn_copy(f->b, g->b);
	bn_copy(f->c, g->c);
}

void qf_neg(qf_t f, const qf_t g) {
	/* The inverse of the form (a, b, c) is (a, -b, c). */
	if (f != g) {
		qf_copy(f, g);
	}
	if (bn_cmp(f->a, f->c) == RLC_NE && bn_cmp(f->a, f->b) == RLC_NE) {
		bn_neg(f->b, f->b);
	}
}

int qf_cmp(const qf_t f, const qf_t g) {
	if (bn_cmp(f->a, g->a) != RLC_EQ || bn_cmp(f->b, g->b) != RLC_EQ ||
			bn_cmp(f->c, g->c) != RLC_EQ) {
		return RLC_NE;
	}
	return RLC_EQ;
}

int qf_is_one(const qf_t f) {
	return bn_cmp_dig(f->a, 1) == RLC_EQ;
}

void qf_zero(qf_t f) {
	bn_zero(f->a);
	bn_zero(f->b);
	bn_zero(f->c);
}

void qf_set(qf_t f, const bn_t a, const bn_t b, const bn_t c) {
	bn_t d, t;

	bn_null(d);
	bn_null(t);

	RLC_TRY {
		bn_new(d);
		bn_new(t);

		/* Compute d = b^2 - 4ac. */
		bn_sqr(d, b);
		bn_mul(t, a, c);
		bn_lsh(t, t, 2);
		bn_sub(d, d, t);
		if (bn_sign(d) == RLC_NEG) {
			bn_copy(f->a, a);
			bn_copy(f->b, b);
			bn_copy(f->c, c);
		} else {
			RLC_THROW(ERR_NO_VALID);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(d);
		bn_free(t);
	}
}

void qf_set_one(qf_t r, const bn_t d) {
	bn_set_dig(r->a, 1);
	if (bn_is_even(d)) {
		bn_zero(r->b);
		bn_zero(r->c);
	} else {
		bn_set_dig(r->b, 1);
		bn_set_dig(r->c, 1);
	}
	bn_sub(r->c, r->c, d);
	bn_rsh(r->c, r->c, 2);
}

void qf_set_dig(qf_t f, dig_t a, dig_t b, dig_t c) {
	bn_t d, t;

	bn_null(d);
	bn_null(t);

	RLC_TRY {
		bn_new(d);
		bn_new(t);

		/* Compute d = b^2 - 4ac. */
		bn_set_dig(d, b);
		bn_sqr(d, d);

		bn_set_dig(t, a);
		bn_mul_dig(t, t, c);
		bn_lsh(t, t, 2);
		bn_sub(d, d, t);
		if (bn_sign(d) == RLC_NEG) {
			bn_set_dig(f->a, a);
			bn_set_dig(f->b, b);
			bn_set_dig(f->c, c);
		} else {
			RLC_THROW(ERR_NO_VALID);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(d);
		bn_free(t);
	}
}

void qf_set_int(qf_t f, int a, int b, int c) {
	bn_t d, t;

	bn_null(d);
	bn_null(t);

	RLC_TRY {
		bn_new(d);
		bn_new(t);

		/* Compute d = b^2 - 4ac. */
		bn_set_dig(d, b);
		if (b < 0) {
			bn_neg(d, d);
		}
		bn_sqr(d, d);

		bn_set_dig(t, a);
		if (a < 0) {
			bn_neg(t, t);
		}
		bn_mul_dig(t, t, c);
		if (c < 0) {
			bn_neg(t, t);
		}
		bn_lsh(t, t, 2);
		bn_sub(d, d, t);
		if (bn_sign(d) == RLC_NEG) {
			bn_set_int(f->a, a);
			bn_set_int(f->b, b);
			bn_set_int(f->c, c);
		} else {
			RLC_THROW(ERR_NO_VALID);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(d);
		bn_free(t);
	}
}

void qf_set_dsc(qf_t f, const bn_t a, const bn_t b, const bn_t d) {
	if (bn_sign(d) != RLC_NEG) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_copy(f->a, a);
	bn_copy(f->b, b);
	/* Compute c = (b^2 - d)/4a. */
	bn_sqr(f->c, f->b);
	bn_sub(f->c, f->c, d);
	bn_div(f->c, f->c, f->a);
	bn_rsh(f->c, f->c, 2);
}

void qf_dsc(bn_t d, const qf_t f) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		/* Compute d = b^2 - 4ac. */
		bn_sqr(d, f->b);
		bn_mul(t, f->a, f->c);
		bn_lsh(t, t, 2);
		bn_sub(d, d, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}
}

int qf_is_prim(const qf_t f) {
	bn_t t;
	int result;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		bn_gcd(t, f->a, f->b);
		bn_gcd(t, t, f->c);
		result = (bn_cmp_dig(t, 1) == RLC_EQ);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}

	return result;
}

void qf_print(const qf_t f) {
	bn_print(f->a);
	bn_print(f->b);
	bn_print(f->c);
}
