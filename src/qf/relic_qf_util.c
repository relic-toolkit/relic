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

int qf_is_prime(const qf_t f) {
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

void qf_copa(qf_t f, const bn_t l) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		bn_gcd(t, f->a, l);
		if (bn_cmp_dig(t, 1) == RLC_GT) {
			bn_gcd(t, f->c, l);
			if (bn_cmp_dig(t, 1) == RLC_GT) {
				/* (a, b, c) -> (a+b+c, -b-2a, a) */
				bn_add(f->c, f->c, f->a);
				bn_add(f->c, f->c, f->b);
				bn_add(f->b, f->b, f->a);
				bn_add(f->b, f->b, f->a);
				bn_neg(f->b, f->b);
			} else {
				/* c is coprime to l: (a, b, c) -> (c, -b, a) */
				bn_neg(f->b, f->b);
			}
			bn_swap(f->a, f->c);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			bn_free(t);
		}
	}
}

void qf_prime(qf_t r, dig_t l, const bn_t dsc) {
	bn_t t0;
	dig_t d, b;

	bn_null(t0);
	bn_new(t0);

	bn_abs(t0, dsc);
	bn_mod_dig(&d, t0, l);
	if (bn_sign(dsc) == RLC_NEG && d != 0) {
		d = l - d;
	}
	for (b = 0; b < l; b++) {
		if ((b * b) % l == d % l) {
			break;
		}
	}

	/* b must have the same parity as disc, so that b^2 = disc mod 4l. */
	if (((b & 1) != 0) != (!bn_is_even(dsc))) {
		b = l - b;
	}
	bn_set_dig(r->a, l);
	bn_set_dig(r->b, b);
	qf_set_dsc(r, r->a, r->b, dsc);
	qf_rdc(r, r);
}

void qf_print(const qf_t f) {
	bn_print(f->a);
	bn_print(f->b);
	bn_print(f->c);
}

void qf_lift(qf_t f, const bn_t l) {
	qf_copa(f, l);
	bn_mul(f->b, f->b, l);
	bn_mul(f->c, f->c, l);
	bn_mul(f->c, f->c, l);
	qf_rdc(f, f);
}

void qf_max(qf_t f, const bn_t l, const bn_t disc_k, int rdc) {
	bn_t t, x, y;

	bn_null(t);
	bn_null(x);
	bn_null(y);

	RLC_TRY {
		bn_new(t);
		bn_new(x);
		bn_new(y);

		qf_copa(f, l);
		/* 1 = g0*l + g1*a, then b <- b*g0 + a*g1 (disc_k and l are odd) */
		bn_gcd_ext(t, x, y, l, f->a);
		bn_mul(f->b, f->b, x);
		bn_mul(t, f->a, y);
		bn_add(f->b, f->b, t);
		qf_set_dsc(f, f->a, f->b, disc_k);
		if (rdc) {
			qf_rdc(f, f);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
		bn_free(x);
		bn_free(y);
	}
}

void qf_kern(bn_t r, const qf_t f, const bn_t l, const bn_t disc_k) {
	bn_t t0, t1, t2, x, y;
	qf_t ft;
	int cmp;

	bn_null(x);
	bn_null(y);
	qf_null(ft);

	RLC_TRY {
		bn_new(x);
		bn_new(y);
		qf_new(ft);

		qf_copy(ft, f);
		qf_max(ft, l, disc_k, 0);

		/*
		 * Reduce ft while accumulating gamma = g0 + g1*sqrt(disc_k): each rho
		 * multiplies gamma by (b + sqrt(disc_k))/(2a).  The 2a is dropped, the
		 * common factor of g0 and g1 is removed at the end instead.
		 */
		bn_set_dig(x, 1);	/* g0 */
		bn_zero(y);		/* g1 */
		qf_norm(ft, ft);
		while ((cmp = bn_cmp_abs(ft->a, ft->c)) == RLC_GT) {
			bn_mul(t2, y, disc_k);
			bn_mul(y, y, ft->b);
			bn_add(y, y, x);
			bn_mul(x, x, ft->b);
			bn_add(x, x, t2);
			bn_copy(t2, ft->a);
			bn_copy(ft->a, ft->c);
			bn_copy(ft->c, t2);
			bn_neg(ft->b, ft->b);
			qf_norm(ft, ft);
		}

		if (bn_cmp_dig(ft->a, 1) != RLC_EQ || bn_cmp_dig(ft->b, 1) != RLC_EQ) {
			RLC_THROW(ERR_NO_VALID);
		}

		bn_gcd_lower(t1, x, y);
		bn_div(x, x, t1);
		bn_div(y, y, t1);

		bn_mod(x, x, l);
		bn_mod_inv(t0, x, l);
		bn_neg(y, y);
		bn_mul(t0, t0, y);
		bn_mod(r, t0, l);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		bn_free(y);
		qf_free(ft);
	}
}
