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
#include "low/relic_bn_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/* floor(a / 2) for a sign-magnitude value, in place */
/*
 * One normalization at digit level. Returns 0 when the quotient needed more
 * than one digit, in which case nothing has been modified and the caller must
 * use the bn_t path for this step.
 */
static int qf_rdc_step(dig_t *a, dig_t *b, int *sb, dig_t *c, size_t n,
		dig_t *q, dig_t *r, dig_t *w) {
	int sq, sr, sw, sp;
	size_t na = n, nb = n;

	while (na > 1 && a[na - 1] == 0) {
		na--;
	}
	while (nb > 1 && b[nb - 1] == 0) {
		nb--;
	}

	dv_zero(q, n);

	if (bn_cmpn_low(b, nb, a, na) < 0) {
		/* |b| < a, so the quotient is 0 or 1 in magnitude */
		if (*sb == RLC_POS && !dv_is_zero(b, n)) {
			bn_subn_low(r, a, b, n);	/* |b - a| = a - b, sign negative */
			sr = RLC_NEG;
			q[0] = 1;
			sq = RLC_POS;
		} else {
			dv_copy(r, b, n);
			sr = *sb;
			sq = RLC_POS;
		}
	} else {
		/* bn_divn_low takes its operands as read-only and stages its own
		 * copies, so the live vectors go in directly. */
		bn_divn_low(q, r, b, nb, a, na);
		/* The remainder is below the divisor, so it takes at most na digits
		 * and nothing writes the rest of the vector. A backend may even leave
		 * its own scratch just above the remainder, so clear from there up. */
		dv_zero(r + na, n - na);
		for (size_t i = 1; i < n; i++) {
			if (q[i] != 0) {
				return 0;			/* wide quotient: caller falls back */
			}
		}
		if (*sb == RLC_POS) {
			if (!dv_is_zero(r, n)) {
				bn_add1_low(q, q, 1, n);
				bn_subn_low(r, a, r, n);	/* |r - a| = a - r, sign negative */
				sr = RLC_NEG;
			} else {
				sr = RLC_POS;
			}
			sq = RLC_POS;
		} else {
			sq = RLC_NEG;
			sr = RLC_NEG;
		}
	}

	if (q[0] & 1) {
		if (sr == RLC_NEG) {
			if (bn_cmpn_low(a, n, r, n) >= 0) {
				bn_subn_low(r, a, r, n);
				sr = RLC_POS;
			} else {
				bn_subn_low(r, r, a, n);
			}
		} else {
			bn_addn_low(r, r, a, n);
		}
	}
	/* q = q/2, with a negative value rounded toward minus infinity. The
	 * specialised shift returns the bit it drops, which says whether it was
	 * odd; what the backends return for it differs, so only zero is tested. */
	if (bn_rsh1_low(q, q, n) != 0 && sq == RLC_NEG) {
		bn_add1_low(q, q, 1, n);
	}

	/* w = (b + r) / 2, exact because r = b mod 2a */
	if (sr == *sb) {
		bn_addn_low(w, b, r, n);
		sw = *sb;
	} else if (bn_cmpn_low(b, n, r, n) >= 0) {
		bn_subn_low(w, b, r, n);
		sw = *sb;
	} else {
		bn_subn_low(w, r, b, n);
		sw = sr;
	}
	bn_rsh1_low(w, w, n);

	/* c -= q * w */
	sp = (sq == sw ? RLC_POS : RLC_NEG);
	if (sp == RLC_POS) {
		bn_muls_low(c, w, q[0], n);
	} else {
		bn_mula_low(c, w, q[0], n);
	}

	dv_copy(b, r, n);
	*sb = sr;
	return 1;
}

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
static inline void qf_norm_imp(qf_t f, const qf_t g, bn_t t, bn_t q, bn_t r) {
	/* b = q*a + r with -a < r <= 0, which is what rounding up gives */
	bn_div_rem_rup(q, r, g->b, g->a);
	if (!bn_is_even(q)) {
		bn_add(r, r, g->a);				/* now -a < r <= a */
	}
	bn_hlv(q, q);						/* b = (2a)*q + r */
	bn_add(t, r, g->b);					/* w = b_new + b_old, even */
	bn_hlv(t, t);
	bn_mul_sub(f->c, g->c, q, t);
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

		/*
		 * The rho loop runs on digit vectors: see qf_rdc_step above. The width
		 * bounds every intermediate, taken from the largest coefficient plus
		 * room for the product accumulated into c. If a step needs a wide
		 * quotient, or the form does not fit, what is left falls to the bn_t
		 * loop below, which handles every case.
		 */
		size_t n = RLC_MAX(RLC_MAX(f->a->used, f->c->used), f->b->used) + 2;

		/* The loop works on the coefficients where they are and takes one
		 * vector from each temporary above, so it allocates nothing and
		 * touches no digit twice. Every one of the six must hold n digits,
		 * and none of them was made with fewer than RLC_BN_SIZE. */
		if (n <= RLC_BN_SIZE) {
			dig_t *da = f->a->dp, *db = f->b->dp, *dc = f->c->dp;
			dig_t *dq = t->dp, *dr = q->dp, *dw = r->dp;
			int sb = f->b->sign;

			/* Digits above the ones in use are stale, and the width below
			 * is fixed, so the coefficients are extended with zeros. The
			 * quotient, the remainder and the sum are left alone, as every
			 * step writes them before reading them. */
			dv_zero(da + f->a->used, n - f->a->used);
			dv_zero(db + f->b->used, n - f->b->used);
			dv_zero(dc + f->c->used, n - f->c->used);

			while (bn_cmpn_low(da, n, dc, n) > 0) {
				dig_t *sw = da;
				da = dc;
				dc = sw;					/* swap a and c */
				sb = (sb == RLC_POS ? RLC_NEG : RLC_POS);
				if (!qf_rdc_step(da, db, &sb, dc, n, dq, dr, dw)) {
					/* wide quotient: undo the swap and hand back */
					sw = da;
					da = dc;
					dc = sw;
					sb = (sb == RLC_POS ? RLC_NEG : RLC_POS);
					break;
				}
			}
			f->a->used = f->b->used = f->c->used = n;
			f->a->sign = f->c->sign = RLC_POS;
			f->b->sign = sb;
			if (da != f->a->dp) {
				/* the loop stopped after an odd number of swaps, so the
				 * two coefficients sit in each other's place */
				bn_swap(f->a, f->c);
			}
			bn_trim(f->a);
			bn_trim(f->b);
			bn_trim(f->c);
		}

		/* While a > c, normalize. The loop above leaves nothing to do unless
		 * it was skipped or handed a step back, and then this finishes it. */
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