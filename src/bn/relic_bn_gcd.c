/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the multiple precision greatest common divisor functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Private definitions                                                         */
/*============================================================================*/

/**
 * Runs the Euclidean algorithm on the leading RLC_DIG bits of x >= y > 0,
 * returning the batched transformation (x', y')^T = [[m[0], m[1]], [m[2],
 * m[3]]] * (x, y)^T as the always-even number of committed steps, or zero
 * when the leading digits yield no trustworthy step and the caller must
 * fall back to one full-precision division.
 */
static int lehmer_step(dis_t *m, const bn_t x, const bn_t y, bn_t u, bn_t v) {
	dig_t X, Y, q, r, q2, r2;
	dis_t a0 = 1, a1 = 0, b0 = 0, b1 = 1;
	dis_t s0 = 1, s1 = 0, s2 = 0, s3 = 1, t;
	size_t bits = bn_bits(x);
	int steps = 0, even = 0;

	if (bits > RLC_DIG) {
		bn_rsh(u, x, bits - RLC_DIG);
		bn_rsh(v, y, bits - RLC_DIG);
	} else {
		bn_copy(u, x);
		bn_copy(v, y);
	}
	if (bn_is_zero(v) || bn_is_zero(u)) {
		return 0;
	}
	bn_get_dig(&X, u);
	bn_get_dig(&Y, v);
	if (Y == 0) {
		return 0;
	}

	q = X / Y;
	r = X % Y;
	/* Below this, the remainder can no longer be trusted to full precision. */
	while (r >= ((dig_t)1 << (RLC_DIG / 2))) {
		q2 = Y / r;
		r2 = Y % r;
		if (r2 < ((dig_t)1 << (RLC_DIG / 2))) {
			break;
		}
		X = Y;
		Y = r;
		t = a0 - (dis_t)q * b0;
		a0 = b0;
		b0 = t;
		t = a1 - (dis_t)q * b1;
		a1 = b1;
		b1 = t;
		steps++;
		if ((steps & 1) == 0) {
			s0 = a0;
			s1 = a1;
			s2 = b0;
			s3 = b1;
			even = steps;
		}
		q = q2;
		r = r2;
	}

	if (even == 0) {
		return 0;
	}
	m[0] = s0;
	m[1] = s1;
	m[2] = s2;
	m[3] = s3;
	return even;
}

/*
 * Extends whatever transformation (a, b; c, d) already holds with further
 * single-precision continued fraction steps on x, y, for as long as they
 * stay trustworthy. Callers reset the matrix to the identity for a first
 * pass, or carry a prior pass's result forward to refine it further.
 */
static void lehme_step_dig(dis_t *a, dis_t *b, dis_t *c, dis_t *d,
		dig_t x, dig_t y) {
	dig_t q = 0, r = 0, q2, r2, t;

	if (y != 0) {
		q = x / y;
		r = x % y;
	}
	if (r >= ((dig_t)1 << (RLC_DIG / 2))) {
		while (1) {
			q2 = y / r;
			r2 = y % r;
			if (r2 < ((dig_t)1 << (RLC_DIG / 2))) {
				break;
			}
			x = y;
			y = r;
			t = *a - q * (*c);
			*a = *c;
			*c = t;
			t = *b - q * (*d);
			*b = *d;
			*d = t;
			r = r2;
			q = q2;
		}
	}
}

/*
 * Disposes of the two cases every bn_gcd_ext_* variant must handle before
 * running its algorithm proper: either operand zero. Returns nonzero when it
 * already produced (c, d, e), leaving the caller nothing further to do.
 *
 * Signs are captured before writing anything because the outputs may alias
 * the inputs, and e.g. bn_abs(c, b) with c aliasing b makes b positive, so a
 * later bn_sign(b) would read the wrong sign. The same applies to a d that
 * aliases b.
 */
static int gcd_ext_zero(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	int sgn_a = bn_sign(a), sgn_b = bn_sign(b);

	if (bn_is_zero(a)) {
		bn_abs(c, b);
		if (d != NULL) {
			bn_zero(d);
		}
		if (e != NULL) {
			bn_set_dig(e, 1);
			if (sgn_b == RLC_NEG) {
				bn_neg(e, e);
			}
		}
		return 1;
	}
	if (bn_is_zero(b)) {
		bn_abs(c, a);
		if (d != NULL) {
			bn_set_dig(d, 1);
			if (sgn_a == RLC_NEG) {
				bn_neg(d, d);
			}
		}
		if (e != NULL) {
			bn_zero(e);
		}
		return 1;
	}
	return 0;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if BN_GCD == BASIC || !defined(STRIP)

void bn_gcd_basic(bn_t c, const bn_t a, const bn_t b) {
	bn_t u, v;

	if (bn_is_zero(a)) {
		bn_abs(c, b);
		return;
	}

	if (bn_is_zero(b)) {
		bn_abs(c, a);
		return;
	}

	bn_null_all(u, v);

	RLC_TRY {
		bn_new_all(u, v);

		bn_abs(u, a);
		bn_abs(v, b);
		while (!bn_is_zero(v)) {
			bn_copy(c, v);
			bn_mod(v, u, v);
			bn_copy(u, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(u, v);
	}
}

void bn_gcd_ext_basic(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	bn_t t, u, v, x_1, y_1, q, r;

	if (gcd_ext_zero(c, d, e, a, b)) {
		return;
	}

	bn_null_all(t, u, v, x_1, y_1, q, r);

	RLC_TRY {
		bn_new_all(t, u, v, x_1, y_1, q, r);

		bn_abs(u, a);
		bn_abs(v, b);

		bn_zero(x_1);
		bn_set_dig(y_1, 1);
		bn_set_dig(d, 1);
		if (e != NULL) {
			bn_zero(e);
		}

		while (!bn_is_zero(v)) {
			bn_div_rem(q, r, u, v);

			bn_copy(u, v);
			bn_copy(v, r);

			bn_mul(t, q, x_1);
			bn_sub(r, d, t);
			bn_copy(d, x_1);
			bn_copy(x_1, r);

			if (e != NULL) {
				bn_mul(t, q, y_1);
				bn_sub(r, e, t);
				bn_copy(e, y_1);
				bn_copy(y_1, r);
			}
		}
		if (bn_sign(a) == RLC_NEG) {
			bn_neg(d, d);
		}
		if (e != NULL && bn_sign(b) == RLC_NEG) {
			bn_neg(e, e);
		}
		bn_copy(c, u);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(t, u, v, x_1, y_1, q, r);
	}
}

#endif

#if BN_GCD == LEHME || !defined(STRIP)

void bn_gcd_lehme(bn_t c, const bn_t a, const bn_t b) {
	bn_t x, y, u, v, t0, t1, t2, t3;
	dig_t _x, _y;
	dis_t _a, _b, _c, _d;

	if (bn_is_zero(a)) {
		bn_abs(c, b);
		return;
	}

	if (bn_is_zero(b)) {
		bn_abs(c, a);
		return;
	}

	bn_null_all(x, y, u, v, t0, t1, t2, t3);

	/*
	 * Taken from Handbook of Hyperelliptic and Elliptic Cryptography.
	 */
	RLC_TRY {
		bn_new_all(x, y, u, v, t0, t1, t2, t3);

		if (bn_cmp_abs(a, b) == RLC_GT) {
			bn_abs(x, a);
			bn_abs(y, b);
		} else {
			bn_abs(x, b);
			bn_abs(y, a);
		}
		while (y->used > 1) {
			if (bn_bits(x) > RLC_DIG) {
				bn_rsh(u, x, bn_bits(x) - RLC_DIG);
				bn_rsh(v, y, bn_bits(x) - RLC_DIG);
			} else {
				bn_copy(u, x);
				bn_copy(v, y);
			}
			_x = u->dp[0];
			_y = v->dp[0];
			_a = _d = 1;
			_b = _c = 0;
			lehme_step_dig(&_a, &_b, &_c, &_d, _x, _y);
			if (_b == 0) {
				bn_mod(t0, x, y);
				bn_copy(x, y);
				bn_copy(y, t0);
			} else {
				if (bn_bits(x) > 2 * RLC_DIG) {
					bn_rsh(u, x, bn_bits(x) - 2 * RLC_DIG);
					bn_rsh(v, y, bn_bits(x) - 2 * RLC_DIG);
				} else {
					bn_copy(u, x);
					bn_copy(v, y);
				}
				bn_mul_dis(t0, u, _a);
				bn_mul_dis(t1, v, _b);
				bn_mul_dis(t2, u, _c);
				bn_mul_dis(t3, v, _d);
				bn_add(u, t0, t1);
				bn_add(v, t2, t3);
				if (bn_bits(u) > RLC_DIG) {
					bn_rsh(t0, u, bn_bits(u) - RLC_DIG);
					bn_rsh(t1, v, bn_bits(u) - RLC_DIG);
				} else {
					bn_copy(t0, u);
					bn_copy(t1, v);
				}
				_x = t0->dp[0];
				_y = t1->dp[0];
				lehme_step_dig(&_a, &_b, &_c, &_d, _x, _y);
				bn_mul_dis(t0, x, _a);
				bn_mul_dis(t1, y, _b);
				bn_mul_dis(t2, x, _c);
				bn_mul_dis(t3, y, _d);
				bn_add(x, t0, t1);
				bn_add(y, t2, t3);
			}
		}
		bn_gcd_ext_dig(c, u, v, x, y->dp[0]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(x, y, u, v, t0, t1, t2, t3);
	}
}

void bn_gcd_ext_lehme(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	bn_t x, y, u, v, t0, t1, t2, t3, t4;
	dig_t _x, _y;
	dis_t _a, _b, _c, _d;
	int swap;

	if (gcd_ext_zero(c, d, e, a, b)) {
		return;
	}

	bn_null_all(x, y, u, v, t0, t1, t2, t3, t4);

	/*
	 * Taken from Handbook of Hyperelliptic and Elliptic Cryptography.
	 */
	RLC_TRY {
		bn_new_all(x, y, u, v, t0, t1, t2, t3, t4);

		if (bn_cmp_abs(a, b) != RLC_LT) {
			bn_abs(x, a);
			bn_abs(y, b);
			swap = 0;
		} else {
			bn_abs(x, b);
			bn_abs(y, a);
			swap = 1;
		}

		bn_zero(t4);
		bn_set_dig(d, 1);

		while (y->used > 1) {
			if (bn_bits(x) > RLC_DIG) {
				bn_rsh(u, x, bn_bits(x) - RLC_DIG);
				bn_rsh(v, y, bn_bits(x) - RLC_DIG);
			} else {
				bn_copy(u, x);
				bn_copy(v, y);
			}
			_x = u->dp[0];
			_y = v->dp[0];
			_a = _d = 1;
			_b = _c = 0;
			lehme_step_dig(&_a, &_b, &_c, &_d, _x, _y);
			if (_b == 0) {
				bn_div_rem(t1, t0, x, y);
				bn_copy(x, y);
				bn_copy(y, t0);
				bn_mul(t1, t1, d);
				bn_sub(t1, t4, t1);
				bn_copy(t4, d);
				bn_copy(d, t1);
			} else {
				if (bn_bits(x) > 2 * RLC_DIG) {
					bn_rsh(u, x, bn_bits(x) - 2 * RLC_DIG);
					bn_rsh(v, y, bn_bits(x) - 2 * RLC_DIG);
				} else {
					bn_copy(u, x);
					bn_copy(v, y);
				}
				bn_mul_dis(t0, u, _a);
				bn_mul_dis(t1, v, _b);
				bn_mul_dis(t2, u, _c);
				bn_mul_dis(t3, v, _d);
				bn_add(u, t0, t1);
				bn_add(v, t2, t3);
				if (bn_bits(u) > RLC_DIG) {
					bn_rsh(t0, u, bn_bits(u) - RLC_DIG);
					bn_rsh(t1, v, bn_bits(u) - RLC_DIG);
				} else {
					bn_copy(t0, u);
					bn_copy(t1, v);
				}
				_x = t0->dp[0];
				_y = t1->dp[0];
				lehme_step_dig(&_a, &_b, &_c, &_d, _x, _y);
				bn_mul_dis(t0, x, _a);
				bn_mul_dis(t1, y, _b);
				bn_mul_dis(t2, x, _c);
				bn_mul_dis(t3, y, _d);
				bn_add(x, t0, t1);
				bn_add(y, t2, t3);

				bn_mul_dis(t0, t4, _a);
				bn_mul_dis(t1, d, _b);
				bn_mul_dis(t2, t4, _c);
				bn_mul_dis(t3, d, _d);
				bn_add(t4, t0, t1);
				bn_add(d, t2, t3);
			}
		}
		bn_gcd_ext_dig(c, u, v, x, y->dp[0]);
		if (!swap) {
			bn_mul(t0, t4, u);
			bn_mul(t1, d, v);
			bn_add(t4, t0, t1);
			bn_mul(x, b, t4);
			bn_sub(x, c, x);
			bn_div(d, x, a);
			if (bn_sign(b) == RLC_NEG) {
				bn_neg(d, d);
				if (bn_sign(a) == RLC_NEG) {
					bn_sub_dig(d, d, 1);
				}
			}
			if (e != NULL) {
				bn_copy(e, t4);
				if (bn_sign(b) == RLC_NEG) {
					bn_neg(e, e);
				}
			}
		} else {
			bn_mul(t0, t4, u);
			bn_mul(t1, d, v);
			bn_add(d, t0, t1);
			bn_mul(x, a, d);
			bn_sub(x, c, x);
			bn_div(t4, x, b);
			if (bn_sign(a) == RLC_NEG) {
				bn_neg(d, d);
			}
			if (e != NULL) {
				bn_copy(e, t4);
				if (bn_sign(a) == RLC_NEG) {
					bn_neg(e, e);
					if (bn_sign(b) == RLC_NEG) {
						bn_sub_dig(e, e, 1);
					}
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(x, y, u, v, t0, t1, t2, t3, t4);
	}
}

#endif

#if BN_GCD == BINAR || !defined(STRIP)

void bn_gcd_binar(bn_t c, const bn_t a, const bn_t b) {
	bn_t u, v, t;
	int shift;

	if (bn_is_zero(a)) {
		bn_abs(c, b);
		return;
	}

	if (bn_is_zero(b)) {
		bn_abs(c, a);
		return;
	}

	bn_null_all(u, v, t);

	RLC_TRY {
		bn_new_all(u, v, t);

		bn_abs(u, a);
		bn_abs(v, b);

		shift = 0;
		while (bn_is_even(u) && bn_is_even(v)) {
			bn_hlv(u, u);
			bn_hlv(v, v);
			shift++;
		}
		while (!bn_is_zero(u)) {
			while (bn_is_even(u)) {
				bn_hlv(u, u);
			}
			while (bn_is_even(v)) {
				bn_hlv(v, v);
			}
			bn_sub(t, u, v);
			bn_abs(t, t);
			bn_hlv(t, t);
			if (bn_cmp(u, v) != RLC_LT) {
				bn_copy(u, t);
			} else {
				bn_copy(v, t);
			}
		}
		bn_lsh(c, v, shift);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(u, v, t);
	}
}

void bn_gcd_ext_binar(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	bn_t x, y, t, u, v, _a, _b, _e;
	int shift;

	if (gcd_ext_zero(c, d, e, a, b)) {
		return;
	}

	bn_null_all(x, y, t, u, v, _a, _b, _e);

	RLC_TRY {
		bn_new_all(x, y, t, u, v, _a, _b, _e);

		bn_abs(x, a);
		bn_abs(y, b);

		/* Strip the common factors of two; shift restores them at the end. */
		shift = 0;
		while (bn_is_even(x) && bn_is_even(y)) {
			bn_hlv(x, x);
			bn_hlv(y, y);
			shift++;
		}

		bn_copy(u, x);
		bn_copy(v, y);

		/*
		 * Binary extended GCD (HAC Algorithm 14.61): _a, _b, d, _e are the
		 * textbook cofactors A, B, C, D, tracking u = A*x + B*y and
		 * v = C*x + D*y as u and v are reduced to their GCD below.
		 */
		bn_set_dig(_a, 1);
		bn_zero(_b);
		bn_zero(d);
		bn_set_dig(_e, 1);

		while (bn_is_even(u)) {
			bn_hlv(u, u);
			if ((_a->dp[0] & 0x01) == 0 && (_b->dp[0] & 0x01) == 0) {
				bn_hlv(_a, _a);
				bn_hlv(_b, _b);
			} else {
				bn_add(_a, _a, y);
				bn_hlv(_a, _a);
				bn_sub(_b, _b, x);
				bn_hlv(_b, _b);
			}
		}
		while (bn_cmp(u, v) != RLC_EQ) {
			if (bn_is_even(v)) {
				bn_hlv(v, v);
				if ((d->dp[0] & 0x01) == 0 && (_e->dp[0] & 0x01) == 0) {
					bn_hlv(d, d);
					bn_hlv(_e, _e);
				} else {
					bn_add(d, d, y);
					bn_hlv(d, d);
					bn_sub(_e, _e, x);
					bn_hlv(_e, _e);
				}
			} else {
				if (bn_cmp(v, u) == RLC_LT) {
					bn_copy(c, u);
					bn_copy(u, v);
					bn_copy(v, c);
					bn_copy(c, d);
					bn_copy(d, _a);
					bn_copy(_a, c);
					bn_copy(c, _e);
					bn_copy(_e, _b);
					bn_copy(_b, c);
				} else {
					bn_sub(v, v, u);
					bn_sub(d, d, _a);
					bn_sub(_e, _e, _b);
				}
			}
		}
		/* The loop above ends with u = v = gcd(x, y); restore the shift. */
		bn_lsh(c, u, shift);
		/* Reduce the oversized cofactors using the coprime pair (x/g, y/g). */
		bn_div(x, x, u);
		bn_div(y, y, u);
		bn_hlv(_a, x);
		bn_hlv(_b, y);
		while (bn_cmp_abs(d, _b) == RLC_GT || bn_cmp_abs(_e, _a) == RLC_GT) {
			bn_div(t, d, _b);
			if (bn_bits(t) > 1) {
				bn_hlv(t, t);
			}
			bn_mul(v, x, t);
			bn_mul(u, y, t);
			if (bn_sign(d) != bn_sign(u)) {
				bn_add(d, d, u);
				bn_sub(_e, _e, v);
			} else {
				bn_sub(d, d, u);
				bn_add(_e, _e, v);
			}
		}
		if (bn_sign(a) == RLC_NEG) {
			bn_neg(d, d);
		}
		if (e != NULL) {
			bn_copy(e, _e);
			if (bn_sign(b) == RLC_NEG) {
				bn_neg(e, e);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(x, y, t, u, v, _a, _b, _e);
	}
}

#endif

#if BN_GCD == LOWER || !defined(STRIP)

void bn_gcd_lower(bn_t c, const bn_t a, const bn_t b) {
	bn_t u, v, g;
	size_t shift = 0;

	if (bn_is_zero(a)) {
		bn_abs(c, b);
		return;
	}
	if (bn_is_zero(b)) {
		bn_abs(c, a);
		return;
	}

	bn_null_all(u, v, g);

	RLC_TRY {
		bn_new_all(u, v, g);

		if (a->used >= b->used) {
			bn_abs(u, a);
			bn_abs(v, b);
		} else {
			/* swap the buffers so that u holds U and v holds V */
			bn_abs(u, b);
			bn_abs(v, a);
		}

		/* mpn_gcd writes at most vn limbs to its result. */
		bn_grow(g, v->used);

		while (bn_is_even(u) && bn_is_even(v)) {
			bn_hlv(u, u);
			bn_hlv(v, v);
			shift++;
		}

		g->used = bn_gcdn_low(g->dp, u->dp, u->used, v->dp, v->used);
		g->sign = RLC_POS;
		bn_trim(g);
		bn_lsh(g, g, shift);

		bn_copy(c, g);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(u, v, g);
	}
}

void bn_gcd_ext_lower(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	bn_t u, v, g, s, t;
	bn_st *ps, *pt;
	size_t un, vn;
	int su, sv, sn, sgn_a, sgn_b, swap;

	/* mpn_gcdext rejects a zero operand, so dispose of those first. */
	if (gcd_ext_zero(c, d, e, a, b)) {
		return;
	}
	sgn_a = bn_sign(a);
	sgn_b = bn_sign(b);

	bn_null_all(u, v, g, s, t);
 
	RLC_TRY {
		bn_new_all(u, v, g, s, t);
 
		/*
		 * un >= vn is a requirement on the limb counts, not on the values.
		 * Whichever operand takes the role of U gets the cofactor S that
		 * mpn_gcdext returns; the other one gets T.
		 */
		swap = (a->used < b->used);
		if (!swap) {
			ps = d;
			pt = e;
			su = sgn_a;
			sv = sgn_b;
		} else {
			/* swap the buffers so that u holds U and v holds V */
			ps = e;
			pt = d;
			su = sgn_b;
			sv = sgn_a;
		}
		bn_abs(u, swap ? b : a);
		bn_abs(v, swap ? a : b);
		un = u->used;
		vn = v->used;
 
		bn_grow(g, vn + 1); 
		bn_grow(s, vn + 1);

		g->used = bn_gcde_low(g->dp, s->dp, &sn, u->dp, un, v->dp, vn);
		g->sign = RLC_POS;
		bn_trim(g);
 
		s->used = (sn < 0 ? -sn : sn);
		s->sign = (sn < 0) ? RLC_NEG : RLC_POS;
		bn_trim(s);
 
		if (pt != NULL) {
			/*
			 * T = (G - U*S)/V.  Both operands were destroyed by mpn_gcdext, so
			 * rebuild the magnitudes from the untouched inputs.
			 */
			bn_abs(u, swap ? b : a);
			bn_abs(v, swap ? a : b);
			bn_mul_sub(t, g, u, s);
			bn_div_exc(t, t, v);
		}
 
		/*
		 * G = |U|*S + |V|*T, and the caller wants a*d + b*e = c, so the
		 * cofactor of a negative operand is negated.
		 */
		if (ps != NULL) {
			bn_copy(ps, s);
			if (su == RLC_NEG) {
				bn_neg(ps, ps);
			}
		}
		if (pt != NULL) {
			bn_copy(pt, t);
			if (sv == RLC_NEG) {
				bn_neg(pt, pt);
			}
		}
		bn_copy(c, g);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(u, v, g, s, t);
	}
}

#endif

void bn_gcd_ext_par(bn_t c, bn_t d, bn_t u00, bn_t u01, bn_t u10, bn_t u11,
		const bn_t a, const bn_t b, const bn_t l) {
	bn_t q, t0, t1, t2, t3, t4, t5;
	dis_t m[4], n[4];
	int c_big, steps;
	int flag = 0;

	bn_null_all(q, t0, t1, t2, t3, t4, t5);

	RLC_TRY {
		bn_new_all(q, t0, t1, t2, t3, t4, t5);

		bn_set_dig(u00, 1);
		bn_zero(u01);
		bn_zero(u10);
		bn_set_dig(u11, 1);

		bn_abs(c, a);
		bn_abs(d, b);

		/*
		 * Reduce with repeated mpn_hgcd2 rather than one mpn_hgcd plus the
		 * Lehmer loop below. The batch mpn_hgcd2 commits per full-precision
		 * pass grows with the operands, so the advantage widens with size:
		 * measured 1.42x at 511-bit operands and 1.28x at 1040-bit ones.
		 * The Lehmer loop is kept as the fallback for anything this declines.
		 */
		if (!bn_is_zero(c) && !bn_is_zero(d)) {
			size_t sm, n, nl = RLC_MAX(c->used, d->used);
			/*
			 * Stop one digit above the bound rather than at it. Reducing
			 * further is not free: the cofactors grow as the operands shrink,
			 * so a tighter stop hands the caller larger minors and a form
			 * further from reduced, and the reduction pays more than this loop
			 * saves. Measured across eight pinned groups, one digit of slack
			 * beats both stopping at the bound and stopping two digits above.
			 */
			size_t tgt = (bn_bits(l) + RLC_DIG - 1) / RLC_DIG + 1;

			bn_grow(c, nl + 2);
			bn_grow(d, nl + 2);
			bn_grow(u00, nl + 2);
			bn_grow(u01, nl + 2);
			bn_grow(u10, nl + 2);
			bn_grow(u11, nl + 2);
			for (size_t i = c->used; i < nl + 2; i++) {
				c->dp[i] = 0;
			}
			for (size_t i = d->used; i < nl + 2; i++) {
				d->dp[i] = 0;
			}
			n = bn_gcdh_low(u00->dp, u01->dp, u10->dp, u11->dp, &sm,
					c->dp, d->dp, nl, tgt);
			c->used = (n ? n : 1);
			d->used = (n ? n : 1);
			c->sign = d->sign = RLC_POS;
			bn_trim(c);
			bn_trim(d);
			u00->used = u01->used = u10->used = u11->used = (sm ? sm : 1);
			u00->sign = u01->sign = u10->sign = u11->sign = RLC_POS;
			bn_trim(u00);
			bn_trim(u01);
			bn_trim(u10);
			bn_trim(u11);
			if (bn_cmp_abs(bn_cmp_abs(c, d) == RLC_GT ? c : d, l) != RLC_GT) {
				flag = 1;
			}
		}

		while (!flag) {
			c_big = (bn_cmp_abs(c, d) == RLC_GT);
			if (bn_cmp_abs(c_big ? c : d, l) != RLC_GT) {
				break;
			}
			if (bn_is_zero(c) || bn_is_zero(d)) {
				break;
			}

			steps = c_big ? lehmer_step(m, c, d, t0, t1)
					: lehmer_step(m, d, c, t0, t1);

			if (steps > 0) {
				/*
				* m acts on (larger, smaller); re-express it on (a, b).  Swapping
				* both the rows and the columns preserves the determinant.
				*/
				if (c_big) {
					n[0] = m[0]; n[1] = m[1]; n[2] = m[2]; n[3] = m[3];
				} else {
					n[0] = m[3]; n[1] = m[2]; n[2] = m[1]; n[3] = m[0];
				}

				/* candidate (a', b') = n * (a, b) */
				bn_mul_dis(t0, c, n[0]);
				bn_mul_dis(t1, d, n[1]);
				bn_add(t0, t0, t1);
				bn_mul_dis(t2, c, n[2]);
				bn_mul_dis(t3, d, n[3]);
				bn_add(t2, t2, t3);

				/*
				* Verify rather than trust.  A single-precision quotient that came
				* out too large yields a negative remainder, and the batch is then
				* not a Euclidean step sequence at all.  Checking the outcome makes
				* correctness independent of how sharp the leading-digit condition
				* is, and guarantees termination: every iteration of the outer loop
				* either commits a batch that strictly reduces the larger operand,
				* or falls back to a division that does.
				*/
				steps = (bn_sign(t0) == RLC_POS && bn_sign(t2) == RLC_POS);
				if (steps) {
					bn_copy(t4, bn_cmp_abs(t0, t2) == RLC_GT ? t0 : t2);
					steps = (bn_cmp_abs(t4, c_big ? c : d) == RLC_LT);
				}
			}

			if (steps > 0) {
				/* U <- U * n^-1, with n^-1 = [[n3, -n1], [-n2, n0]] */
				bn_mul_dis(t1, u00, n[3]);
				bn_mul_dis(t3, u01, n[2]);
				bn_mul_dis(t4, u00, n[1]);
				bn_mul_dis(t5, u01, n[0]);
				bn_sub(u00, t1, t3);
				bn_sub(u01, t5, t4);

				bn_mul_dis(t1, u10, n[3]);
				bn_mul_dis(t3, u11, n[2]);
				bn_mul_dis(t4, u10, n[1]);
				bn_mul_dis(t5, u11, n[0]);
				bn_sub(u10, t1, t3);
				bn_sub(u11, t5, t4);

				bn_copy(c, t0);
				bn_copy(d, t2);
			} else if (c_big) {
				/* a <- a mod b; U <- U * [[1, q], [0, 1]] */
				bn_div_rem(q, c, c, d);
				bn_mul(t5, q, u00);
				bn_add(u01, u01, t5);
				bn_mul(t5, q, u10);
				bn_add(u11, u11, t5);
			} else {
				/* b <- b mod a; U <- U * [[1, 0], [q, 1]] */
				bn_div_rem(q, d, d, c);
				bn_mul(t5, q, u01);
				bn_add(u00, u00, t5);
				bn_mul(t5, q, u11);
				bn_add(u10, u10, t5);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(q, t0, t1, t2, t3, t4, t5);
	}
}

void bn_gcd_ext_mid(bn_t c, bn_t d, bn_t e, bn_t f, const bn_t a, const bn_t b) {
	bn_t n, l, p, s, r0, r1, t0, t1, u00, u01, u10, u11;

	if (bn_is_zero(a) || bn_is_zero(b)) {
		/* The lattice is then x = 0 mod |a| + |b|, which (0, -1) and
		 * (|a| + |b|, 0) span. The input is read first in case e aliases it. */
		bn_abs(e, bn_is_zero(a) ? b : a);
		bn_zero(c);
		bn_set_dig(d, 1);
		bn_neg(d, d);
		bn_zero(f);
		return;
	}

	bn_null_all(n, l, p, s, r0, r1, t0, t1, u00, u01, u10, u11);

	RLC_TRY {
		bn_new_all(n, l, p, s, r0, r1, t0, t1, u00, u01, u10, u11);

		if (bn_cmp_abs(a, b) == RLC_GT) {
			bn_abs(n, a);
			bn_abs(l, b);
		} else {
			bn_abs(n, b);
			bn_abs(l, a);
		}

		/*
		 * Along the remainders r_i = t_i * l mod n, with r_m the last one at
		 * least sqrt(n), the vectors are (r_{m+1}, -t_{m+1}) and the shorter of
		 * (r_m, -t_m) and (r_{m+2}, -t_{m+2}). Bounding the partial GCD a digit
		 * above sqrt(n) stops it short of them, except after a quotient of more
		 * than a digit, which overshoots by one step and is rare enough to
		 * handle by starting over from (n, l).
		 */
		bn_srt(p, n);
		bn_lsh(s, p, RLC_DIG);
		bn_gcd_ext_par(r0, r1, u00, u01, u10, u11, n, l, s);
		/* Here r0 = u11 * n - u01 * l and r1 = u00 * l - u10 * n. */
		bn_neg(t0, u01);
		bn_copy(t1, u00);
		if (bn_cmp(r0, r1) == RLC_LT) {
			bn_swap(r0, r1);
			bn_swap(t0, t1);
		}
		if (bn_cmp(r0, p) == RLC_LT) {
			bn_copy(r0, n);
			bn_zero(t0);
			bn_copy(r1, l);
			bn_set_dig(t1, 1);
		}
		/* Step until r0 = r_{m+1}, keeping (r_m, -t_m) in (e, f). */
		while (bn_cmp(r0, p) != RLC_LT && !bn_is_zero(r1)) {
			bn_copy(e, r0);
			bn_neg(f, t0);
			bn_div_rem(s, r0, r0, r1);
			bn_swap(r0, r1);
			bn_mul(u00, s, t1);
			bn_sub(t0, t0, u00);
			bn_swap(t0, t1);
		}
		bn_copy(c, r0);
		bn_neg(d, t0);
		bn_sqr(u00, e);
		bn_sqr(u01, f);
		bn_add(u00, u00, u01);
		bn_sqr(u10, r1);
		bn_sqr(u11, t1);
		bn_add(u10, u10, u11);
		if (bn_cmp(u00, u10) != RLC_LT) {
			bn_copy(e, r1);
			bn_neg(f, t1);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, l, p, s, r0, r1, t0, t1, u00, u01, u10, u11);
	}
}

void bn_gcd_dig(bn_t c, const bn_t a, dig_t b) {
	dig_t _u, _v, _t = 0;

	if (bn_is_zero(a)) {
		bn_set_dig(c, b);
		return;
	}

	if (b == 0) {
		bn_abs(c, a);
		return;
	}

	bn_mod_dig(&(c->dp[0]), a, b);
	_v = c->dp[0];
	_u = b;
	while (_v != 0) {
		_t = _v;
		_v = _u % _v;
		_u = _t;
	}
	bn_set_dig(c, _u);
}

void bn_gcd_ext_dig(bn_t c, bn_t d, bn_t e, const bn_t a, const dig_t b) {
	bn_t u, v, x1, y1, q, r;
	dig_t _v, _q, _t, _u;

	if (d == NULL && e == NULL) {
		bn_gcd_dig(c, a, b);
		return;
	}

	if (bn_is_zero(a)) {
		bn_set_dig(c, b);
		bn_zero(d);
		if (e != NULL) {
			bn_set_dig(e, 1);
		}
		return;
	}

	if (b == 0) {
		bn_abs(c, a);
		bn_set_dig(d, 1);
		if (e != NULL) {
			bn_zero(e);
		}
		return;
	}

	bn_null_all(u, v, x1, y1, q, r);

	RLC_TRY {
		bn_new_all(u, v, x1, y1, q, r);

		bn_abs(u, a);
		bn_set_dig(v, b);

		bn_zero(x1);
		bn_set_dig(y1, 1);
		bn_set_dig(d, 1);

		if (e != NULL) {
			bn_zero(e);
		}

		bn_div_rem(q, r, u, v);

		bn_copy(u, v);
		bn_copy(v, r);

		bn_mul(c, q, x1);
		bn_sub(r, d, c);
		bn_copy(d, x1);
		bn_copy(x1, r);

		if (e != NULL) {
			bn_mul(c, q, y1);
			bn_sub(r, e, c);
			bn_copy(e, y1);
			bn_copy(y1, r);
		}

		_v = v->dp[0];
		_u = u->dp[0];
		while (_v != 0) {
			_q = _u / _v;
			_t = _u % _v;

			_u = _v;
			_v = _t;

			bn_mul_dig(c, x1, _q);
			bn_sub(r, d, c);
			bn_copy(d, x1);
			bn_copy(x1, r);

			if (e != NULL) {
				bn_mul_dig(c, y1, _q);
				bn_sub(r, e, c);
				bn_copy(e, y1);
				bn_copy(y1, r);
			}
		}
		bn_set_dig(c, _u);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(u, v, x1, y1, q, r);
	}
}
