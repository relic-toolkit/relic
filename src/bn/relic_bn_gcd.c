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
 * Implementation of the multiple precision addition and subtraction functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Private definitions                                                         */
/*============================================================================*/

/**
 * Lehmer step: runs the Euclidean algorithm on the leading RLC_DIG bits of
 * x >= y > 0 and returns the batched transformation
 *
 *     (x', y')^T = [[m[0], m[1]], [m[2], m[3]]] * (x, y)^T.
 *
 * Returns the number of committed steps, always even, and zero when the leading
 * digits yield no trustworthy step, in which case the caller falls back to one
 * full-precision division.
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
	// Threshold in which a single-precision quotient can no longer be trusted.
	while (r >= ((dig_t)1 << (RLC_DIG / 2))) {
		q2 = Y / r;
		r2 = Y % r;
		if (r2 < ((dig_t)1 << (RLC_DIG / 2))) {
			break;			/* the next step would not be trustworthy */
		}
		/* commit the step with quotient q */
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

/**
 * One half-GCD step wrapping the low-level abstraction.
 */
static int hgcd_step(bn_t u00, bn_t u01, bn_t u10, bn_t u11, bn_t a, bn_t b) {
	size_t n = RLC_MAX(a->used, b->used), sm = 0, nn, s = (n + 1) / 2 + 1;

	if (n < 4) {
		return 0;
	}

	bn_grow(a, n + 1);
	bn_grow(b, n + 1);
	for (size_t i = a->used; i < n; i++) {
		a->dp[i] = 0;
	}
	for (size_t i = b->used; i < n; i++) {
		b->dp[i] = 0;
	}
	if ((a->dp[n - 1] | b->dp[n - 1]) == 0) {
		return 0;
	}
	
	bn_grow(u00, s);
	bn_grow(u01, s);
	bn_grow(u10, s);
	bn_grow(u11, s);
	nn = bn_gcdh_low(u00->dp, u01->dp, u10->dp, u11->dp, &sm, a->dp, b->dp, n);
	if (nn == 0) {
		return 0;
	}

	a->used = b->used = nn;
	a->sign = b->sign = RLC_POS;
	bn_trim(a);
	bn_trim(b);
	u00->used = u01->used = u10->used = u11->used = sm;
	u00->sign = u01->sign = u10->sign = u11->sign = RLC_POS;
	bn_trim(u00);
	bn_trim(u01);
	bn_trim(u10);
	bn_trim(u11);

	return 1;
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

	bn_null(u);
	bn_null(v);

	RLC_TRY {
		bn_new(u);
		bn_new(v);

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
		bn_free(u);
		bn_free(v);
	}
}

void bn_gcd_ext_basic(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	bn_t t, u, v, x_1, y_1, q, r;
	int sgn_a, sgn_b;

	/*
	 * Capture both signs before writing anything: the outputs may alias the
	 * inputs, and bn_abs(c, b) with c aliasing b makes b positive, so a later
	 * bn_sign(b) would read the wrong sign. The same applies to a d that
	 * aliases b.
	 */
	sgn_a = bn_sign(a);
	sgn_b = bn_sign(b);

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
		return;
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
		return;
	}

	bn_null(t);
	bn_null(u);
	bn_null(v);
	bn_null(x_1);
	bn_null(y_1);
	bn_null(q);
	bn_null(r);

	RLC_TRY {
		bn_new(t);
		bn_new(u);
		bn_new(v);
		bn_new(x_1);
		bn_new(y_1);
		bn_new(q);
		bn_new(r);

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
		bn_free(t);
		bn_free(u);
		bn_free(v);
		bn_free(x_1);
		bn_free(y_1);
		bn_free(q);
		bn_free(r);
	}
}

#endif

#if BN_GCD == LEHME || !defined(STRIP)

void bn_gcd_lehme(bn_t c, const bn_t a, const bn_t b) {
	bn_t x, y, u, v, t0, t1, t2, t3;
	dig_t _x, _y, q, _q, t, _t;
	dis_t _a, _b, _c, _d;

	if (bn_is_zero(a)) {
		bn_abs(c, b);
		return;
	}

	if (bn_is_zero(b)) {
		bn_abs(c, a);
		return;
	}

	bn_null(x);
	bn_null(y);
	bn_null(u);
	bn_null(v);
	bn_null(t0);
	bn_null(t1);
	bn_null(t2);
	bn_null(t3);

	/*
	 * Taken from Handbook of Hyperelliptic and Elliptic Cryptography.
	 */
	RLC_TRY {
		bn_new(x);
		bn_new(y);
		bn_new(u);
		bn_new(v);
		bn_new(t0);
		bn_new(t1);
		bn_new(t2);
		bn_new(t3);

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
			t = 0;
			if (_y != 0) {
				q = _x / _y;
				t = _x % _y;
			}
			if (t >= ((dig_t)1 << (RLC_DIG / 2))) {
				while (1) {
					_q = _y / t;
					_t = _y % t;
					if (_t < ((dig_t)1 << (RLC_DIG / 2))) {
						break;
					}
					_x = _y;
					_y = t;
					t = _a - q * _c;
					_a = _c;
					_c = t;
					t = _b - q * _d;
					_b = _d;
					_d = t;
					t = _t;
					q = _q;
				}
			}
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
				if (_a < 0) {
					bn_mul_dig(t0, u, -_a);
					bn_neg(t0, t0);
				} else {
					bn_mul_dig(t0, u, _a);
				}
				if (_b < 0) {
					bn_mul_dig(t1, v, -_b);
					bn_neg(t1, t1);
				} else {
					bn_mul_dig(t1, v, _b);
				}
				if (_c < 0) {
					bn_mul_dig(t2, u, -_c);
					bn_neg(t2, t2);
				} else {
					bn_mul_dig(t2, u, _c);
				}
				if (_d < 0) {
					bn_mul_dig(t3, v, -_d);
					bn_neg(t3, t3);
				} else {
					bn_mul_dig(t3, v, _d);
				}
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
				t = 0;
				if (_y != 0) {
					q = _x / _y;
					t = _x % _y;
				}
				if (t >= ((dig_t)1 << RLC_DIG / 2)) {
					while (1) {
						_q = _y / t;
						_t = _y % t;
						if (_t < ((dig_t)1 << RLC_DIG / 2)) {
							break;
						}
						_x = _y;
						_y = t;
						t = _a - q * _c;
						_a = _c;
						_c = t;
						t = _b - q * _d;
						_b = _d;
						_d = t;
						t = _t;
						q = _q;
					}
				}
				if (_a < 0) {
					bn_mul_dig(t0, x, -_a);
					bn_neg(t0, t0);
				} else {
					bn_mul_dig(t0, x, _a);
				}
				if (_b < 0) {
					bn_mul_dig(t1, y, -_b);
					bn_neg(t1, t1);
				} else {
					bn_mul_dig(t1, y, _b);
				}
				if (_c < 0) {
					bn_mul_dig(t2, x, -_c);
					bn_neg(t2, t2);
				} else {
					bn_mul_dig(t2, x, _c);
				}
				if (_d < 0) {
					bn_mul_dig(t3, y, -_d);
					bn_neg(t3, t3);
				} else {
					bn_mul_dig(t3, y, _d);
				}
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
		bn_free(x);
		bn_free(y);
		bn_free(u);
		bn_free(v);
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
		bn_free(t3);
	}
}

void bn_gcd_ext_lehme(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	int sgn_a, sgn_b;
	bn_t x, y, u, v, t0, t1, t2, t3, t4;
	dig_t _x, _y, q, _q, t, _t;
	dis_t _a, _b, _c, _d;
	int swap;

	/*
	 * Capture both signs before writing anything: the outputs may alias the
	 * inputs, and bn_abs(c, b) with c aliasing b makes b positive, so a later
	 * bn_sign(b) would read the wrong sign. The same applies to a d that
	 * aliases b.
	 */
	sgn_a = bn_sign(a);
	sgn_b = bn_sign(b);

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
		return;
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
		return;
	}

	bn_null(x);
	bn_null(y);
	bn_null(u);
	bn_null(v);
	bn_null(t0);
	bn_null(t1);
	bn_null(t2);
	bn_null(t3);
	bn_null(t4);

	/*
	 * Taken from Handbook of Hyperelliptic and Elliptic Cryptography.
	 */
	RLC_TRY {
		bn_new(x);
		bn_new(y);
		bn_new(u);
		bn_new(v);
		bn_new(t0);
		bn_new(t1);
		bn_new(t2);
		bn_new(t3);
		bn_new(t4);

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
			t = 0;
			if (_y != 0) {
				q = _x / _y;
				t = _x % _y;
			}
			if (t >= ((dig_t)1 << (RLC_DIG / 2))) {
				while (1) {
					_q = _y / t;
					_t = _y % t;
					if (_t < ((dig_t)1 << (RLC_DIG / 2))) {
						break;
					}
					_x = _y;
					_y = t;
					t = _a - q * _c;
					_a = _c;
					_c = t;
					t = _b - q * _d;
					_b = _d;
					_d = t;
					t = _t;
					q = _q;
				}
			}
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
				if (_a < 0) {
					bn_mul_dig(t0, u, -_a);
					bn_neg(t0, t0);
				} else {
					bn_mul_dig(t0, u, _a);
				}
				if (_b < 0) {
					bn_mul_dig(t1, v, -_b);
					bn_neg(t1, t1);
				} else {
					bn_mul_dig(t1, v, _b);
				}
				if (_c < 0) {
					bn_mul_dig(t2, u, -_c);
					bn_neg(t2, t2);
				} else {
					bn_mul_dig(t2, u, _c);
				}
				if (_d < 0) {
					bn_mul_dig(t3, v, -_d);
					bn_neg(t3, t3);
				} else {
					bn_mul_dig(t3, v, _d);
				}
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
				t = 0;
				if (_y != 0) {
					q = _x / _y;
					t = _x % _y;
				}
				if (t >= ((dig_t)1 << RLC_DIG / 2)) {
					while (1) {
						_q = _y / t;
						_t = _y % t;
						if (_t < ((dig_t)1 << RLC_DIG / 2)) {
							break;
						}
						_x = _y;
						_y = t;
						t = _a - q * _c;
						_a = _c;
						_c = t;
						t = _b - q * _d;
						_b = _d;
						_d = t;
						t = _t;
						q = _q;
					}
				}
				if (_a < 0) {
					bn_mul_dig(t0, x, -_a);
					bn_neg(t0, t0);
				} else {
					bn_mul_dig(t0, x, _a);
				}
				if (_b < 0) {
					bn_mul_dig(t1, y, -_b);
					bn_neg(t1, t1);
				} else {
					bn_mul_dig(t1, y, _b);
				}
				if (_c < 0) {
					bn_mul_dig(t2, x, -_c);
					bn_neg(t2, t2);
				} else {
					bn_mul_dig(t2, x, _c);
				}
				if (_d < 0) {
					bn_mul_dig(t3, y, -_d);
					bn_neg(t3, t3);
				} else {
					bn_mul_dig(t3, y, _d);
				}
				bn_add(x, t0, t1);
				bn_add(y, t2, t3);

				if (_a < 0) {
					bn_mul_dig(t0, t4, -_a);
					bn_neg(t0, t0);
				} else {
					bn_mul_dig(t0, t4, _a);
				}
				if (_b < 0) {
					bn_mul_dig(t1, d, -_b);
					bn_neg(t1, t1);
				} else {
					bn_mul_dig(t1, d, _b);
				}
				if (_c < 0) {
					bn_mul_dig(t2, t4, -_c);
					bn_neg(t2, t2);
				} else {
					bn_mul_dig(t2, t4, _c);
				}
				if (_d < 0) {
					bn_mul_dig(t3, d, -_d);
					bn_neg(t3, t3);
				} else {
					bn_mul_dig(t3, d, _d);
				}
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
		bn_free(x);
		bn_free(y);
		bn_free(u);
		bn_free(v);
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
		bn_free(t3);
		bn_free(t4);
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

	bn_null(u);
	bn_null(v);
	bn_null(t);

	RLC_TRY {
		bn_new(u);
		bn_new(v);
		bn_new(t);

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
		bn_free(u);
		bn_free(v);
		bn_free(t);
	}
}

void bn_gcd_ext_binar(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	int sgn_a, sgn_b;
	bn_t x, y, t, u, v, _a, _b, _e;
	int shift;

	/*
	 * Capture both signs before writing anything: the outputs may alias the
	 * inputs, and bn_abs(c, b) with c aliasing b makes b positive, so a later
	 * bn_sign(b) would read the wrong sign. The same applies to a d that
	 * aliases b.
	 */
	sgn_a = bn_sign(a);
	sgn_b = bn_sign(b);

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
		return;
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
		return;
	}
	
	bn_null(x);
	bn_null(y);
	bn_null(t);
	bn_null(u);
	bn_null(v);
	bn_null(_a);
	bn_null(_b);
	bn_null(_e);

	RLC_TRY {
		bn_new(x);
		bn_new(y);
		bn_new(t);
		bn_new(u);
		bn_new(v);
		bn_new(_a);
		bn_new(_b);
		bn_new(_e);

		bn_abs(x, a);
		bn_abs(y, b);

		/* g = 1. */
		shift = 0;
		/* While x and y are both even, x = x/2 and y = y/2, g = 2g. */
		while (bn_is_even(x) && bn_is_even(y)) {
			bn_hlv(x, x);
			bn_hlv(y, y);
			shift++;
		}

		bn_copy(u, x);
		bn_copy(v, y);

		/* u = x, y = v, A = 1, B = 0, C = 0, D = 1. */
		bn_set_dig(_a, 1);
		bn_zero(_b);
		bn_zero(d);
		bn_set_dig(_e, 1);

		/* While u is even, u = u/2. */
		while (bn_is_even(u)) {
			bn_hlv(u, u);
			/* If A = B = 0 (mod 2) then A = A/2, B = B/2. */
			if ((_a->dp[0] & 0x01) == 0 && (_b->dp[0] & 0x01) == 0) {
				bn_hlv(_a, _a);
				bn_hlv(_b, _b);
			} else {
				/* Otherwise A = (A + y)/2, B = (B - x)/2. */
				bn_add(_a, _a, y);
				bn_hlv(_a, _a);
				bn_sub(_b, _b, x);
				bn_hlv(_b, _b);
			}
		}
		while (bn_cmp(u, v) != RLC_EQ) {
			/* If v is even, v = v/2. */
			if (bn_is_even(v)) {
				bn_hlv(v, v);
				/* If C = D = 0 (mod 2) then C = C/2, D = D/2. */
				if ((d->dp[0] & 0x01) == 0 && (_e->dp[0] & 0x01) == 0) {
					bn_hlv(d, d);
					bn_hlv(_e, _e);
				} else {
					/* Otherwise C = (C + y)/2, D = (D - x)/2. */
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
		/* If u = 0 then d = C, e = D and return (d, e, g * v). */
		bn_lsh(c, u, shift);
		/* Now fix reciprocals. */
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
		bn_free(x);
		bn_free(y);
		bn_free(t);
		bn_free(u);
		bn_free(v);
		bn_free(_a);
		bn_free(_b);
		bn_free(_e);
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

	bn_null(u);
	bn_null(v);
	bn_null(g);

	RLC_TRY {
		bn_new(u);
		bn_new(v);
		bn_new(g);

		if (a->used >= b->used) {
			bn_abs(u, a);
			bn_abs(v, b);
		} else {
			/* swap the buffers so that u holds U and v holds V */
			bn_abs(u, b);
			bn_abs(v, a);
		}

		/* gp needs vn limbs, sp needs vn + 1 */
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
		bn_free(u);
		bn_free(v);
		bn_free(g);
	}
}

void bn_gcd_ext_lower(bn_t c, bn_t d, bn_t e, const bn_t a, const bn_t b) {
	bn_t u, v, g, s, t;
	bn_st *ps, *pt;
	const bn_st *pu, *pv;
	size_t un, vn;
	int su, sv, sn, sgn_a, sgn_b;
  
	/* mpn_gcdext rejects a zero operand, so dispose of those first. */
	/*
	 * Capture both signs before writing anything: the outputs may alias the
	 * inputs, and bn_abs(c, b) with c aliasing b makes b positive, so a later
	 * bn_sign(b) would read the wrong sign. The same applies to a d that
	 * aliases b.
	 */
	sgn_a = bn_sign(a);
	sgn_b = bn_sign(b);

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
		return;
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
		return;
	}
 
	bn_null(u);
	bn_null(v);
	bn_null(g);
	bn_null(s);
	bn_null(t);
 
	RLC_TRY {
		bn_new(u);
		bn_new(v);
		bn_new(g);
		bn_new(s);
		bn_new(t);
 
		/*
		 * un >= vn is a requirement on the limb counts, not on the values.
		 * Whichever operand takes the role of U gets the cofactor S that
		 * mpn_gcdext returns; the other one gets T.
		 */
		if (a->used >= b->used) {
			pu = a;
			pv = b;
			ps = d;
			pt = e;
			su = sgn_a;
			sv = sgn_b;
			bn_abs(u, a);
			bn_abs(v, b);
		} else {
			/* swap the buffers so that u holds U and v holds V */
			pu = b;
			pv = a;
			ps = e;
			pt = d;
			su = sgn_b;
			sv = sgn_a;
			bn_abs(u, b);
			bn_abs(v, a);
		}
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
			bn_abs(u, pu);
			bn_abs(v, pv);
			bn_mul(t, u, s);
			bn_sub(t, g, t);
			bn_div(t, t, v);
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
		bn_free(u);
		bn_free(v);
		bn_free(g);
		bn_free(s);
		bn_free(t);
	}
}

#endif

void bn_gcd_ext_mid(bn_t c, bn_t d, bn_t e, bn_t f, const bn_t a, const bn_t b) {
	bn_t p, q, r, s, t, u, v, x, w, y, z;

	if (bn_is_zero(a)) {
		bn_abs(c, b);
		bn_zero(d);
		bn_zero(e);
		return;
	}

	if (bn_is_zero(b)) {
		bn_abs(c, a);
		bn_set_dig(d, 1);
		bn_set_dig(e, 1);
		return;
	}

	bn_null(p);
	bn_null(q);
	bn_null(r);
	bn_null(s);
	bn_null(t);
	bn_null(u);
	bn_null(v);
	bn_null(x);
	bn_null(w);
	bn_null(y);
	bn_null(z);

	RLC_TRY {
		bn_new(p);
		bn_new(q);
		bn_new(r);
		bn_new(s);
		bn_new(t);
		bn_new(u);
		bn_new(v);
		bn_new(x);
		bn_new(w);
		bn_new(y);
		bn_new(z);

		if (bn_cmp_abs(a, b) == RLC_GT) {
			bn_abs(u, a);
			bn_abs(v, b);
		} else {
			bn_abs(u, b);
			bn_abs(v, a);
		}

		bn_srt(p, u);

		bn_set_dig(x, 1);
		bn_zero(t);

		int wait = 0;
		while (!bn_is_zero(v)) {
			bn_div_rem(q, r, u, v);

			bn_copy(u, v);
			bn_copy(v, r);

			bn_mul(s, q, x);
			bn_sub(s, t, s);
			bn_copy(t, x);
			bn_copy(x, s);

			if (wait) {
				bn_copy(e, r);
				bn_neg(f, x);
				wait = 0;
			}
			if (bn_cmp(u, p) != RLC_LT) {
				bn_copy(c, r);
				bn_neg(d, x);
				bn_copy(w, u);
				bn_neg(y, t);
				wait = 1;
			}
		}
		/* Compute r as the norm of vector (w, y). */
		bn_sqr(s, w);
		bn_sqr(t, y);
		bn_add(t, t, s);

		/* Compute q as the norm of vector (e, f). */
		bn_sqr(r, e);
		bn_sqr(q, f);
		bn_add(q, q, r);

		/* Output (e, f) as the vector of smaller norm. */
		if (bn_cmp(t, q) == RLC_LT) {
			bn_copy(e, w);
			bn_copy(f, y);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(p);
		bn_free(q);
		bn_free(r);
		bn_free(s);
		bn_free(t);
		bn_free(u);
		bn_free(v);
		bn_free(x);
		bn_free(w);
		bn_free(y);
		bn_free(z);
	}
}

void bn_gcd_ext_par(bn_t c, bn_t d, bn_t u00, bn_t u01, bn_t u10, bn_t u11,
		const bn_t a, const bn_t b, const bn_t l) {
	bn_t q, t0, t1, t2, t3, t4, t5;
	dis_t m[4], n[4];
	int c_big, steps;
	int flag = 0;

	bn_null(q);
	bn_null(t0);
	bn_null(t1);
	bn_null(t2);
	bn_null(t3);
	bn_null(t4);
	bn_null(t5);

	RLC_TRY {
		bn_new(q);
		bn_new(t0);
		bn_new(t1);
		bn_new(t2);
		bn_new(t3);
		bn_new(t4);
		bn_new(t5);

		bn_set_dig(u00, 1);
		bn_zero(u01);
		bn_zero(u10);
		bn_set_dig(u11, 1);

		bn_abs(c, a);
		bn_abs(d, b);

		if (hgcd_step(u00, u01, u10, u11, c, d)) {
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
		bn_free(q);
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
		bn_free(t3);
		bn_free(t4);
		bn_free(t5);
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

	bn_null(u);
	bn_null(v);
	bn_null(x1);
	bn_null(y1);
	bn_null(q);
	bn_null(r);

	RLC_TRY {
		bn_new(u);
		bn_new(v);
		bn_new(x1);
		bn_new(y1);
		bn_new(q);
		bn_new(r);

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
		bn_free(u);
		bn_free(v);
		bn_free(x1);
		bn_free(y1);
		bn_free(q);
		bn_free(r);
	}
}
