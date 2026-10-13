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
 * Implementation of point multiplication on binary elliptic curves.
 *
 * @ingroup eb
 */

#include "relic_core.h"
#include "relic_fb_low.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Combines the accumulators of a right-to-left w-NAF method, computing
 * R = sum_i (2i + 1) * T[i] as T[0] + 2 * sum_{i >= 1} S[i], where
 * S[i] = sum_{j >= i} T[j]. The accumulators are overwritten.
 *
 * @param[out] r 				- the result.
 * @param[in,out] t				- the accumulators.
 */
static void eb_mul_odd_sum(eb_t r, eb_t *t) {
	int i;

	eb_set_infty(r);
	for (i = (1 << (RLC_WIDTH - 2)) - 1; i > 0; i--) {
		eb_add(t[i - 1], t[i - 1], t[i]);
		eb_add(r, r, t[i]);
	}
	eb_dbl(r, r);
	eb_add(r, r, t[0]);
}

/**
 * Multiplies a point on a Koblitz curve by a small element
 * alpha = b + g * tau of Z[tau], using the tau-adic NAF of alpha.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the point to multiply.
 * @param[in] b					- the integer part of alpha.
 * @param[in] g					- the coefficient of tau in alpha.
 * @param[in] u					- the parameter mu of the curve.
 */
static void eb_mul_alpha(eb_t r, const eb_t p, int b, int g, int u) {
	int8_t d[2 * RLC_WIDTH + 4];
	int c, l = 0;

	/* Compute the tau-adic NAF of alpha, least significant digit first. */
	while (b != 0 || g != 0) {
		d[l] = 0;
		if (b & 1) {
			d[l] = 2 - ((b - 2 * g) & 3);
			b -= d[l];
		}
		/* Divide by tau, using tau^2 = mu * tau - 2. */
		c = b / 2;
		b = g + u * c;
		g = -c;
		l++;
	}

	/* Evaluate the expansion with Horner's rule. */
	if (d[l - 1] > 0) {
		eb_copy(r, p);
	} else {
		eb_neg(r, p);
	}
	for (l -= 2; l >= 0; l--) {
		eb_frb(r, r);
		if (d[l] > 0) {
			eb_add(r, r, p);
		}
		if (d[l] < 0) {
			eb_sub(r, r, p);
		}
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EC_MUL_BASIC(eb);

void eb_mul_lodah(eb_t r, const eb_t p, const bn_t k) {
	dv_t x1, z1, x2, z2, r1, r2, r3, r4, r5;
	const dig_t *b;
	bn_t t, n;
	size_t bits;
	eb_t q;

	if (bn_is_zero(k) || eb_is_infty(p)) {
		eb_set_infty(r);
		return;
	}

	eb_null(q);
	bn_null_all(n, t);
	dv_null_all(x1, z1, x2, z2, r1, r2, r3, r4, r5);

	RLC_TRY {
		/* The ladder needs the input point in affine coordinates. */
		eb_new(q);
		eb_norm(q, p);
		bn_new_all(n, t);
		dv_new_all(x1, z1, x2, z2, r1, r2, r3, r4, r5);

		fb_sqr(z2, q->x);
		fb_sqr(x2, z2);
		dv_zero(r5, 2 * RLC_FB_DIGS);

		b = eb_curve_get_b();
		eb_curve_get_ord(n);
		bits = bn_bits(n);

		bn_mod(t, k, n);
		bn_add(t, t, n);
		bn_add(n, t, n);
		dv_swap_sec(t->dp, n->dp, RLC_MAX(t->used, n->used),
			bn_get_bit(t, bits) == 0);
		t->used = RLC_SEL(t->used, n->used, bn_get_bit(t, bits) == 0);

		switch (eb_curve_opt_b()) {
			case RLC_ZERO:
				break;
			case RLC_ONE:
				fb_add_dig(x2, x2, (dig_t)1);
				break;
			case RLC_TINY:
				fb_add_dig(x2, x2, b[0]);
				break;
			default:
				fb_addn_low(x2, x2, b);
				break;
		}

		/* Blind both points indebendently. */
		fb_rand(z1);
		fb_mul(x1, z1, q->x);
		fb_rand(r1);
		fb_mul(z2, z2, r1);
		fb_mul(x2, x2, r1);

		for (int i = bits - 1; i >= 0; i--) {
			int j = bn_get_bit(t, i);
			fb_mul(r1, x1, z2);
			fb_mul(r2, x2, z1);
			fb_add(r3, r1, r2);
			fb_muln_low(r4, r1, r2);
			dv_swap_sec(x1, x2, RLC_FB_DIGS, j ^ 1);
			dv_swap_sec(z1, z2, RLC_FB_DIGS, j ^ 1);
			fb_sqr(z1, r3);
			fb_muln_low(r1, z1, q->x);
			fb_addd_low(x1, r1, r4, 2 * RLC_FB_DIGS);
			fb_rdcn_low(x1, x1);
			fb_sqr(r1, z2);
			fb_sqr(r2, x2);
			fb_mul(z2, r1, r2);
			switch (eb_curve_opt_b()) {
				case RLC_ZERO:
					fb_sqr(x2, r2);
					break;
				case RLC_ONE:
					fb_add(r1, r1, r2);
					fb_sqr(x2, r1);
					break;
				case RLC_TINY:
					fb_sqr(r1, r1);
					fb_sqrl_low(x2, r2);
					fb_mul1_low(r5, r1, b[0]);
					fb_addd_low(x2, x2, r5, RLC_FB_DIGS + 1);
					fb_rdcn_low(x2, x2);
					break;
				default:
					fb_sqr(r1, r1);
					fb_sqrl_low(x2, r2);
					fb_muln_low(r5, r1, b);
					fb_addd_low(x2, x2, r5, 2 * RLC_FB_DIGS);
					fb_rdcn_low(x2, x2);
					break;
			}
			dv_swap_sec(x1, x2, RLC_FB_DIGS, j ^ 1);
			dv_swap_sec(z1, z2, RLC_FB_DIGS, j ^ 1);
		}

		if (fb_is_zero(z1)) {
			/* The point q is at infinity. */
			eb_set_infty(r);
		} else {
			if (fb_is_zero(z2)) {
				fb_copy(r->x, q->x);
				fb_add(r->y, q->x, q->y);
				fb_set_dig(r->z, 1);
			} else {
				/* r3 = z1 * z2. */
				fb_mul(r3, z1, z2);
				/* z1 = (x1 + x * z1). */
				fb_mul(z1, z1, q->x);
				fb_add(z1, z1, x1);
				/* z2 = x * z2. */
				fb_mul(z2, z2, q->x);
				/* x1 = x1 * z2. */
				fb_mul(x1, x1, z2);
				/* z2 = (x2 + x * z2)(x1 + x * z1). */
				fb_add(z2, z2, x2);
				fb_mul(z2, z2, z1);

				/* r4 = (x^2 + y) * z1 * z2 + (x2 + x * z2)(x1 + x * z1). */
				fb_sqr(r4, q->x);
				fb_add(r4, r4, q->y);
				fb_mul(r4, r4, r3);
				fb_add(r4, r4, z2);

				/* r3 = (z1 * z2 * x)^{-1}. */
				fb_mul(r3, r3, q->x);
				fb_inv(r3, r3);
				/* r4 = (x^2 + y) * z1 * z2 + (x2 + x * z2)(x1 + x * z1) * r3. */
				fb_mul(r4, r4, r3);
				/* x2 = x1 * x * z2 * (z1 * z2 * x)^{-1} = x1/z1. */
				fb_mul(x2, x1, r3);
				/* z2 = x + x1/z1. */
				fb_add(z2, x2, q->x);

				/* z2 = z2 * r4 + y. */
				fb_mul(z2, z2, r4);
				fb_add(z2, z2, q->y);

				fb_copy(r->x, x2);
				fb_copy(r->y, z2);
				fb_set_dig(r->z, 1);
			}
		}

		r->coord = BASIC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		eb_free(q);
		bn_free_all(n, t);
		dv_free_all(x1, z1, x2, z2, r1, r2, r3, r4, r5);
	}
}

void eb_mul_lwnaf(eb_t r, const eb_t p, const bn_t k) {
	int i, d, kbltz = eb_curve_is_kbltz();
	int8_t u, naf[RLC_FB_BITS + 8];
	eb_t t[1 << (RLC_WIDTH - 2)];
	bn_t n, _k;
	size_t l;

	if (bn_is_zero(k) || eb_is_infty(p)) {
		eb_set_infty(r);
		return;
	}

	bn_null_all(n, _k);
	for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
		eb_null(t[i]);
	}

	RLC_TRY {
		bn_new_all(n, _k);
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_new(t[i]);
		}

		/* Reduce the scalar to bound the length of its recoding. */
		eb_curve_get_ord(n);
		bn_mod(_k, k, n);

		/* Compute the precomputation table. */
		eb_tab(t, p, RLC_WIDTH);

		/* Compute the w-TNAF or w-NAF representation of k. */
		l = sizeof(naf);
		if (kbltz) {
			u = (eb_curve_opt_a() == RLC_ZERO ? -1 : 1);
			bn_rec_tnaf(naf, &l, _k, u, RLC_FB_BITS, RLC_WIDTH);
		} else {
			bn_rec_naf(naf, &l, _k, RLC_WIDTH);
		}

		eb_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			/* The Frobenius map replaces doubling on Koblitz curves. */
			if (kbltz) {
				eb_frb(r, r);
			} else {
				eb_dbl(r, r);
			}

			d = naf[i];
			if (d > 0) {
				eb_add(r, r, t[d / 2]);
			}
			if (d < 0) {
				eb_sub(r, r, t[-d / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		eb_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, _k);
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_free(t[i]);
		}
	}
}

void eb_mul_rwnaf(eb_t r, const eb_t p, const bn_t k) {
	size_t i;
	int d, kbltz = eb_curve_is_kbltz();
	int8_t u, naf[RLC_FB_BITS + 8];
	int8_t beta[1 << (RLC_WIDTH - 2)], gama[1 << (RLC_WIDTH - 2)];
	uint8_t t_w;
	eb_t t[1 << (RLC_WIDTH - 2)];
	bn_t n, _k;
	size_t l;

	if (bn_is_zero(k) || eb_is_infty(p)) {
		eb_set_infty(r);
		return;
	}

	bn_null_all(n, _k);
	for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
		eb_null(t[i]);
	}

	RLC_TRY {
		bn_new_all(n, _k);
		/* Prepare the accumulator table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_new(t[i]);
			eb_set_infty(t[i]);
		}

		/* Reduce the scalar to bound the length of its recoding. */
		eb_curve_get_ord(n);
		bn_mod(_k, k, n);

		/* Compute the w-TNAF or w-NAF representation of k. */
		u = (eb_curve_opt_a() == RLC_ZERO ? -1 : 1);
		l = sizeof(naf);
		if (kbltz) {
			bn_rec_tnaf(naf, &l, _k, u, RLC_FB_BITS, RLC_WIDTH);
		} else {
			bn_rec_naf(naf, &l, _k, RLC_WIDTH);
		}

		/* The method needs the input point in affine coordinates. */
		eb_norm(r, p);
		for (i = 0; i < l; i++) {
			d = naf[i];
			if (d > 0) {
				eb_add(t[d / 2], t[d / 2], r);
			}
			if (d < 0) {
				eb_sub(t[-d / 2], t[-d / 2], r);
			}

			/* The Frobenius map replaces doubling on Koblitz curves, and
			 * only squares the coordinates of an affine point. */
			if (kbltz) {
				fb_sqr(r->x, r->x);
				fb_sqr(r->y, r->y);
			} else {
				eb_dbl(r, r);
			}
		}

		if (kbltz) {
			/* Multiply each accumulator by its representative alpha. */
			bn_rec_tnaf_get(&t_w, beta, gama, u, RLC_WIDTH);
			for (i = 1; i < (1 << (RLC_WIDTH - 2)); i++) {
				eb_copy(r, t[i]);
				eb_mul_alpha(t[i], r, beta[i], gama[i], u);
			}
			/* Add the accumulators. */
			eb_copy(r, t[0]);
			for (i = 1; i < (1 << (RLC_WIDTH - 2)); i++) {
				eb_add(r, r, t[i]);
			}
		} else {
			eb_mul_odd_sum(r, t);
		}
		/* Convert r to affine coordinates. */
		eb_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, _k);
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_free(t[i]);
		}
	}
}

void eb_mul_halve(eb_t r, const eb_t p, const bn_t k) {
	int i, j, cof;
	dig_t trc;
	int8_t naf[RLC_FB_BITS + 1], *_k;
	eb_t a, q, s, t[1 << (RLC_WIDTH - 2)];
	bn_t n, m;
	fb_t u, v, w, z;
	size_t l;

	if (bn_is_zero(k) || eb_is_infty(p)) {
		eb_set_infty(r);
		return;
	}

	bn_null_all(m, n);
	eb_null_all(a, q, s);
	for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
		eb_null(t[i]);
	}
	fb_null_all(u, v, w, z);

	RLC_TRY {
		/* The method needs the input point in affine coordinates. */
		eb_new(a);
		eb_norm(a, p);
		bn_new_all(n, m);
		eb_new_all(q, s);
		fb_new_all(u, v, w, z);

		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_new(t[i]);
			eb_set_infty(t[i]);
		}

		/* Convert k to alternate representation k' = (2^{t-1}k mod n). */
		eb_curve_get_ord(n);
		bn_lsh(m, k, bn_bits(n) - 1);
		bn_mod(m, m, n);

		/* Compute the w-NAF representation of k'. */
		l = sizeof(naf);
		bn_rec_naf(naf, &l, m, RLC_WIDTH);

		if (naf[bn_bits(n)] == 1) {
			eb_dbl(t[0], a);
		}
		l = bn_bits(n);
		_k = naf + l - 1;

		eb_copy(q, a);
		eb_curve_get_cof(n);

		/* Test if curve has a cofactor bigger than 2. */
		if (bn_cmp_dig(n, 2) == RLC_GT) {
			cof = 1;
		} else {
			cof = 0;
		}

		trc = fb_trc(eb_curve_get_a());

		if (cof) {
			/* Curves with cofactor > 2, u = sqrt(a), v = Solve(u). */
			fb_srt(u, eb_curve_get_a());
			fb_slv(v, u);

			bn_rand(n, RLC_POS, l);

			for (i = l - 1; i >= 0; i--, _k--) {
				j = *_k;
				if (j > 0) {
					eb_norm(s, q);
					eb_add(t[j / 2], t[j / 2], s);
				}
				if (j < 0) {
					eb_norm(s, q);
					eb_sub(t[-j / 2], t[-j / 2], s);
				}

				/* T = 1/2(Q). */
				eb_hlv(s, q);

				/* If Tr(x_T) != Tr(a). */
				if (fb_trc(s->x) != 0) {
					/* z = l_t, w = sqrt(l_Q), l_T = l_T + sqrt(l_Q) + v. */
					fb_copy(z, s->y);
					fb_srt(w, q->y);
					fb_add(s->y, s->y, w);
					fb_add(s->y, s->y, v);
					/* z = (z + x_Q + v + sqrt(a)). */
					fb_add(z, z, q->x);
					fb_add(z, z, v);
					fb_add(z, z, u);
					/* w = sqrt(w + x_Q + l_Q + sqrt(a)). */
					fb_add(w, w, q->x);
					fb_add(w, w, q->y);
					fb_add(w, w, u);
					/* x_T = sqrt(w * z), . */
					fb_mul(w, w, z);
					fb_srt(s->x, w);
					fb_set_dig(s->z, 1);
					s->coord = HALVE;
				}
				eb_copy(q, s);
			}
		} else {
			for (i = l - 1; i >= 0; i--, _k--) {
				j = *_k;
				if (j > 0) {
					eb_norm(q, q);
					eb_add(t[j / 2], t[j / 2], q);
				}
				if (j < 0) {
					eb_norm(q, q);
					eb_sub(t[-j / 2], t[-j / 2], q);
				}
				eb_hlv(q, q);
			}
		}

		eb_mul_odd_sum(r, t);
		eb_norm(r, r);

		/* We may need to fix an error of a 2-torsion point if the curve has a
		 * 4-cofactor. */
		if (cof) {
			eb_hlv(s, r);
			if (fb_trc(s->x) != trc) {
				fb_zero(s->x);
				fb_srt(s->y, eb_curve_get_b());
				fb_set_dig(s->z, 1);
				eb_add(r, r, s);
				eb_norm(r, r);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_free(t[i]);
		}
		bn_free_all(n, m);
		eb_free_all(a, q, s);
		fb_free_all(u, v, w, z);
	}
}

#ifdef EB_PRECO
TMPL_EC_MUL_GEN(eb, preco);
#else
TMPL_EC_MUL_GEN(eb, plain);
#endif

TMPL_EC_MUL_DIG(eb);
