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
 * Implementation of simultaneous point multiplication on binary elliptic
 * curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies and adds two prime elliptic curve points simultaneously, using
 * the GLV endomorphism.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 */
static void ep_mul_sim_endom(ep_t r, const ep_t p, const bn_t k, const ep_t q,
		const bn_t m) {
	const int e = 1 << (RLC_WIDTH - 2);
	int i, j, t, s[4];
	int8_t naf[4][RLC_FP_BITS + 1], u;
	bn_t n, _k[4];
	ep_t tab[4 << (RLC_WIDTH - 2)];
	size_t l, _l[4];

	bn_null(n);
	for (j = 0; j < 4; j++) {
		bn_null(_k[j]);
	}
	for (i = 0; i < (4 << (RLC_WIDTH - 2)); i++) {
		ep_null(tab[i]);
	}

	RLC_TRY {
		bn_new(n);
		for (j = 0; j < 4; j++) {
			bn_new(_k[j]);
		}
		for (i = 0; i < (4 << (RLC_WIDTH - 2)); i++) {
			ep_new(tab[i]);
		}

		ep_curve_get_ord(n);
		bn_rec_glv(_k[0], _k[1], k, n, ep_curve_get_v1(), ep_curve_get_v2());
		bn_rec_glv(_k[2], _k[3], m, n, ep_curve_get_v1(), ep_curve_get_v2());
		for (j = 0; j < 4; j++) {
			s[j] = bn_sign(_k[j]);
			bn_abs(_k[j], _k[j]);
		}

		/* Compute the precomputation tables of P and Q, normalized with one
		 * inversion unless they stay projective. */
		TMPL_EC_MUL_TAB(ep, tab, p, RLC_WIDTH);
		TMPL_EC_MUL_TAB(ep, tab + e, q, RLC_WIDTH);
		TMPL_EP_MUL_NORM(ep, tab, 2, RLC_WIDTH);
		/* Fold the signs of the subscalars into the tables, and apply the
		 * endomorphism once per entry instead of once per digit. */
		for (i = 0; i < e; i++) {
			for (j = 0; j < 2; j++) {
				ep_psi(tab[(j + 2) * e + i], tab[j * e + i]);
				if (s[2 * j + 1] == RLC_NEG) {
					ep_neg(tab[(j + 2) * e + i], tab[(j + 2) * e + i]);
				}
				if (s[2 * j] == RLC_NEG) {
					ep_neg(tab[j * e + i], tab[j * e + i]);
				}
			}
		}

		/* Compute the w-NAF representations of the subscalars k_0, k_1, m_0
		 * and m_1, which go with tables 0, 2, 1 and 3. */
		l = 0;
		for (j = 0; j < 4; j++) {
			t = 2 * (j & 1) + (j >> 1);
			_l[t] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[t], &_l[t], _k[j], RLC_WIDTH);
			l = RLC_MAX(l, _l[t]);
			if (bn_sign(j < 2 ? k : m) == RLC_NEG) {
				for (i = 0; i < (int)_l[t]; i++) {
					naf[t][i] = -naf[t][i];
				}
			}
		}

		ep_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			ep_dbl(r, r);
			for (j = 0; j < 4; j++) {
				u = ((size_t)i < _l[j] ? naf[j][i] : 0);
				if (u > 0) {
					ep_add(r, r, tab[j * e + u / 2]);
				}
				if (u < 0) {
					ep_sub(r, r, tab[j * e - u / 2]);
				}
			}
		}
		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		for (j = 0; j < 4; j++) {
			bn_free(_k[j]);
		}
		for (i = 0; i < (4 << (RLC_WIDTH - 2)); i++) {
			ep_free(tab[i]);
		}
	}
}

/**
 * Multiplies and adds multiple elliptic curve points simultaneously.
 * Computes R = \Sum_i=0..n [k_i]P_i.
 *
 * @param[out] r			- the result.
 * @param[out] p			- the elements to multiply.
 * @param[out] k			- the integer scalars.
 * @param[out] n			- the number of elements to multiply.
 */
static void ep_mul_sim_lot_endom(ep_t r, const ep_t p[], const bn_t k[],
		int n) {
	const int len = RLC_FP_BITS + 1;
	int i, j, m, sk;
	bn_t _k[2], q;
	int8_t ptr, *naf = RLC_ALLOCA(int8_t, 2 * n * len);
	size_t l, _l[2];

	bn_null(q);

	/* Up to 64 points, interleaving beats buckets with small windows. */
	if (n <= 64) {
		/* Interleave w-NAFs over tables of odd multiples of each point and
		 * of its endomorphism image, as for two points in ep_mul_sim. */
		const int e = 1 << (RLC_WIDTH - 2);
		ep_t v, *t = RLC_ALLOCA(ep_t, 2 * n * e);

		ep_null(v);
		for (j = 0; j < 2; j++) {
			bn_null(_k[j]);
		}
		for (i = 0; i < 2 * n * e; i++) {
			ep_null(t[i]);
		}

		RLC_TRY {
			bn_new(q);
			ep_new(v);
			for (j = 0; j < 2; j++) {
				bn_new(_k[j]);
			}
			for (i = 0; i < 2 * n * e; i++) {
				ep_new(t[i]);
			}

			l = 0;
			ep_curve_get_ord(q);
			for (i = 0; i < n; i++) {
				ep_t *_t = t + 2 * i * e;

				bn_mod(_k[0], k[i], q);
				sk = bn_sign(_k[0]);
				bn_rec_glv(_k[0], _k[1], _k[0], q,
						ep_curve_get_v1(), ep_curve_get_v2());
				if (sk == RLC_NEG) {
					bn_neg(_k[0], _k[0]);
					bn_neg(_k[1], _k[1]);
				}
				ep_norm(v, p[i]);
				if (bn_sign(_k[0]) == RLC_NEG) {
					ep_neg(v, v);
				}
				TMPL_EC_MUL_TAB(ep, _t, v, RLC_WIDTH);
				for (m = 0; m < e; m++) {
					ep_psi(_t[e + m], _t[m]);
					if (bn_sign(_k[1]) != bn_sign(_k[0])) {
						ep_neg(_t[e + m], _t[e + m]);
					}
				}
				for (j = 0; j < 2; j++) {
					_l[j] = len;
					bn_rec_naf(&naf[(2*i + j)*len], &_l[j], _k[j], RLC_WIDTH);
					l = RLC_MAX(l, _l[j]);
				}
			}
			/* One inversion makes every table entry affine. */
			ep_norm_sim(t, (const ep_t *)t, 2 * n * e);

			ep_set_infty(r);
			for (i = l - 1; i >= 0; i--) {
				ep_dbl(r, r);
				for (j = 0; j < 2 * n; j++) {
					ptr = naf[j * len + i];
					if (ptr > 0) {
						ep_add(r, r, t[j * e + ptr / 2]);
					}
					if (ptr < 0) {
						ep_sub(r, r, t[j * e - ptr / 2]);
					}
				}
			}
			ep_norm(r, r);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			bn_free_all(q, _k[0], _k[1]);
			ep_free(v);
			for (i = 0; i < 2 * n * e; i++) {
				ep_free(t[i]);
			}
			RLC_FREE(t);
			RLC_FREE(naf);
		}
	} else {
		/* The digits of bn_rec_naf fit in int8_t only up to w = 8. */
		const int w = RLC_MIN(8, RLC_MAX(2, util_bits_dig(n) - 2));
		const int c = (1 << (w - 2));
		ep_t s, t, u, v, *_p = RLC_ALLOCA(ep_t, c);
		ep_t *_q = RLC_ALLOCA(ep_t, 2 * n);

		ep_null_all(s, t, u, v);

		for (i = 0; i < 2; i++) {
			bn_null(_k[i]);
		}
		for (j = 0; j < c; j++) {
			ep_null(_p[j]);
		}
		for (i = 0; i < 2 * n; i++) {
			ep_null(_q[i]);
		}

		RLC_TRY {
			bn_new(q);
			ep_new_all(s, t, u, v);
			for (i = 0; i < 2; i++) {
				bn_new(_k[i]);
			}
			for (j = 0; j < c; j++) {
				ep_new(_p[j]);
				ep_set_infty(_p[j]);
			}
			for (i = 0; i < 2 * n; i++) {
				ep_new(_q[i]);
			}

			l = 0;
			ep_curve_get_ord(q);
			for (i = 0; i < n; i++) {
				ep_norm(_q[2*i], p[i]);
				ep_psi(_q[2*i + 1], _q[2*i]);
				bn_mod(_k[0], k[i], q);
				sk = bn_sign(_k[0]);
				bn_rec_glv(_k[0], _k[1], _k[0], q,
						ep_curve_get_v1(), ep_curve_get_v2());
				if (sk == RLC_NEG) {
					bn_neg(_k[0], _k[0]);
					bn_neg(_k[1], _k[1]);
				}
				for (j = 0; j < 2; j++) {
					_l[j] = len;
					bn_rec_naf(&naf[(2*i + j)*len], &_l[j], _k[j], w);
					if (bn_sign(_k[j]) == RLC_NEG) {
						for (size_t s = 0; s < _l[j]; s++) {
							naf[(2*i + j)*len + s] = -naf[(2*i + j)*len + s];
						}
					}
					l = RLC_MAX(l, _l[j]);
				}
			}

			ep_set_infty(s);
			for (i = l - 1; i >= 0; i--) {
				for (j = 0; j < n; j++) {
					for (m = 0; m < 2; m++) {
						ptr = naf[(2*j + m)*len + i];
						if (ptr != 0) {
							ep_copy(t, _q[2*j + m]);
							if (ptr < 0) {
								ptr = -ptr;
								ep_neg(t, t);
							}
							ptr >>= 1;
							ep_add(_p[ptr], _p[ptr], t);
						}
					}
				}

				ep_set_infty(u);
				ep_set_infty(v);
				for (j = c - 1; j >= 0; j--) {
					ep_add(u, u, _p[j]);
					if (j == 0) {
						ep_dbl(v, v);
					}
					ep_add(v, v, u);
					ep_set_infty(_p[j]);
				}
				ep_dbl(s, s);
				ep_add(s, s, v);
			}

			/* Convert r to affine coordinates. */
			ep_norm(r, s);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			bn_free(q);
			ep_free_all(s, t, u, v);
			for (i = 0; i < 2; i++) {
				bn_free(_k[i]);
			}
			for (j = 0; j < c; j++) {
				ep_free(_p[j]);
			}
			for (i = 0; i < 2 * n; i++) {
				ep_free(_q[i]);
			}
			RLC_FREE(_p);
			RLC_FREE(_q);
			RLC_FREE(naf);
		}
	}
}

TMPL_EC_MUL_SIM_PLAIN(ep, RLC_FP_BITS);

TMPL_EC_MUL_SIM_LOT_PLAIN(ep);

TMPL_EC_MUL_SIM_LOT_PIPPE(ep);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_SIM(ep, glv);

TMPL_EC_MUL_SIM_GEN(ep);

void ep_mul_sim_dig(ep_t r, const ep_t p[], const dig_t k[], int n) {
	ep_t t;
	int max;

	ep_null(t);

	if (n <= 0) {
		ep_set_infty(r);
		return;
	}

	max = util_bits_dig(k[0]);
	for (int i = 1; i < n; i++) {
		max = RLC_MAX(max, (int)util_bits_dig(k[i]));
	}

	RLC_TRY {
		ep_new(t);

		ep_set_infty(t);
		for (int i = max - 1; i >= 0; i--) {
			ep_dbl(t, t);
			for (int j = 0; j < n; j++) {
				if (k[j] & ((dig_t)1 << i)) {
					ep_add(t, t, p[j]);
				}
			}
		}

		ep_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
	}
}

void ep_mul_sim_lot(ep_t r, const ep_t p[], const bn_t k[], int n) {
	int flag = 0;

	if (n == 0) {
		ep_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep_mul_sim_lot_endom(r, p, k, n);
		flag = 1;
	}

	if (!flag) {
		/* Buckets pay off once the points outnumber a few dozen. */
		if (n > 32) {
			ep_mul_sim_lot_pippe(r, p, k, n);
		} else {
			ep_mul_sim_lot_plain(r, p, k, n);
		}
	}
	(void)flag;
}
