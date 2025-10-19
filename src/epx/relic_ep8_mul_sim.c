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
 * Implementation of simultaneous point multiplication on a prime elliptic
 * curve over an octic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_SIM == INTER || !defined(STRIP)

/**
 * Multiplies and adds two prime elliptic curve points simultaneously,
 * optionally choosing the first point as the generator depending on an optional
 * table of precomputed points.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 * @param[in] t					- the pointer to the precomputed table.
 */
static void ep8_mul_sim_plain(ep8_t r, const ep8_t p, const bn_t k,
		const ep8_t q, const bn_t m, ep8_t *t) {
	int i, n0, n1, w, gen = (t == NULL ? 0 : 1);
	int8_t naf0[2 * RLC_FP_BITS + 1], naf1[2 * RLC_FP_BITS + 1], *_k, *_m;
	ep8_t t0[1 << (RLC_WIDTH - 2)];
	ep8_t t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	RLC_TRY {
		if (!gen) {
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
				ep8_null(t0[i]);
				ep8_new(t0[i]);
			}
			ep8_tab(t0, p, RLC_WIDTH);
			t = (ep8_t *)t0;
		}

		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep8_null(t1[i]);
			ep8_new(t1[i]);
		}
		/* Compute the precomputation table. */
		ep8_tab(t1, q, RLC_WIDTH);

		/* Compute the w-TNAF representation of k. */
		if (gen) {
			w = RLC_DEPTH;
		} else {
			w = RLC_WIDTH;
		}
		l0 = l1 = 2 * RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k, w);
		bn_rec_naf(naf1, &l1, m, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		_k = naf0 + l - 1;
		_m = naf1 + l - 1;
		if (bn_sign(k) == RLC_NEG) {
			for (i =  0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(m) == RLC_NEG) {
			for (i =  0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		ep8_set_infty(r);
		for (i = l - 1; i >= 0; i--, _k--, _m--) {
			ep8_dbl(r, r);

			n0 = *_k;
			n1 = *_m;
			if (n0 > 0) {
				ep8_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				ep8_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				ep8_add(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				ep8_sub(r, r, t1[-n1 / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ep8_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation tables. */
		if (!gen) {
			for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
				ep8_free(t0[i]);
			}
		}
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep8_free(t1[i]);
		}
	}
}

#endif /* EP_SIM == INTER */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_SIM == BASIC || !defined(STRIP)

void ep8_mul_sim_basic(ep8_t r, const ep8_t p, const bn_t k, const ep8_t q,
		const bn_t l) {
	ep8_t t;

	ep8_null(t);

	RLC_TRY {
		ep8_new(t);
		ep8_mul(t, q, l);
		ep8_mul(r, p, k);
		ep8_add(t, t, r);
		ep8_norm(r, t);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep8_free(t);
	}
}

#endif

#if EP_SIM == TRICK || !defined(STRIP)

void ep8_mul_sim_trick(ep8_t r, const ep8_t p, const bn_t k, const ep8_t q,
		const bn_t m) {
	ep8_t t0[1 << (RLC_WIDTH / 2)];
	ep8_t t1[1 << (RLC_WIDTH / 2)];
	ep8_t t[1 << RLC_WIDTH];
	bn_t n;
	size_t l0, l1, w = RLC_WIDTH / 2;
	uint8_t w0[2 * RLC_FP_BITS], w1[2 * RLC_FP_BITS];

	bn_null(n);

	if (bn_is_zero(k) || ep8_is_infty(p)) {
		ep8_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep8_is_infty(q)) {
		ep8_mul(r, p, k);
		return;
	}

	RLC_TRY {
		bn_new(n);

		ep8_curve_get_ord(n);

		for (int i = 0; i < (1 << w); i++) {
			ep8_null(t0[i]);
			ep8_null(t1[i]);
			ep8_new(t0[i]);
			ep8_new(t1[i]);
		}
		for (int i = 0; i < (1 << RLC_WIDTH); i++) {
			ep8_null(t[i]);
			ep8_new(t[i]);
		}

		ep8_set_infty(t0[0]);
		ep8_copy(t0[1], p);
		if (bn_sign(k) == RLC_NEG) {
			ep8_neg(t0[1], t0[1]);
		}
		for (int i = 2; i < (1 << w); i++) {
			ep8_add(t0[i], t0[i - 1], t0[1]);
		}

		ep8_set_infty(t1[0]);
		ep8_copy(t1[1], q);
		if (bn_sign(m) == RLC_NEG) {
			ep8_neg(t1[1], t1[1]);
		}
		for (int i = 1; i < (1 << w); i++) {
			ep8_add(t1[i], t1[i - 1], t1[1]);
		}

		for (int i = 0; i < (1 << w); i++) {
			for (int j = 0; j < (1 << w); j++) {
				ep8_add(t[(i << w) + j], t0[i], t1[j]);
			}
		}

#if defined(EP_MIXED)
		ep8_norm_sim(t + 2, (const ep8_t *)(t + 2), (1 << (w + w)) - 2);
#endif

		l0 = l1 = RLC_CEIL(2 * RLC_FP_BITS, w);
		bn_rec_win(w0, &l0, k, w);
		bn_rec_win(w1, &l1, m, w);

		ep8_set_infty(r);
		for (int i = RLC_MAX(l0, l1) - 1; i >= 0; i--) {
			for (int j = 0; j < w; j++) {
				ep8_dbl(r, r);
			}
			ep8_add(r, r, t[(w0[i] << w) + w1[i]]);
		}
		ep8_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		for (int i = 0; i < (1 << w); i++) {
			ep8_free(t0[i]);
			ep8_free(t1[i]);
		}
		for (int i = 0; i < (1 << RLC_WIDTH); i++) {
			ep8_free(t[i]);
		}
	}
}
#endif

#if EP_SIM == INTER || !defined(STRIP)

void ep8_mul_sim_inter(ep8_t r, const ep8_t p, const bn_t k, const ep8_t q,
		const bn_t m) {
	if (bn_is_zero(k) || ep8_is_infty(p)) {
		ep8_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep8_is_infty(q)) {
		ep8_mul(r, p, k);
		return;
	}

	ep8_mul_sim_plain(r, p, k, q, m, NULL);
}

#endif

#if EP_SIM == JOINT || !defined(STRIP)

void ep8_mul_sim_joint(ep8_t r, const ep8_t p, const bn_t k, const ep8_t q,
		const bn_t m) {
	ep8_t t[5];
	int i, u_i, offset;
	int8_t jsf[4 * (RLC_FP_BITS + 1)];
	size_t l;

	if (bn_is_zero(k) || ep8_is_infty(p)) {
		ep8_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep8_is_infty(q)) {
		ep8_mul(r, p, k);
		return;
	}

	RLC_TRY {
		for (i = 0; i < 5; i++) {
			ep8_null(t[i]);
			ep8_new(t[i]);
		}

		ep8_set_infty(t[0]);
		ep8_copy(t[1], q);
		if (bn_sign(m) == RLC_NEG) {
			ep8_neg(t[1], t[1]);
		}
		ep8_copy(t[2], p);
		if (bn_sign(k) == RLC_NEG) {
			ep8_neg(t[2], t[2]);
		}
		ep8_add(t[3], t[2], t[1]);
		ep8_sub(t[4], t[2], t[1]);
#if defined(EP_MIXED)
		ep8_norm_sim(t + 3, t + 3, 2);
#endif

		l = 4 * (RLC_FP_BITS + 1);
		bn_rec_jsf(jsf, &l, k, m);

		ep8_set_infty(r);

		offset = RLC_MAX(bn_bits(k), bn_bits(m)) + 1;
		for (i = l - 1; i >= 0; i--) {
			ep8_dbl(r, r);
			if (jsf[i] != 0 && jsf[i] == -jsf[i + offset]) {
				u_i = jsf[i] * 2 + jsf[i + offset];
				if (u_i < 0) {
					ep8_sub(r, r, t[4]);
				} else {
					ep8_add(r, r, t[4]);
				}
			} else {
				u_i = jsf[i] * 2 + jsf[i + offset];
				if (u_i < 0) {
					ep8_sub(r, r, t[-u_i]);
				} else {
					ep8_add(r, r, t[u_i]);
				}
			}
		}
		ep8_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < 5; i++) {
			ep8_free(t[i]);
		}
	}
}

#endif

void ep8_mul_sim_gen(ep8_t r, const bn_t k, const ep8_t q, const bn_t m) {
	ep8_t gen;

	ep8_null(gen);

	if (bn_is_zero(k)) {
		ep8_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ep8_is_infty(q)) {
		ep8_mul_gen(r, k);
		return;
	}

	RLC_TRY {
		ep8_new(gen);

		ep8_curve_get_gen(gen);
#if EP_FIX == LWNAF && defined(EP_PRECO)
		ep8_mul_sim_plain(r, gen, k, q, m, ep8_curve_get_tab());
#else
		ep8_mul_sim(r, gen, k, q, m);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep8_free(gen);
	}
}

void ep8_mul_sim_dig(ep8_t r, const ep8_t p[], const dig_t k[], size_t len) {
	ep8_t t;
	int max;

	ep8_null(t);

	max = util_bits_dig(k[0]);
	for (int i = 1; i < len; i++) {
		max = RLC_MAX(max, util_bits_dig(k[i]));
	}

	RLC_TRY {
		ep8_new(t);

		ep8_set_infty(t);
		for (int i = max - 1; i >= 0; i--) {
			ep8_dbl(t, t);
			for (int j = 0; j < len; j++) {
				if (k[j] & ((dig_t)1 << i)) {
					ep8_add(t, t, p[j]);
				}
			}
		}

		ep8_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep8_free(t);
	}
}

void ep8_mul_sim_lot(ep8_t r, const ep8_t p[], const bn_t k[], size_t n) {
	const size_t len = RLC_FP_BITS + 1;
	int i, j, m;
	bn_t _k[8], q, x;
	int8_t *naf = RLC_ALLOCA(int8_t, 8 * n * len);
	size_t l, *_l = RLC_ALLOCA(size_t, 8 * n);

	bn_null(q);
	bn_null(x);

	if (n <= 10) {
		ep8_t *_p = RLC_ALLOCA(ep8_t, 8 * n);

		RLC_TRY {
			bn_new(q);
			bn_new(x);
			for (j = 0; j < 8; j++) {
				bn_null(_k[j]);
				bn_new(_k[j]);
				for (i = 0; i < n; i++) {
					ep8_null(_p[8*i + j]);
					ep8_new(_p[8*i + j]);
				}
			}

			for (int i = 0; i < n; i++) {
				ep8_norm(_p[8*i], p[i]);
				ep8_frb(_p[8*i + 1], _p[8*i], 1);
				ep8_frb(_p[8*i + 2], _p[8*i + 1], 1);
				ep8_frb(_p[8*i + 3], _p[8*i + 2], 1);
				ep8_frb(_p[8*i + 4], _p[8*i + 3], 1);
				ep8_frb(_p[8*i + 5], _p[8*i + 4], 1);
				ep8_frb(_p[8*i + 6], _p[8*i + 5], 1);
				ep8_frb(_p[8*i + 7], _p[8*i + 6], 1);
			}

			ep_curve_get_ord(q);
			fp_prime_get_par(x);

			l = 0;
			for (i = 0; i < n; i++) {
				bn_rec_frb(_k, 8, k[i], q, x, ep_curve_is_pairf() == EP_BN);
				for (j = 0; j < 8; j++) {
					_l[8*i + j] = len;
					bn_rec_naf(&naf[(8*i + j)*len], &_l[8*i + j], _k[j], 2);
					if (bn_sign(_k[j]) == RLC_NEG) {
						ep8_neg(_p[8*i + j], _p[8*i + j]);
					}
					l = RLC_MAX(l, _l[8*i + j]);
				}
			}

			ep8_set_infty(r);
			for (i = l - 1; i >= 0; i--) {
				ep8_dbl(r, r);
				for (j = 0; j < n; j++) {
					for (m = 0; m < 8; m++) {
						if (naf[(8*j + m)*len + i] > 0) {
							ep8_add(r, r, _p[8*j + m]);
						}
						if (naf[(8*j + m)*len + i] < 0) {
							ep8_sub(r, r, _p[8*j + m]);
						}
					}
				}
			}

			/* Convert r to affine coordinates. */
			ep8_norm(r, r);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			bn_free(q);
			bn_free(x);
			for (j = 0; j < 8; j++) {
				bn_free(_k[j]);
				for (i = 0; i < n; i++) {
					ep8_free(_p[8*i + j]);
				}
			}
			RLC_FREE(_l);
			RLC_FREE(_p);
			RLC_FREE(naf);
		}
	} else {
		const int w = RLC_MAX(2, util_bits_dig(n) - 2), c = (1 << (w - 2));
		ep8_t s, t, u, v, *_p = RLC_ALLOCA(ep8_t, 8 * c);
		int8_t ptr;

		ep8_null(s);
		ep8_null(t);
		ep8_null(u);
		ep8_null(v);

		RLC_TRY {
			bn_new(q);
			bn_new(x);
			ep8_new(s);
			ep8_new(t);
			ep8_new(u);
			ep8_new(v);
			for (i = 0; i < 8; i++) {
				bn_null(_k[i]);
				bn_new(_k[i]);
				for (j = 0; j < c; j++) {
					ep8_null(_p[i*c + j]);
					ep8_new(_p[i*c + j]);
					ep8_set_infty(_p[i*c + j]);
				}
			}

			ep_curve_get_ord(q);
			fp_prime_get_par(x);

			l = 0;
			for (i = 0; i < n; i++) {
				bn_rec_frb(_k, 8, k[i], q, x, ep_curve_is_pairf() == EP_BN);
				for (j = 0; j < 8; j++) {
					_l[8*i + j] = len;
					bn_rec_naf(&naf[(8*i + j)*len], &_l[8*i + j], _k[j], w);
					l = RLC_MAX(l, _l[8*i + j]);
				}
			}

			for (i = 0; i < n; i++) {
				for (j = 0; j < 8; j++) {
					for (m = _l[8*i + j]; m < l; m++) {
						naf[(8*i + j)*len + m] = 0;
					}
				}
			}

			ep8_set_infty(s);
			for (i = l - 1; i >= 0; i--) {
				for (j = 0; j < n; j++) {
					for (m = 0; m < 8; m++) {
						ptr = naf[(8*j + m)*len + i];
						if (ptr != 0) {
							ep8_copy(t, p[j]);
							if (ptr < 0) {
								ptr = -ptr;
								ep8_neg(t, t);
							}
							if (bn_sign(_k[m]) == RLC_NEG) {
								ep8_neg(t, t);
							}
							ep8_add(_p[m*c + (ptr/2)], _p[m*c + (ptr/2)], t);
						}
					}
				}

				ep8_set_infty(t);
				for (m = 3; m >= 0; m--) {
					ep8_frb(t, t, 1);
					ep8_set_infty(u);
					ep8_set_infty(v);
					for (j = c - 1; j >= 0; j--) {
						ep8_add(u, u, _p[m*c + j]);
						if (j == 0) {
							ep8_dbl(v, v);
						}
						ep8_add(v, v, u);
						ep8_set_infty(_p[m*c + j]);
					}
					ep8_add(t, t, v);
				}
				ep8_dbl(s, s);
				ep8_add(s, s, t);
			}

			/* Convert r to affine coordinates. */
			ep8_norm(r, s);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			bn_free(q);
			bn_free(x);
			ep8_free(s);
			ep8_free(t);
			ep8_free(u);
			ep8_free(v);
			for (i = 0; i < 8; i++) {
				bn_free(_k[i]);
				for (j = 0; j < c; j++) {
					ep8_free(_p[i*c + j]);
				}
			}
			RLC_FREE(_l);
			RLC_FREE(_p);
			RLC_FREE(naf);
		}
	}
}
