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
 * @ingroup eb
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/


/**
 * Multiplies and adds two binary elliptic curve points simultaneously,
 * optionally choosing the first point as the generator depending on an optional
 * table of precomputed points.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 * @param[in] t					- the pointer to a precomputed table.
 */
static void eb_mul_sim_kbltz(eb_t r, const eb_t p, const bn_t k, const eb_t q,
		const bn_t m, const eb_t *t) {
	int i, n0, n1, w, g;
	int8_t u, tnaf0[RLC_FB_BITS + 8], tnaf1[RLC_FB_BITS + 8], *_k, *_m;
	eb_t t0[1 << (RLC_WIDTH - 2)];
	eb_t t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
		eb_null(t0[i]);
		eb_null(t1[i]);
	}

	RLC_TRY {
		/* Compute the w-TNAF representation of k. */
		if (eb_curve_opt_a() == RLC_ZERO) {
			u = -1;
		} else {
			u = 1;
		}

		g = (t == NULL ? 0 : 1);
		if (!g) {
			for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
				eb_new(t0[i]);
				eb_set_infty(t0[i]);
				fb_set_bit(t0[i]->z, 0, 1);
				t0[i]->coord = BASIC;
			}
			eb_tab(t0, p, RLC_WIDTH);
			t = (const eb_t *)t0;
		}

		/* Prepare the precomputation table. */
		for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_new(t1[i]);
			eb_set_infty(t1[i]);
			fb_set_bit(t1[i]->z, 0, 1);
			t1[i]->coord = BASIC;
		}
		/* Compute the precomputation table. */
		eb_tab(t1, q, RLC_WIDTH);

		/* Compute the w-TNAF representation of k. */
		if (g) {
			w = RLC_DEPTH;
		} else {
			w = RLC_WIDTH;
		}

		l0 = l1 = RLC_FB_BITS + 8;
		bn_rec_tnaf(tnaf0, &l0, k, u, RLC_FB_BITS, w);
		bn_rec_tnaf(tnaf1, &l1, m, u, RLC_FB_BITS, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		_k = tnaf0 + l - 1;
		_m = tnaf1 + l - 1;

		if (bn_sign(k) == RLC_NEG) {
			for (i =  0; i < l0; i++) {
				tnaf0[i] = -tnaf0[i];
			}
		}
		if (bn_sign(m) == RLC_NEG) {
			for (i =  0; i < l1; i++) {
				tnaf1[i] = -tnaf1[i];
			}
		}

		_k = tnaf0 + l - 1;
		_m = tnaf1 + l - 1;
		eb_set_infty(r);
		for (i =  l - 1; i >= 0; i--, _k--, _m--) {
			eb_frb(r, r);

			n0 = *_k;
			n1 = *_m;
			if (n0 > 0) {
				eb_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				eb_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				eb_add(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				eb_sub(r, r, t1[-n1 / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		eb_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		if (!g) {
			for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
				eb_free(t0[i]);
			}
		}
		for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_free(t1[i]);
		}
	}
}



/**
 * Multiplies and adds two binary elliptic curve points simultaneously,
 * optionally choosing the first point as the generator depending on an optional
 * table of precomputed points.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 * @param[in] t					- the pointer to a precomputed table.
 */
static void eb_mul_sim_plain(eb_t r, const eb_t p, const bn_t k, const eb_t q,
		const bn_t m, const eb_t *t) {
	int i, n0, n1, w, g = (t == NULL ? 0 : 1);
	int8_t naf0[RLC_FB_BITS + 1], naf1[RLC_FB_BITS + 1], *_k, *_m;
	eb_t t0[1 << (RLC_WIDTH - 2)];
	eb_t t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
		eb_null(t0[i]);
		eb_null(t1[i]);
	}

	RLC_TRY {
		if (!g) {
			for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
				eb_new(t0[i]);
			}
			eb_tab(t0, p, RLC_WIDTH);
			t = (const eb_t *)t0;
		}

		/* Prepare the precomputation table. */
		for (i =  0; i < (1 << (RLC_WIDTH - 2)); i++) {
			eb_new(t1[i]);
		}
		/* Compute the precomputation table. */
		eb_tab(t1, q, RLC_WIDTH);

		/* Compute the w-NAF representation of k. */
		if (g) {
			w = RLC_DEPTH;
		} else {
			w = RLC_WIDTH;
		}

		l0 = l1 = RLC_FB_BITS + 1;
		bn_rec_naf(naf0, &l0, k, w);
		bn_rec_naf(naf1, &l1, m, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
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

		_k = naf0 + l - 1;
		_m = naf1 + l - 1;
		eb_set_infty(r);
		for (i =  l - 1; i >= 0; i--, _k--, _m--) {
			eb_dbl(r, r);

			n0 = *_k;
			n1 = *_m;
			if (n0 > 0) {
				eb_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				eb_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				eb_add(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				eb_sub(r, r, t1[-n1 / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		eb_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation tables. */
		if (!g) {
			for (i =  0; i < 1 << (RLC_WIDTH - 2); i++) {
				eb_free(t0[i]);
			}
		}
		for (i =  0; i < 1 << (RLC_WIDTH - 2); i++) {
			eb_free(t1[i]);
		}
	}
}


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void eb_mul_sim(eb_t r, const eb_t p, const bn_t k, const eb_t q,
		const bn_t m) {

	if (bn_is_zero(k) || eb_is_infty(p)) {
		eb_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || eb_is_infty(q)) {
		eb_mul(r, p, k);
		return;
	}

	if (eb_curve_is_kbltz()) {
		eb_mul_sim_kbltz(r, p, k, q, m, NULL);
		return;
	}

	eb_mul_sim_plain(r, p, k, q, m, NULL);
}

void eb_mul_sim_gen(eb_t r, const bn_t k, const eb_t q, const bn_t m) {
	eb_t g;

	eb_null(g);

	if (bn_is_zero(k)) {
		eb_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || eb_is_infty(q)) {
		eb_mul_gen(r, k);
		return;
	}

	RLC_TRY {
		eb_new(g);

		eb_curve_get_gen(g);

#if EB_FIX == LWNAF && defined(EB_PRECO)
		if (eb_curve_is_kbltz()) {
			eb_mul_sim_kbltz(r, g, k, q, m, eb_curve_get_tab());
		}
#else
		if (eb_curve_is_kbltz()) {
			eb_mul_sim(r, g, k, q, m);
		}
#endif

#if EB_FIX == LWNAF && defined(EB_PRECO)
		if (!eb_curve_is_kbltz()) {
			eb_mul_sim_plain(r, g, k, q, m, eb_curve_get_tab());
		}
#else
		if (!eb_curve_is_kbltz()) {
			eb_mul_sim(r, g, k, q, m);
		}
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		eb_free(g);
	}
}

void eb_mul_sim_lot(eb_t r, const eb_t p[], const bn_t k[], int n) {
	int i, j;
	int8_t *naf = NULL;
	eb_t *_p = RLC_ALLOCA(eb_t, n);
	size_t l, *_l = RLC_ALLOCA(size_t, n);

	RLC_TRY {
		l = 0;
		for (i = 0; i < n; i++) {
			l = RLC_MAX(l, bn_bits(k[i]) + 1);
		}
		naf = RLC_ALLOCA(int8_t, n * l);
		if (naf == NULL || _p == NULL || _l == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		for (i = 0; i < n; i++) {
			eb_null(_p[i]);
			eb_new(_p[i]);
		}

		for (i = 0; i < n; i++) {
			_l[i] = l;
			eb_norm(_p[i], p[i]);
			bn_rec_naf(&naf[i*l], &_l[i], k[i], 2);
			if (bn_sign(k[i]) == RLC_NEG) {
				eb_neg(_p[i], _p[i]);
			}
		}

		eb_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			eb_dbl(r, r);
			for (j = 0; j < n; j++) {
				if (naf[j*l + i] > 0) {
					eb_add(r, r, _p[j]);
				}
				if (naf[j*l + i] < 0) {
					eb_sub(r, r, _p[j]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		eb_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (i = 0; i < n; i++) {
			eb_free(_p[i]);
		}
		RLC_FREE(_l);
		RLC_FREE(_p);
		RLC_FREE(naf);
	}
}
