/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of the multi-key linearly homomophic signature protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Hashes a pair of strings to G_1 as t || a || 0 || b, where t separates the
 * uses of the hash. Strings have no zero bytes, so distinct pairs never give
 * the same input.
 *
 * @param[out] p			- the resulting point.
 * @param[out] buf			- a buffer with room for both strings and 2 bytes.
 * @param[in] t				- the domain separation byte.
 * @param[in] a				- the first string.
 * @param[in] b				- the second string.
 */
static void mklhs_map(g1_t p, uint8_t *buf, uint8_t t, const char *a,
		const char *b) {
	size_t la = strlen(a), lb = strlen(b);

	buf[0] = t;
	memcpy(buf + 1, a, la);
	buf[la + 1] = 0;
	memcpy(buf + la + 2, b, lb);
	g1_map(p, buf, la + lb + 2);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_mklhs_gen(bn_t sk, g2_t pk) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(sk, n);
		g2_mul_gen(pk, sk);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_mklhs_sig(g1_t s, const bn_t m, const char *data, const char *id,
		const char *tag, const bn_t sk) {
	bn_t n;
	g1_t a;
	int result = RLC_OK;
	uint8_t *str = RLC_ALLOCA(uint8_t,
			strlen(id) + RLC_MAX(strlen(data), strlen(tag)) + 2);

	if (str == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	g1_null(a);

	RLC_TRY {
		bn_new(n);
		g1_new(a);

		pc_get_ord(n);
		g1_mul_gen(a, m);

		mklhs_map(s, str, 1, data, id);
		g1_add(s, s, a);

		mklhs_map(a, str, 2, id, tag);
		g1_add(s, s, a);
		g1_norm(s, s);
		g1_mul_sec(s, s, sk);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		RLC_FREE(str);
		bn_free(n);
		g1_free(a);
	}
	return result;
}

int cp_mklhs_fun(bn_t mu, const bn_t m[], const dig_t f[], size_t len) {
	bn_t n, t;
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(t);

		pc_get_ord(n);
		bn_zero(mu);
		for (size_t i = 0; i < len; i++) {
			bn_mul_dig(t, m[i], f[i]);
			bn_add(mu, mu, t);
			bn_mod(mu, mu, n);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(t);
	}
	return result;
}

int cp_mklhs_evl(g1_t sig, const g1_t s[], const dig_t f[], size_t len) {
	int result = RLC_OK;

	g1_mul_sim_dig(sig, s, f, len);

	return result;
}

int cp_mklhs_ver(const g1_t sig, const bn_t m, const bn_t mu[],
		const char *data, const char *id[], const char *tag[], const dig_t *f[],
		const size_t flen[], const g2_t pk[], size_t slen) {
	bn_t t, n;
	g1_t d, *g = RLC_ALLOCA(g1_t, slen);
	gt_t c;
	size_t imax = 0, lmax = 0, fmax = 0;
	int result = 0;
	for (size_t i = 0; i < slen; i++) {
		fmax = RLC_MAX(fmax, flen[i]);
		imax = RLC_MAX(imax, strlen(id[i]));
		for (size_t j = 0; j < flen[i]; j++) {
			lmax = RLC_MAX(lmax, strlen(tag[j]));
		}
	}
	g1_t *h = RLC_ALLOCA(g1_t, fmax);
	uint8_t *str = RLC_ALLOCA(uint8_t, imax + RLC_MAX(strlen(data), lmax) + 2);

	if (g == NULL || h == NULL || str == NULL) {
		RLC_FREE(g);
		RLC_FREE(h);
		RLC_FREE(str);
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	bn_null(t);
	bn_null(n);
	g1_null(d);
	gt_null(c);
	for (size_t j = 0; j < slen; j++) {
		g1_null(g[j]);
	}
	for (size_t j = 0; j < fmax; j++) {
		g1_null(h[j]);
	}

	RLC_TRY {
		bn_new(t);
		bn_new(n);
		g1_new(d);
		gt_new(c);

		bn_zero(t);
		pc_get_ord(n);
		for (size_t j = 0; j < slen; j++) {
			g1_new(g[j]);
			bn_add(t, t, mu[j]);
			bn_mod(t, t, n);
		}
		for (size_t j = 0; j < fmax; j++) {
			g1_new(h[j]);
		}

		/* Torsion added to the signature would not change the pairing. */
		if (bn_cmp(m, t) == RLC_EQ && g1_is_valid(sig)) {
			for (size_t i = 0; i < slen; i++) {
				mklhs_map(d, str, 1, data, id[i]);
				for (size_t j = 0; j < flen[i]; j++) {
					mklhs_map(h[j], str, 2, id[i], tag[j]);
					g1_add(h[j], h[j], d);
				}
				g1_norm_sim(h, h, flen[i]);
				g1_mul_sim_dig(g[i], h, f[i], flen[i]);
				g1_mul_gen(h[0], mu[i]);
				g1_add(g[i], g[i], h[0]);
			}
			g1_norm_sim(g, g, slen);

			/* Check that prod e(g_i, pk_i) * e(-sig, G_2) = 1. */
			g1_neg(d, sig);
			pc_map_sim_gen(c, g, pk, slen, d);
			result = gt_is_unity(c);
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(n);
		g1_free(d);
		gt_free(c);
		for (size_t j = 0; j < slen; j++) {
			g1_free(g[j]);
		}
		for (size_t j = 0; j < fmax; j++) {
			g1_free(h[j]);
		}
		RLC_FREE(g);
		RLC_FREE(h);
		RLC_FREE(str);
	}
	return result;
}

int cp_mklhs_off(g1_t h[], bn_t ft[], const char *id[], const char *tag[],
		const dig_t *f[], const size_t flen[], size_t slen) {
	bn_t n;
	size_t imax = 0, lmax = 0, fmax = 0;
	int result = RLC_OK;
	for (size_t i = 0; i < slen; i++) {
		fmax = RLC_MAX(fmax, flen[i]);
		imax = RLC_MAX(imax, strlen(id[i]));
		for (size_t j = 0; j < flen[i]; j++) {
			lmax = RLC_MAX(lmax, strlen(tag[j]));
		}
	}
	g1_t *_h = RLC_ALLOCA(g1_t, fmax);
	uint8_t *str = RLC_ALLOCA(uint8_t, imax + lmax + 2);

	if (_h == NULL || str == NULL) {
		RLC_FREE(_h);
		RLC_FREE(str);
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	for (size_t j = 0; j < fmax; j++) {
		g1_null(_h[j]);
	}

	RLC_TRY {
		bn_new(n);
		for (size_t j = 0; j < fmax; j++) {
			g1_new(_h[j]);
		}

		pc_get_ord(n);
		for (size_t i = 0; i < slen; i++) {
			bn_zero(ft[i]);
			for (size_t j = 0; j < flen[i]; j++) {
				mklhs_map(_h[j], str, 2, id[i], tag[j]);
				bn_add_dig(ft[i], ft[i], f[i][j]);
			}
			/* Reduce, as the sum of coefficients can exceed a digit. */
			bn_mod(ft[i], ft[i], n);
			g1_mul_sim_dig(h[i], _h, f[i], flen[i]);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		for (size_t j = 0; j < fmax; j++) {
			g1_free(_h[j]);
		}
		RLC_FREE(_h);
		RLC_FREE(str);
	}
	return result;
}

int cp_mklhs_onv(const g1_t sig, const bn_t m, const bn_t mu[],
		const char *data, const char *id[], const g1_t h[], const bn_t ft[],
		const g2_t pk[], size_t slen) {
	bn_t t, n;
	g1_t d, g1, *g = RLC_ALLOCA(g1_t, slen);
	gt_t c;
	int result = 0;
	size_t imax = 0;
	for (size_t i = 0; i < slen; i++) {
		imax = RLC_MAX(imax, strlen(id[i]));
	}
	uint8_t *str = RLC_ALLOCA(uint8_t, strlen(data) + imax + 2);

	if (g == NULL || str == NULL) {
		RLC_FREE(g);
		RLC_FREE(str);
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	bn_null(t);
	bn_null(n);
	g1_null(d);
	g1_null(g1);
	gt_null(c);
	for (size_t j = 0; j < slen; j++) {
		g1_null(g[j]);
	}

	RLC_TRY {
		bn_new(t);
		bn_new(n);
		g1_new(d);
		g1_new(g1);
		gt_new(c);

		bn_zero(t);
		pc_get_ord(n);
		for (size_t j = 0; j < slen; j++) {
			g1_new(g[j]);
			bn_add(t, t, mu[j]);
			bn_mod(t, t, n);
		}

		/* Torsion added to the signature would not change the pairing. */
		if (bn_cmp(m, t) == RLC_EQ && g1_is_valid(sig)) {
			for (size_t i = 0; i < slen; i++) {
				mklhs_map(d, str, 1, data, id[i]);
				g1_mul(g[i], d, ft[i]);
				g1_add(g[i], g[i], h[i]);
				g1_mul_gen(g1, mu[i]);
				g1_add(g[i], g[i], g1);
			}
			g1_norm_sim(g, g, slen);

			/* Check that prod e(g_i, pk_i) * e(-sig, G_2) = 1. */
			g1_neg(d, sig);
			pc_map_sim_gen(c, g, pk, slen, d);
			result = gt_is_unity(c);
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(n);
		g1_free(d);
		g1_free(g1);
		gt_free(c);
		for (size_t j = 0; j < slen; j++) {
			g1_free(g[j]);
		}
		RLC_FREE(g);
		RLC_FREE(str);
	}
	return result;
}
