/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
/* Public definitions                                                         */
/*============================================================================*/

int cp_mklhs_gen(bn_t sk, g2_t pk) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	TRY {
		bn_new(n);

		g2_get_ord(n);
		bn_rand_mod(sk, n);
		g2_mul_gen(pk, sk);
	}
	CATCH_ANY {
		result = RLC_ERR;
	}
	FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_mklhs_sig(g1_t s, bn_t m, char *data, int dlen, char *label, int llen,
		bn_t sk) {
	bn_t n;
	g1_t a;
	int result = RLC_OK;

	bn_null(n);
	g1_new(a);

	TRY {
		bn_new(n);
		g1_new(a);

		g1_get_ord(n);
		g1_mul_gen(a, m);

		g1_map(s, (uint8_t *)data, dlen);
		g1_add(s, s, a);
		g1_map(a, (uint8_t *)label, llen);
		g1_add(s, s, a);
		g1_norm(s, s);
		g1_mul_key(s, s, sk);
	}
	CATCH_ANY {
		result = RLC_ERR;
	}
	FINALLY {
		bn_free(n);
		g1_free(a);
	}
	return result;
}

int cp_mklhs_fun(bn_t mu, bn_t m[], dig_t f[], int len) {
	bn_t n, t;
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);

	TRY {
		bn_new(n);
		bn_new(t);

		g1_get_ord(n);
		bn_zero(mu);
		for (int i = 0; i < len; i++) {
			bn_mul_dig(t, m[i], f[i]);
			bn_add(mu, mu, t);
			bn_mod(mu, mu, n);
		}
	}
	CATCH_ANY {
		result = RLC_ERR;
	}
	FINALLY {
		bn_free(n);
		bn_free(t);
	}
	return result;
}

int cp_mklhs_evl(g1_t sig, g1_t s[], dig_t f[], int len) {
	int result = RLC_OK;

	g1_mul_sim_dig(sig, s, f, len);

	return result;
}

int cp_mklhs_ver(g1_t sig, bn_t m, bn_t mu[], char *data, int dlen,
		char *label[], int llen[], dig_t f[][RLC_TERMS], int flen[], g2_t pk[],
		int slen) {
	bn_t t, n;
	g1_t d, *g = RLC_ALLOCA(g1_t, slen);
	g2_t g2;
	gt_t c, e;
	int fmax = 0, ver1 = 0, ver2 = 0;
	for (int i = 0; i < slen; i++) {
		fmax = RLC_MAX(fmax, flen[i]);
	}
	g1_t *h = RLC_ALLOCA(g1_t, fmax);

	bn_null(t);
	bn_null(n);
	g1_null(d);
	g2_null(g2);
	gt_null(c);
	gt_null(e);

	TRY {
		bn_new(t);
		bn_new(n);
		g1_new(d);
		g2_new(g2);
		gt_new(c);
		gt_new(e);
		if (g == NULL || h == NULL) {
			RLC_FREE(g);
			RLC_FREE(h);
			THROW(ERR_NO_MEMORY);
		}

		bn_zero(t);
		g1_get_ord(n);
		for (int j = 0; j < slen; j++) {
			g1_null(g[j]);
			g1_new(g[j]);
			bn_add(t, t, mu[j]);
			bn_mod(t, t, n);
		}
		for (int j = 0; j < fmax; j++) {
			g1_null(h[j]);
			g1_new(h[j]);
		}

		if (bn_cmp(m, t) == RLC_EQ) {
			ver1 = 1;
		}

		g1_map(d, (uint8_t *)data, dlen);
		for (int i = 0; i < slen; i++) {
			for (int j = 0; j < flen[i]; j++) {
				g1_map(h[j], (uint8_t *)label[j], llen[j]);
				g1_add(h[j], h[j], d);
			}
			g1_norm_sim(h, h, slen);
			g1_mul_sim_dig(g[i], h, f[i], flen[i]);
			g1_mul_gen(h[0], mu[i]);
			g1_add(g[i], g[i], h[0]);
		}
		g1_norm_sim(g, g, slen);

		g2_get_gen(g2);
		pc_map(e, sig, g2);
		pc_map_sim(c, g, pk, slen);
		if (gt_cmp(c, e) == RLC_EQ) {
			ver2 = 1;
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_new(t);
		bn_new(n);
		g1_free(d);
		g2_free(g2);
		gt_free(c);
		gt_free(e);
		for (int j = 0; j < slen; j++) {
			g1_free(g[j]);
		}
		for (int j = 0; j < fmax; j++) {
			g1_free(h[j]);
		}
		RLC_FREE(g);
		RLC_FREE(h);
	}
	return (ver1 && ver2);
}

int cp_mklhs_off(g1_t h[], dig_t ft[], char *label[], int llen[], dig_t f[][RLC_TERMS],
		int flen[], int slen) {
	int fmax = 0, result = RLC_OK;;
	for (int i = 0; i < slen; i++) {
		fmax = RLC_MAX(fmax, flen[i]);
	}
	g1_t *_h = RLC_ALLOCA(g1_t, fmax);

	TRY {
		if (_h == NULL) {
			RLC_FREE(_h);
			THROW(ERR_NO_MEMORY);
		}

		for (int j = 0; j < fmax; j++) {
			g1_null(_h[j]);
			g1_new(_h[j]);
		}

		for (int i = 0; i < slen; i++) {
			ft[i] = 0;
			for (int j = 0; j < flen[i]; j++) {
				g1_map(_h[j], (uint8_t *)label[j], llen[j]);
				ft[i] += f[i][j];
			}
			g1_mul_sim_dig(h[i], _h, f[i], flen[i]);
		}
	}
	CATCH_ANY {
		result = RLC_ERR;
	}
	FINALLY {
		for (int j = 0; j < fmax; j++) {
			g1_free(_h[j]);
		}
		RLC_FREE(_h);
	}
	return result;
}

int cp_mklhs_onv(g1_t sig, bn_t m, bn_t mu[], char *data, int dlen,
		g1_t h[], dig_t ft[], g2_t pk[], int slen) {
	bn_t t, n;
	g1_t d, g1, *g = RLC_ALLOCA(g1_t, slen);
	g2_t g2;
	gt_t c, e;
	int ver1 = 0, ver2 = 0;

	bn_null(t);
	bn_null(n);
	g1_null(d);
	g1_null(g1);
	g2_null(g2);
	gt_null(c);
	gt_null(e);

	TRY {
		bn_new(t);
		bn_new(n);
		g1_new(d);
		g1_new(g1);
		g2_new(g2);
		gt_new(c);
		gt_new(e);
		if (g == NULL) {
			RLC_FREE(g);
			THROW(ERR_NO_MEMORY);
		}

		bn_zero(t);
		g1_get_ord(n);
		for (int j = 0; j < slen; j++) {
			g1_null(g[j]);
			g1_new(g[j]);
			bn_add(t, t, mu[j]);
			bn_mod(t, t, n);
		}

		if (bn_cmp(m, t) == RLC_EQ) {
			ver1 = 1;
		}

		g1_map(d, (uint8_t *)data, dlen);
		for (int i = 0; i < slen; i++) {
			g1_mul_dig(g[i], d, ft[i]);
			g1_add(g[i], g[i], h[i]);
			g1_mul_gen(g1, mu[i]);
			g1_add(g[i], g[i], g1);
		}
		g1_norm_sim(g, g, slen);

		g2_get_gen(g2);
		pc_map(e, sig, g2);
		pc_map_sim(c, g, pk, slen);
		if (gt_cmp(c, e) == RLC_EQ) {
			ver2 = 1;
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_new(t);
		bn_new(n);
		g1_free(d);
		g1_free(g1);
		g2_free(g2);
		gt_free(c);
		gt_free(e);
		for (int j = 0; j < slen; j++) {
			g1_free(g[j]);
		}
		RLC_FREE(g);
	}
	return (ver1 && ver2);
}
