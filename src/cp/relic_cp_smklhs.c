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
/* Public definitions                                                         */
/*============================================================================*/

int cp_smklhs_set(ec_t u, g1_t t1, g1_t p1, g2_t t2, g2_t p2) {
	bn_t n, k;
	int result = RLC_OK;

	bn_null(k);
	bn_null(n);

	RLC_TRY {
		bn_new(k);
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(k, n);
		g1_mul_gen(t1, k);
		g2_mul_gen(t2, k);
		bn_rand_mod(k, n);
		g1_mul_gen(p1, k);
		g2_mul_gen(p2, k);
		ec_rand(u);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(k);
		bn_free(n);
	}
	return result;
}

int cp_smklhs_gen(bn_t sk1, bn_t sk2, g1_t pk1, g2_t pk2, g1_t pk3) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(sk1, n);
		bn_rand_mod(sk2, n);
		g1_mul_gen(pk1, sk1);
		g2_mul_gen(pk2, sk1);
		g1_mul_gen(pk3, sk2);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_smklhs_sig(g1_t s, const bn_t m, const char *data, const char *id,
		const char *tag, const g1_t t1, const g1_t p1, const bn_t sk1,
		const bn_t sk2, const g1_t pk1) {
	bn_t k, n;
	g1_t a;
	int result = RLC_OK;
	uint8_t *str = RLC_ALLOCA(uint8_t, strlen(id) + strlen(data) + strlen(tag));

	bn_null(k);
	bn_null(n);
	g1_null(a);

	RLC_TRY {
		bn_new(k);
		bn_new(n);
		g1_new(a);
		if (str == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		pc_get_ord(n);
		g1_mul(a, t1, m);

		memcpy(str, data, strlen(data));
		memcpy(str + strlen(data), id, strlen(id));
		memcpy(str + strlen(data) + strlen(id), tag, strlen(tag));
		g1_map(s, str, strlen(data) + strlen(id) + strlen(tag));
		g1_add(s, s, a);
		g1_norm(s, s);
		g1_mul_sec(s, s, sk1);

		bn_mul(k, m, sk2);
		bn_mod(k, k, n);
		g1_mul(a, p1, k);
		g1_add(s, s, a);
		g1_norm(s, s);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		RLC_FREE(str);
		bn_free(k);
		bn_free(n);
		g1_free(a);
	}
	return result;
}

int cp_smklhs_ver(const g1_t sig, const bn_t m, const bn_t y1, const ec_t ps1,
		const ec_t *ls1, const ec_t *rs1, const bn_t y2, const ec_t ps2,
		const ec_t *ls2, const ec_t *rs2, const ec_t u, const char *data,
		const char *id[], const char *tag[], const dig_t *f[],
		const size_t flen[], const g1_t pk1[], const g2_t pk2[],
		const g1_t pk3[], const g2_t t2, const g2_t p2, size_t slen) {
	bn_t t, n;
	g1_t *g1 = RLC_ALLOCA(g1_t, slen + 2);
	g2_t *g2 = RLC_ALLOCA(g2_t, slen + 2);
	gt_t c, e;
	int imax = 0, lmax = 0, fmax = 0, ver1 = 0, ver2 = 0, ver3 = 0;
	for (size_t i = 0; i < slen; i++) {
		fmax = RLC_MAX(fmax, flen[i]);
		imax = RLC_MAX(imax, strlen(id[i]));
		for (int j = 0; j < flen[i]; j++) {
			lmax = RLC_MAX(lmax, strlen(tag[j]));
		}
	}
	g1_t *h = RLC_ALLOCA(g1_t, fmax);
	uint8_t *str = RLC_ALLOCA(uint8_t, strlen(data) + imax + lmax);

	bn_null(t);
	bn_null(n);
	gt_null(c);
	gt_null(e);

	RLC_TRY {
		bn_new(t);
		bn_new(n);
		gt_new(c);
		gt_new(e);
		if (g1 == NULL || g2 == NULL || h == NULL || str == NULL) {
			RLC_FREE(g1);
			RLC_FREE(g2);
			RLC_FREE(h);
			RLC_THROW(ERR_NO_MEMORY);
		}

		bn_zero(t);
		pc_get_ord(n);
		for (size_t j = 0; j < slen + 2; j++) {
			g1_null(g1[j]);
			g1_new(g1[j]);
			g2_null(g2[j]);
			g2_new(g2[j]);
		}
		for (size_t j = 0; j < fmax; j++) {
			g1_null(h[j]);
			g1_new(h[j]);
		}

		if (slen == 1) {
			ver1 = ver2 = 1;
		} else {
			ver1 = cp_ipa_ver(y1, ps1, ls1, rs1, pk1, u, slen);
			ver2 = cp_ipa_ver(y2, ps2, ls2, rs2, pk3, u, slen);
		}

		for (int i = 0; i < slen; i++) {
			memcpy(str, data, strlen(data));
			memcpy(str + strlen(data), id[i], strlen(id[i]));
			for (int j = 0; j < flen[i]; j++) {
				memcpy(str + strlen(data) + strlen(id[i]), tag[j], strlen(tag[j]));
				g1_map(h[j], str, strlen(data) + strlen(id[i]) + strlen(tag[j]));
			}
			g1_norm_sim(h, h, slen);
			g1_mul_sim_dig(g1[i], h, f[i], flen[i]);
			g2_copy(g2[i], pk2[i]);
		}
		g1_norm_sim(g1, g1, slen);
		if (slen == 1) {
			g1_mul(g1[slen], pk1[0], m);
			g1_mul(g1[slen + 1], pk3[0], m);
		} else {
			g1_mul(g1[slen], u, m);
			g1_sub(g1[slen + 1], ps2, g1[slen]);
			g1_sub(g1[slen], ps1, g1[slen]);
			g1_norm(g1[slen], g1[slen]);
			g1_norm(g1[slen + 1], g1[slen + 1]);
		}
		g2_copy(g2[slen], t2);
		g2_copy(g2[slen + 1], p2);
		
		pc_map_sim(c, g1, g2, slen + 2);
		g2_get_gen(g2[0]);
		pc_map(e, sig, g2[0]);
		if (gt_cmp(c, e) == RLC_EQ) {
			ver3 = 1;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(n);
		gt_free(c);
		gt_free(e);
		for (int j = 0; j < slen + 2; j++) {
			g1_free(g1[j]);
			g2_free(g2[j]);
		}
		for (int j = 0; j < fmax; j++) {
			g1_free(h[j]);
		}
		RLC_FREE(g1);
		RLC_FREE(g2);
		RLC_FREE(h);
		RLC_FREE(str);
	}
	return (ver1 && ver2 && ver3);
}
