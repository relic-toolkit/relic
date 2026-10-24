/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
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
 * Implementation of the Boneh-Lynn-Schacham short signature protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Aggregates signatures over the same message as in the Boneh-Drijvers-Neven
 * scheme, with coefficients t_i = H(q_i || H(q_1 || ... || q_n)) that depend
 * on the whole set of keys, so that rogue keys cannot cancel honest ones.
 *
 * @param[out] sig			- the aggregate signature, or NULL.
 * @param[out] a			- the aggregate public key.
 * @param[in] s				- the signatures to aggregate, or NULL.
 * @param[in] q				- the public keys to aggregate.
 * @param[in] n				- the number of public keys.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int bls_agg(g1_t sig, g2_t a, const g1_t s[], const g2_t q[],
		size_t n) {
	const size_t len = (n > 0 ? g2_size_bin(q[0], 1) : 0);
	const size_t k = RLC_MIN(RLC_MD_LEN, RLC_CEIL(pc_param_level(), 8));
	bn_t *t;
	uint8_t d[RLC_MD_LEN], h[RLC_MD_LEN], *buf;
	int result = RLC_OK;

	if (n == 0) {
		return RLC_ERR;
	}
	/* Invalid keys would make the coefficients and the aggregate useless. */
	for (size_t i = 0; i < n; i++) {
		if (!g2_is_valid(q[i])) {
			return RLC_ERR;
		}
	}

	t = RLC_ALLOCA(bn_t, n);
	buf = RLC_ALLOCA(uint8_t, RLC_MAX(n * len, len + RLC_MD_LEN));
	if (t == NULL || buf == NULL) {
		RLC_FREE(t);
		RLC_FREE(buf);
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	for (size_t i = 0; i < n; i++) {
		bn_null(t[i]);
	}

	RLC_TRY {
		for (size_t i = 0; i < n; i++) {
			bn_new(t[i]);
		}

		/* Valid keys have compressed encodings of the same length. */
		for (size_t i = 0; i < n; i++) {
			g2_write_bin(buf + i * len, len, q[i], 1);
		}
		md_map(d, buf, n * len);
		for (size_t i = 0; i < n; i++) {
			g2_write_bin(buf, len, q[i], 1);
			memcpy(buf + len, d, RLC_MD_LEN);
			md_map(h, buf, len + RLC_MD_LEN);
			bn_read_bin(t[i], h, k);
		}

		g2_mul_sim_lot(a, q, (const bn_t *)t, n);
		if (sig != NULL) {
			g1_mul_sim_lot(sig, s, (const bn_t *)t, n);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		for (size_t i = 0; i < n; i++) {
			bn_free(t[i]);
		}
		RLC_FREE(t);
		RLC_FREE(buf);
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_bls_gen(bn_t d, g2_t q) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(d, n);
		g2_mul_gen(q, d);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_bls_sig(g1_t s, const uint8_t *msg, size_t len, const bn_t d) {
	g1_t p;
	int result = RLC_OK;

	g1_null(p);

	RLC_TRY {
		g1_new(p);
		g1_map(p, msg, len);
		g1_mul_sec(s, p, d);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		g1_free(p);
	}
	return result;
}

int cp_bls_ver(const g1_t s, const uint8_t *msg, size_t len, const g2_t q) {
	g1_t p[2];
	g2_t r[1];
	gt_t e;
	int result = 0;

	g1_null(p[0]);
	g1_null(p[1]);
	g2_null(r[0]);
	gt_null(e);

	RLC_TRY {
		g1_new(p[0]);
		g1_new(p[1]);
		g2_new(r[0]);
		gt_new(e);

		g1_map(p[0], msg, len);
		g1_neg(p[1], s);
		g2_copy(r[0], q);

		/* Check that e(H(m), q) * e(-s, g) = 1. */
		pc_map_sim_gen(e, p, r, 1, p[1]);
		/* Torsion added to the signature would not change the pairing. */
		if (gt_is_unity(e) && g1_is_valid(s) && g2_is_valid(q)) {
			result = 1;
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g1_free(p[0]);
		g1_free(p[1]);
		g2_free(r[0]);
		gt_free(e);
	}
	return result;
}

int cp_bls_agg_sig(g1_t sig, g2_t a, const g1_t s[], const g2_t q[],
		size_t n) {
	return bls_agg(sig, a, s, q, n);
}

int cp_bls_agg_key(g2_t a, const g2_t q[], size_t n) {
	return bls_agg(NULL, a, NULL, q, n);
}

int cp_bls_agg_ver(const g1_t s, const uint8_t **m, const size_t *l,
		size_t size, const g2_t q[]) {
	g1_t *p = RLC_ALLOCA(g1_t, size + 1);
	gt_t e;
	int result = 0;

	if (p == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	gt_null(e);
	for (size_t i = 0; i < size + 1; i++) {
		g1_null(p[i]);
	}

	RLC_TRY {
		g1_new(p[0]);
		for (size_t i = 0; i < size; i++) {
			g1_new(p[i + 1]);
			g1_map(p[i + 1], m[i], l[i]);
		}
		gt_new(e);

		g1_neg(p[0], s);

		/* Check that prod e(H(m_i), q_i) * e(-s, g) = 1. */
		pc_map_sim_gen(e, p + 1, q, size, p[0]);
		if (gt_is_unity(e) && g1_is_valid(s)) {
			result = 1;
		}
		for (size_t i = 0; i < size; i++) {
			result = result & g2_is_valid(q[i]);
			/* Messages must be distinct, or rogue keys forge aggregates. */
			for (size_t j = 0; j < i; j++) {
				if (l[i] == l[j] && memcmp(m[i], m[j], l[i]) == 0) {
					result = 0;
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (size_t i = 0; i < size + 1; i++) {
			g1_free(p[i]);
		}
		gt_free(e);
		RLC_FREE(p);
	}
	return result;
}