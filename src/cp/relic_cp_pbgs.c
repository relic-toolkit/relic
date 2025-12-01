/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of the password-based group signature protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_pbgs_gen(bn_t alpha, g1_t c, g1_t pk1, g2_t pk2) {
	bn_t r, s, n;
	int result = RLC_OK;

	bn_null(r);
	bn_null(s);
	bn_null(n);

	RLC_TRY {
		bn_new(r);
		bn_new(s);
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(r, n);
		bn_rand_mod(s, n);

		/* pk1 = g1^s, pk2 = g2^r, c = g1^(sr\alpha). */
		g1_mul_gen(pk1, s);
		g2_mul_gen(pk2, r);
		bn_mul(r, r, s);
		bn_mul(r, r, alpha);
		bn_mod(r, r, n);
		g1_mul_gen(c, r);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(r);
		bn_free(s);
	}
	return result;
}

int cp_pbgs_gen_prv(g1_t ci, g1_t w, bn_t d, const char *id,
		const uint8_t *pwd, size_t len, const bn_t alpha, const g1_t pk1) {
	bn_t n, t;
	uint8_t h[RLC_MD_LEN];
	uint8_t *buf = RLC_ALLOCA(uint8_t, strlen(id) + len);
	int result = RLC_OK;

	bn_null(n);
	bn_null(t);

	if (buf == NULL) {
		RLC_FREE(buf); 
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(t);

		memcpy(buf, id, strlen(id));
		memcpy(buf + strlen(id), pwd, len);

		md_map(h, buf, strlen(id) + len);
		g1_map(w, h, RLC_MD_LEN);
		pc_get_ord(n);
		bn_read_bin(d, h, RLC_MD_LEN);
		bn_mod(d, d, n);
		bn_mod_inv(t, d, n);
		bn_mul(t, t, alpha);
		bn_mod(t, t, n);

		g1_sub(ci, pk1, w);
		g1_norm(ci, ci);
		g1_mul(ci, ci, t);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(r);
		bn_free(s);
		RLC_FREE(buf);
	}
	return result;
}

int cp_pbgs_set(bn_t m, gt_t t, const g2_t pk2) {
	g1_t g1;
	bn_t n;
	int result = RLC_OK;

	g1_null(g1);
	bn_null(n);

	RLC_TRY {
		g1_new(g1);
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(m, n);
		g1_mul_gen(g1, m);;
		pc_map(t, g1, pk2);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		g1_free(g1);
		bn_free(n);
	}
	return result;
}

int cp_pbgs_ask(g1_t r, g1_t s, bn_t x, bn_t y, gt_t k, const uint8_t *msg,
		size_t len, const g1_t w, const g2_t pk2, const gt_t t) {
	bn_t n;
	size_t l2 = g2_size_bin(pk2, 0), lt = gt_size_bin(k, 0);
	uint8_t *buf = NULL, h[RLC_MD_LEN];
	int result = RLC_OK;

	bn_null(n);
	gt_null(k);

	RLC_TRY {
		bn_new(n);
		gt_new(k);
		buf = RLC_ALLOCA(uint8_t, len + l2 + lt);
		if (buf == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		pc_get_ord(n);
		bn_rand_mod(x, n);
		gt_exp(k, t, x);
		/* y = H(msg, pk2, k). */
		memcpy(buf, msg, len);
		g2_write_bin(buf + len, l2, pk2, 0);
		gt_write_bin(buf + len + l2, lt, k, 0);
		md_map(h, buf, len + l2 + lt);
		bn_read_bin(y, h, RLC_MD_LEN);
		bn_mod(y, y, n);

		g1_mul_gen(s, x);
		/* Overwrite x with a for OPRF protocol. */
		g1_mul(r, w, y);
		do {
			bn_rand_mod(x, n);
		} while (bn_is_zero(x));
		g1_mul(r, r, x);
		g1_mul(s, s, x);
		bn_mod_inv(x, x, n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		gt_free(k);
		RLC_FREE(buf);
	}
	return result;
}

int cp_pbgs_ans(g1_t b, const g1_t r, const g1_t s, const bn_t m,
		const bn_t alpha) {
	int result = RLC_OK;

	/* This should be an OPRF answer, but it's faster to combine the two. */
	g1_mul_sim(b, r, alpha, s, m);

	return result;
}

int cp_pbgs_sig(g1_t z, const bn_t x, const g1_t b, const bn_t y,
		const bn_t d, const g1_t ci) {
	g1_t f;
	bn_t t, n;
	int result = RLC_OK;

	bn_null(t);
	bn_null(n);
	g1_null(f);

	RLC_TRY {
		bn_new(t);
		bn_new(n);
		g1_new(f);

		pc_get_ord(n);
		bn_mul(t, y, d);
		bn_mod(t, t, n);

		g1_mul(f, b, x);
		g1_mul(z, ci, t);
		g1_add(z, z, f);
		g1_norm(z, z);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(n);
		g1_free(f);
	}
	return result;
}

int cp_pbgs_ver(const g1_t z, const uint8_t *msg, size_t len, const g1_t c,
		const g2_t pk2, const gt_t k) {
	bn_t y, n;
	g1_t g1[2];
	g2_t g2[2];
	gt_t e;
	size_t l2 = g2_size_bin(pk2, 0), lt = gt_size_bin(k, 0);
	uint8_t *buf = NULL, h[RLC_MD_LEN];
	int result = 1;

	bn_null(y);
	bn_null(n);
	gt_null(e);

	RLC_TRY {
		bn_new(y);
		bn_new(n);
		gt_new(e);
		for (size_t i = 0; i < 2; i++) {
			g1_null(g1[i]);
			g2_null(g2[i]);
			g1_new(g1[i]);
			g2_new(g2[i]);
		}
		buf = RLC_ALLOCA(uint8_t, len + l2 + lt);
		if (buf == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		/* y = H(msg, k). */
		pc_get_ord(n);
		memcpy(buf, msg, len);
		g2_write_bin(buf + len, l2, pk2, 0);
		gt_write_bin(buf + len + l2, lt, k, 0);
		md_map(h, buf, len + l2 + lt);
		bn_read_bin(y, h, RLC_MD_LEN);
		bn_mod(y, y, n);

		g1_copy(g1[0], z);
		g2_copy(g2[0], pk2);
		g1_mul(g1[1], c, y);
		g2_get_gen(g2[1]);
		pc_map_sim(e, g1, g2, 2);

		result &= (gt_cmp(e, k) == RLC_EQ);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(y);
		bn_free(n);
		gt_free(e);
		for (size_t i = 0; i < 2; i++) {
			g1_free(g1[i]);
			g2_free(g2[i]);
		}
		RLC_FREE(buf);
	}
	return result;
}