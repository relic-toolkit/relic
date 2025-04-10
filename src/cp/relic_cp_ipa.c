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
 * Implementation of inner product arguments.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_ipa_prv(bn_t y, ec_t p, ec_t *ls, ec_t *rs, const ec_t *g, const bn_t *a,
		const ec_t u, size_t n) {
	uint8_t buf[2 * RLC_FP_BYTES + 2], hash[RLC_MD_LEN];
	int result = RLC_OK;
	size_t m = n, k = 0;
	bn_t *b, *x, *c, t, r, c_l, c_r;
	ec_t q, s, *h;

	do {
		k++;
	} while (m >>= 1);
	k = ( n == 1 ? 0 : k);
	b = RLC_ALLOCA(bn_t, 1 << k);
	x = RLC_ALLOCA(bn_t, 1 << k);
	c = RLC_ALLOCA(bn_t, 1 << k);
	h = RLC_ALLOCA(ec_t, 1 << k);

	ec_null(q);
	ec_null(s);
	bn_null(r);
	bn_null(t);
	bn_null(c_l);
	bn_null(c_r);

	if (n == 0 || b == NULL || c == NULL || x == NULL || h == NULL) {
		RLC_FREE(b);
		RLC_FREE(c);
		RLC_FREE(x);
		RLC_FREE(h);
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}
	
	RLC_TRY {
		ec_new(q);
		ec_new(s);
		bn_new(r);
		bn_new(t);
		bn_new(c_l);
		bn_new(c_r);

		bn_zero(c_l);
		for (size_t i = 0; i < (1 << k); i++) {
			bn_null(b[i]);
			bn_null(c[i]);
			bn_null(x[i]);
			ec_null(h[i]);
			bn_new(b[i]);
			bn_new(c[i]);
			bn_new(x[i]);
			ec_new(h[i]);
			bn_set_dig(b[i], 1);
			if (i < n) {
				ec_copy(h[i], g[i]);
				bn_copy(c[i], a[i]);
			} else {
				ec_set_infty(h[i]);
				bn_zero(c[i]);
			}
			bn_add(c_l, c_l, c[i]);
		}

		ec_curve_get_ord(r);
		bn_mod(c_l, c_l, r);
		ec_mul_sim_lot(p, g, a, n);
		ec_mul(q, u, c_l);
		ec_add(p, p, q);
		ec_norm(p, p);

		m = (1 << k);
		ec_copy(q, p);
		for (size_t i = 0; i < k; i++) {
			m = m >> 1;
			bn_zero(c_l);
			bn_zero(c_r);
			for (size_t j = 0; j < m; j++) {
				bn_mul(t, c[j], b[m + j]);
				bn_add(c_l, c_l, t);
				bn_mul(t, c[m + j], b[j]);
				bn_add(c_r, c_r, t);
			}
			bn_mod(c_l, c_l, r);
			bn_mod(c_r, c_r, r);
			ec_mul_sim_lot(ls[i], h + m, c, m);
			ec_mul(s, u, c_l);
			ec_add(ls[i], ls[i], s);
			ec_norm(ls[i], ls[i]);
			ec_mul_sim_lot(rs[i], h, c + m, m);
			ec_mul(s, u, c_r);
			ec_add(rs[i], rs[i], s);
			ec_norm(rs[i], rs[i]);

			ec_write_bin(buf, RLC_FP_BYTES + 1, ls[i], 1);
			ec_write_bin(buf + RLC_FP_BYTES + 1, RLC_FP_BYTES + 1, rs[i], 1);
			md_map(hash, buf, sizeof(buf));
			bn_read_bin(x[i], hash, RLC_MD_LEN);

			bn_mod_inv(t, x[i], r);
			for (size_t j = 0; j < m; j++) {
				ec_mul_sim(h[j], h[j], t, h[m + j], x[i]);
				bn_mul(c[j], c[j], x[i]);
				bn_mul(c[m + j], c[m + j], t);
				bn_add(c[j], c[j], c[m + j]);
				bn_mod(c[j], c[j], r);
				bn_mul(b[j], b[j], t);
				bn_mul(b[m + j], b[m + j], x[i]);
				bn_add(b[j], b[j], b[m + j]);
				bn_mod(b[j], b[j], r);
			}
			bn_sqr(x[i], x[i]);
			bn_mod(x[i], x[i], r);
			bn_sqr(t, t);
			bn_mod(t, t, r);
			ec_mul_sim(s, ls[i], x[i], rs[i], t);
			ec_add(q, q, s);
		}
		ec_norm(q, q);
		bn_copy(y, c[0]);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		ec_free(q);
		ec_free(s);
		bn_free(r);
		bn_free(t);
		bn_free(c_l);
		bn_free(c_r);
		for (size_t i = 0; i < (1 << k); i++) {
			bn_free(b[i]);
			bn_free(c[i]);
			bn_free(x[i]);
			ec_free(h[i]);
		}
		RLC_FREE(b);
		RLC_FREE(c);
		RLC_FREE(x);
		RLC_FREE(h);
	}
	return result;
}

int cp_ipa_ver(const bn_t y, const ec_t p, const ec_t *ls, const ec_t *rs,
		const ec_t *g, const ec_t u, size_t n) {
	uint8_t buf[2 * RLC_FP_BYTES + 2], hash[RLC_MD_LEN];
	int result = 1;
	size_t m = n, k = 0;
	bn_t t, r, x, *b;
	ec_t q, s, *h;

	do {
		k++;
	} while (m >>= 1);
	k = (n == 1 ? 0 : k);
	b = RLC_ALLOCA(bn_t, 1 << k);
	h = RLC_ALLOCA(ec_t, 1 << k);

	ec_null(q);
	ec_null(s);
	bn_null(r);
	bn_null(t);
	bn_null(x);

	if (b == NULL || h == NULL) {
		RLC_FREE(b);
		RLC_FREE(h);
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	RLC_TRY {
		ec_new(q);
		ec_new(s);
		bn_new(r);
		bn_new(t);
		bn_new(x);
		for (size_t i = 0; i < (1 << k); i++) {
			bn_null(b[i]);
			ec_null(h[i]);
			bn_new(b[i]);
			ec_new(h[i]);
			bn_set_dig(b[i], 1);
			if (i < n) {
				ec_copy(h[i], g[i]);
			} else {
				ec_set_infty(h[i]);
			}
		}

		ec_curve_get_ord(r);

		m = (1 << k);
		ec_copy(q, p);
		for (size_t i = 0; i < k; i++) {
			m = m >> 1;
			ec_write_bin(buf, RLC_FP_BYTES + 1, ls[i], 1);
			ec_write_bin(buf + RLC_FP_BYTES + 1, RLC_FP_BYTES + 1, rs[i], 1);
			md_map(hash, buf, sizeof(buf));
			bn_read_bin(x, hash, RLC_MD_LEN);
			bn_mod_inv(t, x, r);
			for (size_t j = 0; j < m; j++) {
				ec_mul_sim(h[j], h[j], t, h[m + j], x);
				bn_mul(b[j], b[j], t);
				bn_mul(b[m + j], b[m + j], x);
				bn_add(b[j], b[j], b[m + j]);
				bn_mod(b[j], b[j], r);
			}
			bn_sqr(x, x);
			bn_mod(x, x, r);
			bn_sqr(t, t);
			bn_mod(t, t, r);
			ec_mul_sim(s, ls[i], x, rs[i], t);
			ec_add(q, q, s);
		}
		ec_norm(q, q);

		bn_mul(t, y, b[0]);
		bn_mod(t, t, r);
		ec_mul_sim(s, h[0], y, u, t);
		result = (ec_cmp(q, s) == RLC_EQ);
	} RLC_CATCH_ANY {
		result = 0;
	} RLC_FINALLY {
		ec_free(q);
		ec_free(s);
		bn_free(r);
		bn_free(t);
		bn_free(x);
		for (size_t i = 0; i < (1 << k); i++) {
			bn_free(b[i]);
			ec_free(h[i]);
		}
		RLC_FREE(b);
		RLC_FREE(h);
	}
	return result;
}