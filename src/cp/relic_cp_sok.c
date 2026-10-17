/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of protocols for proof of knowledge of discrete logarithms.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/*
 * Source: "Efficient Group Signature for Large Groups"
 * Authors: Jan Camenisch, Markus Stadler
 */

int cp_sokdl_sig(bn_t c, bn_t s, const uint8_t *msg, size_t len, const ec_t y,
		const bn_t x) {
	bn_t n, r;
	ec_t t;
	uint8_t h[RLC_MD_LEN];
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, len + 3 * (RLC_FC_BYTES + 1));
	int l, result = RLC_OK;

	if (m == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	bn_null(r);
	ec_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(r);
		ec_new(t);

		/* Points at infinity are shorter, so clear the unused bytes. */
		memset(m, 0, len + 3 * (RLC_FC_BYTES + 1));
		buf = m;
		ec_curve_get_ord(n);
		ec_curve_get_gen(t);
		memcpy(buf, msg, len);
		buf += len;
		l = ec_size_bin(t, 1);
		ec_write_bin(buf, l, t, 1);
		buf += l;
		l = ec_size_bin(y, 1);
		ec_write_bin(buf, l, y, 1);
		buf += l;

		bn_rand_mod(r, n);
		ec_mul_gen(t, r);
		l = ec_size_bin(t, 1);
		ec_write_bin(buf, l, t, 1);
		buf += l;

		md_map(h, m, len + 3 * (RLC_FC_BYTES + 1));
		bn_read_bin(c, h, RLC_MD_LEN);
		bn_mod(c, c, n);

		bn_mul(s, c, x);
		bn_sub(s, r, s);
		bn_mod(s, s, n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(r);
		ec_free(t);
		RLC_FREE(m);
	}
	return result;
}

int cp_sokdl_ver(const bn_t c, const bn_t s, const uint8_t *msg, size_t len,
		const ec_t y) {
	bn_t n, v;
	ec_t t;
	uint8_t h[RLC_MD_LEN];
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, len + 3 * (RLC_FC_BYTES + 1));
	int l, result = 0;

	/* Points off the curve are not in the statement. */
	if (!ec_on_curve(y)) {
		RLC_FREE(m);
		return 0;
	}

	if (m == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	bn_null(n);
	bn_null(v);
	ec_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(v);
		ec_new(t);

		/* Points at infinity are shorter, so clear the unused bytes. */
		memset(m, 0, len + 3 * (RLC_FC_BYTES + 1));
		buf = m;
		ec_curve_get_ord(n);
		ec_curve_get_gen(t);
		memcpy(buf, msg, len);
		buf += len;
		l = ec_size_bin(t, 1);
		ec_write_bin(buf, l, t, 1);
		buf += l;
		l = ec_size_bin(y, 1);
		ec_write_bin(buf, l, y, 1);
		buf += l;

		/* Compute t' = [r]G + [c]Y. */
		ec_mul_sim_gen(t, s, y, c);
		l = ec_size_bin(t, 1);
		ec_write_bin(buf, l, t, 1);

		md_map(h, m, len + 3 * (RLC_FC_BYTES + 1));
		bn_read_bin(v, h, RLC_MD_LEN);
		bn_mod(v, v, n);

		/* A response outside [0, n) would give another valid proof. */
		if (bn_cmp(v, c) == RLC_EQ &&
				bn_sign(s) == RLC_POS && bn_cmp(s, n) == RLC_LT) {
			result = 1;
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(v);
		ec_free(t);
		RLC_FREE(m);
	}
	return result;
}

int cp_sokor_sig(bn_t c[2], bn_t s[2], const uint8_t *msg, size_t len,
		const ec_t y[2], const ec_t g[2], const bn_t x, int first) {
	bn_t n, v[2], z;
	ec_t u, t[2];
	uint8_t h[RLC_MD_LEN];
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, len + 6 * (RLC_FC_BYTES + 1));
	int l, result = RLC_OK;
	/* Treat any nonzero flag as one, so that the indices stay in range. */
	int one = 1 ^ (first != 0);
	int zero = 0 ^ (first != 0);

	if (m == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	bn_null(v[0]);
	bn_null(v[1]);
	bn_null(z);
	ec_null(u);
	ec_null(t[0]);
	ec_null(t[1]);

	RLC_TRY {
		bn_new(n);
		bn_new(v[0]);
		bn_new(v[1]);
		bn_new(z);
		ec_new(u);
		ec_new(t[0]);
		ec_new(t[1]);

		/* Points at infinity are shorter, so clear the unused bytes. */
		memset(m, 0, len + 6 * (RLC_FC_BYTES + 1));
		buf = m;
		ec_curve_get_ord(n);
		bn_rand_mod(c[zero], n);
		memcpy(buf, msg, len);
		buf += len;

		bn_rand_mod(v[0], n);
		bn_rand_mod(v[1], n);
		if (first) {
			if (g != NULL) {
				ec_mul(t[0], g[0], v[0]);
				ec_mul_sim(t[1], g[1], v[1], y[1], c[zero]);
			} else {
				ec_mul_gen(t[0], v[0]);
				ec_mul_sim_gen(t[1], v[1], y[1], c[zero]);
			}
		} else {
			if (g != NULL) {
				/* T1 = [w]Y1 + [v1]G. */
				ec_mul_sim(t[0], g[0], v[0], y[0], c[zero]);
				/* T2 = [v2]G. */
				ec_mul(t[1], g[1], v[1]);
			} else {
				/* T1 = [w]Y1 + [v1]G. */
				ec_mul_sim_gen(t[0], v[0], y[0], c[zero]);
				/* T2 = [v2]G. */
				ec_mul_gen(t[1], v[1]);
			}
		}

		ec_curve_get_gen(u);
		for (int i = 0; i < 2; i++) {
			if (g != NULL) {
				ec_copy(u, g[i]);
			}
			l = ec_size_bin(u, 1);
			ec_write_bin(buf, l, u, 1);
			buf += l;
			l = ec_size_bin(y[i], 1);
			ec_write_bin(buf, l, y[i], 1);
			buf += l;
			l = ec_size_bin(t[i], 1);
			ec_write_bin(buf, l, t[i], 1);
			buf += l;
		}
		md_map(h, m, len + 6 * (RLC_FC_BYTES + 1));
		bn_read_bin(z, h, RLC_MD_LEN);
		bn_mod(z, z, n);

		bn_sub(c[one], z, c[zero]);
		bn_mod(c[one], c[one], n);

		bn_copy(s[zero], v[zero]);
		bn_mul(s[one], c[one], x);
		bn_sub(s[one], v[one], s[one]);
		bn_mod(s[one], s[one], n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(v[0]);
		bn_free(v[1]);
		bn_free(z);
		ec_free(u);
		ec_free(t[0]);
		ec_free(t[1]);
		RLC_FREE(m);
	}
	return result;
}

int cp_sokor_ver(const bn_t c[2], const bn_t s[2], const uint8_t *msg,
		size_t len, const ec_t y[2], const ec_t g[2]) {
	bn_t n, v[2], z;
	ec_t t;
	uint8_t h[RLC_MD_LEN];
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, len + 6 * (RLC_FC_BYTES + 1));
	int l, result = 0;

	/* Points off the curve are not in the statement. Without generators,
	 * the statements use the generator of the curve. */
	if (!ec_on_curve(y[0]) || !ec_on_curve(y[1]) || (g != NULL &&
			(!ec_on_curve(g[0]) || !ec_on_curve(g[1])))) {
		RLC_FREE(m);
		return 0;
	}

	if (m == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	bn_null(n);
	bn_null(v[0]);
	bn_null(v[1]);
	bn_null(z);
	ec_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(v[0]);
		bn_new(v[1]);
		bn_new(z);
		ec_new(t);

		/* Points at infinity are shorter, so clear the unused bytes. */
		memset(m, 0, len + 6 * (RLC_FC_BYTES + 1));
		buf = m;
		ec_curve_get_ord(n);
		memcpy(buf, msg, len);
		buf += len;

		for (int i = 0; i < 2; i++) {
			if (g != NULL) {
				ec_copy(t, g[i]);
			} else {
				ec_curve_get_gen(t);
			}
			l = ec_size_bin(t, 1);
			ec_write_bin(buf, l, t, 1);
			buf += l;
			l = ec_size_bin(y[i], 1);
			ec_write_bin(buf, l, y[i], 1);
			buf += l;
			if (g != NULL) {
				ec_mul_sim(t, g[i], s[i], y[i], c[i]);
			} else {
				ec_mul_sim_gen(t, s[i], y[i], c[i]);
			}
			l = ec_size_bin(t, 1);
			ec_write_bin(buf, l, t, 1);
			buf += l;
		}
		md_map(h, m, len + 6 * (RLC_FC_BYTES + 1));
		bn_read_bin(z, h, RLC_MD_LEN);
		bn_mod(z, z, n);

		bn_sub(z, z, c[0]);
		bn_sub(z, z, c[1]);
		bn_mod(z, z, n);

		/* Values outside [0, n) would give another valid proof. */
		if (bn_is_zero(z) &&
				bn_sign(c[0]) == RLC_POS && bn_cmp(c[0], n) == RLC_LT &&
				bn_sign(c[1]) == RLC_POS && bn_cmp(c[1], n) == RLC_LT &&
				bn_sign(s[0]) == RLC_POS && bn_cmp(s[0], n) == RLC_LT &&
				bn_sign(s[1]) == RLC_POS && bn_cmp(s[1], n) == RLC_LT) {
			result = 1;
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(v[0]);
		bn_free(v[1]);
		bn_free(z);
		ec_free(t);
		RLC_FREE(m);
	}
	return result;
}

int cp_sokeqor_sig(bn_t c[2], bn_t s[2], const uint8_t *msg, size_t len,
		const ec_t h, const ec_t y[2], const ec_t g[2], const bn_t x,
		int first) {
	bn_t n, v[2], z;
	ec_t t[3], u;
	uint8_t d[RLC_MD_LEN];
	const size_t size = len + 9 * (RLC_FC_BYTES + 1);
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, size);
	int result = RLC_OK;
	/* The first branch proves log_G(h), the second log_g0(y0) = log_g1(y1). */
	int one = (first == 0);
	int zero = (first != 0);

	if (m == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	bn_null(v[0]);
	bn_null(v[1]);
	bn_null(z);
	ec_null(u);
	for (int i = 0; i < 3; i++) {
		ec_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(v[0]);
		bn_new(v[1]);
		bn_new(z);
		ec_new(u);
		for (int i = 0; i < 3; i++) {
			ec_new(t[i]);
		}

		ec_curve_get_ord(n);
		/* Simulate the branch with no witness for a random challenge. */
		bn_rand_mod(c[zero], n);
		bn_rand_mod(v[0], n);
		bn_rand_mod(v[1], n);
		if (first) {
			ec_mul_gen(t[0], v[0]);
			ec_mul_sim(t[1], g[0], v[1], y[0], c[zero]);
			ec_mul_sim(t[2], g[1], v[1], y[1], c[zero]);
		} else {
			ec_mul_sim_gen(t[0], v[0], h, c[zero]);
			ec_mul(t[1], g[0], v[1]);
			ec_mul(t[2], g[1], v[1]);
		}

		/* Hash a fixed-length encoding, so that short points leave zeros. */
		memset(m, 0, size);
		memcpy(m, msg, len);
		buf = m + len;
		ec_curve_get_gen(u);
		ec_write_bin(buf, ec_size_bin(u, 1), u, 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(h, 1), h, 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(t[0], 1), t[0], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(g[0], 1), g[0], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(y[0], 1), y[0], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(t[1], 1), t[1], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(g[1], 1), g[1], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(y[1], 1), y[1], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(t[2], 1), t[2], 1);
		buf += RLC_FC_BYTES + 1;
		md_map(d, m, size);
		bn_read_bin(z, d, RLC_MD_LEN);
		bn_mod(z, z, n);

		/* The real branch gets the rest of the challenge. */
		bn_sub(c[one], z, c[zero]);
		bn_mod(c[one], c[one], n);
		bn_copy(s[zero], v[zero]);
		bn_mul(s[one], c[one], x);
		bn_sub(s[one], v[one], s[one]);
		bn_mod(s[one], s[one], n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(v[0]);
		bn_free(v[1]);
		bn_free(z);
		ec_free(u);
		for (int i = 0; i < 3; i++) {
			ec_free(t[i]);
		}
		RLC_FREE(m);
	}
	return result;
}

int cp_sokeqor_ver(const bn_t c[2], const bn_t s[2], const uint8_t *msg,
		size_t len, const ec_t h, const ec_t y[2], const ec_t g[2]) {
	bn_t n, z;
	ec_t t[3], u;
	uint8_t d[RLC_MD_LEN];
	const size_t size = len + 9 * (RLC_FC_BYTES + 1);
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, size);
	int result = 0;

	/* Points off the curve are not in the statement. */
	if (!ec_on_curve(h) || !ec_on_curve(y[0]) || !ec_on_curve(y[1])
			|| !ec_on_curve(g[0]) || !ec_on_curve(g[1])) {
		RLC_FREE(m);
		return 0;
	}

	if (m == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	bn_null(n);
	bn_null(z);
	ec_null(u);
	for (int i = 0; i < 3; i++) {
		ec_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(z);
		ec_new(u);
		for (int i = 0; i < 3; i++) {
			ec_new(t[i]);
		}

		ec_curve_get_ord(n);
		/* Recompute the commitments from the challenges and responses. */
		ec_mul_sim_gen(t[0], s[0], h, c[0]);
		ec_mul_sim(t[1], g[0], s[1], y[0], c[1]);
		ec_mul_sim(t[2], g[1], s[1], y[1], c[1]);

		memset(m, 0, size);
		memcpy(m, msg, len);
		buf = m + len;
		ec_curve_get_gen(u);
		ec_write_bin(buf, ec_size_bin(u, 1), u, 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(h, 1), h, 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(t[0], 1), t[0], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(g[0], 1), g[0], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(y[0], 1), y[0], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(t[1], 1), t[1], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(g[1], 1), g[1], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(y[1], 1), y[1], 1);
		buf += RLC_FC_BYTES + 1;
		ec_write_bin(buf, ec_size_bin(t[2], 1), t[2], 1);
		buf += RLC_FC_BYTES + 1;
		md_map(d, m, size);
		bn_read_bin(z, d, RLC_MD_LEN);
		bn_mod(z, z, n);

		/* The challenges must add up to the hash. */
		bn_sub(z, z, c[0]);
		bn_sub(z, z, c[1]);
		bn_mod(z, z, n);
		/* Values outside [0, n) would give another valid proof. */
		if (bn_is_zero(z) &&
				bn_sign(c[0]) == RLC_POS && bn_cmp(c[0], n) == RLC_LT &&
				bn_sign(c[1]) == RLC_POS && bn_cmp(c[1], n) == RLC_LT &&
				bn_sign(s[0]) == RLC_POS && bn_cmp(s[0], n) == RLC_LT &&
				bn_sign(s[1]) == RLC_POS && bn_cmp(s[1], n) == RLC_LT) {
			result = 1;
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(z);
		ec_free(u);
		for (int i = 0; i < 3; i++) {
			ec_free(t[i]);
		}
		RLC_FREE(m);
	}
	return result;
}
