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
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Returns 1 if a point of a statement is in the group of prime order, which
 * includes the point at infinity, and 0 otherwise. A point on the curve with
 * a component of small order would pass the checks for some challenges.
 *
 * @param[in] p				- the point.
 * @return 1 if the point is in the group, 0 otherwise.
 */
static int sok_in_group(const ec_t p) {
	return ec_is_infty(p) || ec_is_valid(p);
}

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

	/* Points outside the group are not in the statement. */
	if (!sok_in_group(y)) {
		RLC_FREE(m);
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
	bn_t n, a[2], b[2], z;
	ec_t u, t[2];
	uint8_t h[RLC_MD_LEN];
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, len + 6 * (RLC_FC_BYTES + 1));
	int l, result = RLC_OK;
	/* The real branch is the first one if first is nonzero, the second one
	 * otherwise. Both branches run the same operations, and the values are
	 * moved between them with swaps that do not reveal which is real. */
	dig_t swap = (first == 0);

	bn_null_all(n, a[0], a[1], b[0], b[1], z);
	ec_null_all(u, t[0], t[1]);

	RLC_TRY {
		bn_new_all(n, a[0], a[1], b[0], b[1], z);
		ec_new_all(u, t[0], t[1]);

		/* Points at infinity are shorter, so clear the unused bytes. */
		memset(m, 0, len + 6 * (RLC_FC_BYTES + 1));
		buf = m;
		ec_curve_get_ord(n);
		memcpy(buf, msg, len);
		buf += len;

		/* Index 0 is the real branch and index 1 the simulated one: each
		 * commitment is T = [a]G + [b]Y, so the real nonce is a + bx and the
		 * simulated branch has response a and challenge b. */
		for (int i = 0; i < 2; i++) {
			bn_rand_mod(a[i], n);
			bn_rand_mod(b[i], n);
		}
		bn_swap_sec(a[0], a[1], swap);
		bn_swap_sec(b[0], b[1], swap);
		for (int i = 0; i < 2; i++) {
			if (g != NULL) {
				ec_mul_sec(t[i], g[i], a[i]);
			} else {
				ec_mul_gen(t[i], a[i]);
			}
			ec_mul_sec(u, y[i], b[i]);
			ec_add(t[i], t[i], u);
			ec_norm(t[i], t[i]);
		}
		bn_swap_sec(a[0], a[1], swap);
		bn_swap_sec(b[0], b[1], swap);

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

		/* The real branch gets the rest of the challenge, c = z - b1, and
		 * the response a + (b - c)x, so that [s]G + [c]Y is its commitment. */
		bn_sub(c[0], z, b[1]);
		bn_mod(c[0], c[0], n);
		bn_sub(s[0], b[0], c[0]);
		bn_mul(s[0], s[0], x);
		bn_add(s[0], s[0], a[0]);
		bn_mod(s[0], s[0], n);
		bn_copy(c[1], b[1]);
		bn_copy(s[1], a[1]);
		bn_swap_sec(c[0], c[1], swap);
		bn_swap_sec(s[0], s[1], swap);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free_all(n, a[0], a[1], b[0], b[1], z);
		ec_free_all(u, t[0], t[1]);
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

	/* Points outside the group are not in the statement. Without generators,
	 * the statements use the generator of the curve. */
	if (!sok_in_group(y[0]) || !sok_in_group(y[1]) || (g != NULL &&
			(!sok_in_group(g[0]) || !sok_in_group(g[1])))) {
		RLC_FREE(m);
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
	bn_t n, a[2], b[2], z;
	ec_t t[3], u;
	uint8_t d[RLC_MD_LEN];
	const size_t size = len + 9 * (RLC_FC_BYTES + 1);
	uint8_t *buf, *m = RLC_ALLOCA(uint8_t, size);
	int result = RLC_OK;
	/* The first branch proves log_G(h), the second log_g0(y0) = log_g1(y1).
	 * The real branch is the first one if first is nonzero, the second one
	 * otherwise. Both branches run the same operations, and the values are
	 * moved between them with swaps that do not reveal which is real. */
	dig_t swap = (first == 0);

	bn_null_all(n, a[0], a[1], b[0], b[1], z);
	ec_null_all(u, t[0], t[1], t[2]);

	RLC_TRY {
		bn_new_all(n, a[0], a[1], b[0], b[1], z);
		ec_new_all(u, t[0], t[1], t[2]);
		ec_curve_get_ord(n);

		/* Index 0 is the real branch and index 1 the simulated one: each
		 * commitment is [a]G + [b]Y for the bases of its branch, so the real
		 * nonce is a + bx and the simulated branch has response a and
		 * challenge b. */
		for (int i = 0; i < 2; i++) {
			bn_rand_mod(a[i], n);
			bn_rand_mod(b[i], n);
		}
		bn_swap_sec(a[0], a[1], swap);
		bn_swap_sec(b[0], b[1], swap);
		ec_mul_gen(t[0], a[0]);
		ec_mul_sec(u, h, b[0]);
		ec_add(t[0], t[0], u);
		ec_norm(t[0], t[0]);
		for (int i = 0; i < 2; i++) {
			ec_mul_sec(t[i + 1], g[i], a[1]);
			ec_mul_sec(u, y[i], b[1]);
			ec_add(t[i + 1], t[i + 1], u);
			ec_norm(t[i + 1], t[i + 1]);
		}
		bn_swap_sec(a[0], a[1], swap);
		bn_swap_sec(b[0], b[1], swap);

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
		/* The real branch gets the rest of the challenge, c = z - b1, and
		 * the response a + (b - c)x, so that its commitment verifies. */
		bn_sub(c[0], z, b[1]);
		bn_mod(c[0], c[0], n);
		bn_sub(s[0], b[0], c[0]);
		bn_mul(s[0], s[0], x);
		bn_add(s[0], s[0], a[0]);
		bn_mod(s[0], s[0], n);
		bn_copy(c[1], b[1]);
		bn_copy(s[1], a[1]);
		bn_swap_sec(c[0], c[1], swap);
		bn_swap_sec(s[0], s[1], swap);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free_all(n, a[0], a[1], b[0], b[1], z);
		ec_free_all(u, t[0], t[1], t[2]);
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

	/* Points outside the group are not in the statement. */
	if (!sok_in_group(h) || !sok_in_group(y[0]) || !sok_in_group(y[1])
			|| !sok_in_group(g[0]) || !sok_in_group(g[1])) {
		RLC_FREE(m);
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
