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
 * Implementation of the ECDSA protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Maximum length in bytes of the order of the curve.
 */
#define ECDSA_BYTES		RLC_CEIL(RLC_BN_BITS, 8)

/**
 * Updates the state K || V of the HMAC_DRBG that derives deterministic
 * nonces (RFC 6979).
 *
 * @param[in,out] kv		- the state.
 * @param[in] in			- the provided data, or NULL.
 * @param[in] len			- the number of bytes in the provided data.
 */
static void ecdsa_det_update(uint8_t *kv, const uint8_t *in, size_t len) {
	uint8_t *k = kv, *v = kv + RLC_MD_LEN;
	uint8_t buf[RLC_MD_LEN + 1 + 2 * ECDSA_BYTES];

	if (len > 2 * ECDSA_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len > 0) {
		memcpy(buf + RLC_MD_LEN + 1, in, len);
	}
	/* The second round only happens when there is data. */
	for (int j = 0; j < (len > 0 ? 2 : 1); j++) {
		/* K = HMAC(K, V || j || data), V = HMAC(K, V). */
		memcpy(buf, v, RLC_MD_LEN);
		buf[RLC_MD_LEN] = j;
		md_hmac(k, buf, RLC_MD_LEN + 1 + len, k, RLC_MD_LEN);
		md_hmac(v, v, RLC_MD_LEN, k, RLC_MD_LEN);
	}
	util_zero(buf, sizeof(buf));
}

/**
 * Derives the next deterministic nonce candidate in [1, n - 1] (RFC 6979).
 *
 * @param[out] k			- the nonce.
 * @param[in,out] kv		- the state K || V of the HMAC_DRBG.
 * @param[in] n				- the order of the curve.
 */
static void ecdsa_det_next(bn_t k, uint8_t *kv, const bn_t n) {
	size_t rlen = RLC_CEIL(bn_bits(n), 8);
	uint8_t t[ECDSA_BYTES];

	do {
		/* T = V_1 || V_2 || ..., until it has qlen bits. */
		for (size_t i = 0; i < rlen; i += RLC_MD_LEN) {
			md_hmac(kv + RLC_MD_LEN, kv + RLC_MD_LEN, RLC_MD_LEN, kv,
					RLC_MD_LEN);
			memcpy(t + i, kv + RLC_MD_LEN, RLC_MIN(RLC_MD_LEN, rlen - i));
		}
		/* k = bits2int(T). */
		bn_read_bin(k, t, rlen);
		bn_rsh(k, k, 8 * rlen - bn_bits(n));
		/* Prepare the state for another candidate. */
		ecdsa_det_update(kv, NULL, 0);
	} while (bn_is_zero(k) || bn_cmp(k, n) != RLC_LT);
	util_zero(t, sizeof(t));
}

/**
 * Signs a message using ECDSA, with random or deterministic nonces.
 *
 * @param[out] r			- the first component of the signature.
 * @param[out] s			- the second component of the signature.
 * @param[in] msg			- the message to sign.
 * @param[in] len			- the message length in bytes.
 * @param[in] hash			- the flag to indicate the message format.
 * @param[in] d				- the private key.
 * @param[in] det			- the flag to derive nonces as in RFC 6979.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int ecdsa_sig(bn_t r, bn_t s, const uint8_t *msg, size_t len, int hash,
		const bn_t d, int det) {
	bn_t n, k, x, e;
	ec_t p;
	uint8_t h[RLC_MD_LEN], kv[2 * RLC_MD_LEN], seed[2 * ECDSA_BYTES];
	size_t rlen;
	int result = RLC_OK;

	bn_null(n);
	bn_null(k);
	bn_null(x);
	bn_null(e);
	ec_null(p);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		bn_new(x);
		bn_new(e);
		ec_new(p);

		ec_curve_get_ord(n);

		/* Hash once, so retries sign the same digest. */
		if (!hash) {
			md_map(h, msg, len);
			msg = h;
			len = RLC_MD_LEN;
		}
		if (8 * len > bn_bits(n)) {
			len = RLC_CEIL(bn_bits(n), 8);
			bn_read_bin(e, msg, len);
			bn_rsh(e, e, 8 * len - bn_bits(n));
		} else {
			bn_read_bin(e, msg, len);
		}

		if (det) {
			rlen = RLC_CEIL(bn_bits(n), 8);
			if (rlen > ECDSA_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			/* K = 00...00, V = 01...01. */
			memset(kv, 0x00, RLC_MD_LEN);
			memset(kv + RLC_MD_LEN, 0x01, RLC_MD_LEN);
			/* Seed with int2octets(d) || bits2octets(e). */
			bn_mod(x, d, n);
			bn_write_bin(seed, rlen, x);
			bn_mod(x, e, n);
			bn_write_bin(seed + rlen, rlen, x);
			ecdsa_det_update(kv, seed, 2 * rlen);
		}

		do {
			do {
				if (det) {
					ecdsa_det_next(k, kv, n);
				} else {
					bn_rand_mod(k, n);
				}
				ec_mul_gen(p, k);
				ec_get_x(x, p);
				bn_mod(r, x, n);
			} while (bn_is_zero(r));

			bn_mul(s, d, r);
			bn_mod(s, s, n);
			bn_add(s, s, e);
			bn_mod(s, s, n);
			/* Blind the secret, as inversion takes variable time. */
			bn_rand_mod(x, n);
			bn_mul(k, k, x);
			bn_mod(k, k, n);
			bn_mod_inv(k, k, n);
			bn_mul(k, k, x);
			bn_mod(k, k, n);
			bn_mul(s, s, k);
			bn_mod(s, s, n);
		} while (bn_is_zero(s));
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		util_zero(kv, sizeof(kv));
		util_zero(seed, sizeof(seed));
		bn_free(n);
		bn_free(k);
		bn_free(x);
		bn_free(e);
		ec_free(p);
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_ecdsa_gen(bn_t d, ec_t q) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		ec_curve_get_ord(n);
		bn_rand_mod(d, n);
		ec_mul_gen(q, d);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_ecdsa_sig(bn_t r, bn_t s, const uint8_t *msg, size_t len, int hash,
		const bn_t d) {
	return ecdsa_sig(r, s, msg, len, hash, d, 0);
}

int cp_ecdsa_sig_det(bn_t r, bn_t s, const uint8_t *msg, size_t len, int hash,
		const bn_t d) {
	return ecdsa_sig(r, s, msg, len, hash, d, 1);
}

int cp_ecdsa_ver(const bn_t r, const bn_t s, const uint8_t *msg, size_t len,
		int hash, const ec_t q) {
	bn_t n, k, e, v;
	ec_t p;
	uint8_t h[RLC_MD_LEN];
	int cmp, result = 0;

	bn_null(n);
	bn_null(k);
	bn_null(e);
	bn_null(v);
	ec_null(p);

	RLC_TRY {
		bn_new(n);
		bn_new(e);
		bn_new(v);
		bn_new(k);
		ec_new(p);

		ec_curve_get_ord(n);

		/* The key at infinity would let anyone produce valid signatures. */
		if (bn_sign(r) == RLC_POS && bn_sign(s) == RLC_POS &&
				!bn_is_zero(r) && !bn_is_zero(s) && !ec_is_infty(q) &&
				ec_on_curve(q)) {
			if (bn_cmp(r, n) == RLC_LT && bn_cmp(s, n) == RLC_LT) {
				bn_mod_inv(k, s, n);

				if (!hash) {
					md_map(h, msg, len);
					msg = h;
					len = RLC_MD_LEN;
				}

				if (8 * len > bn_bits(n)) {
					len = RLC_CEIL(bn_bits(n), 8);
					bn_read_bin(e, msg, len);
					bn_rsh(e, e, 8 * len - bn_bits(n));
				} else {
					bn_read_bin(e, msg, len);
				}

				bn_mul(e, e, k);
				bn_mod(e, e, n);
				bn_mul(v, r, k);
				bn_mod(v, v, n);

				ec_mul_sim_gen(p, e, q, v);
				ec_get_x(v, p);

				bn_mod(v, v, n);

				cmp = dv_equ_sec(v->dp, r->dp, RLC_MIN(v->used, r->used));
				result = (cmp == RLC_EQ && v->used == r->used &&
						!ec_is_infty(p));
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(e);
		bn_free(v);
		bn_free(k);
		ec_free(p);
	}
	return result;
}
