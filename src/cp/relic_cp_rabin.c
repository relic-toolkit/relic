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
 * Implementation of the Rabin cryptosystem.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Length in bytes of added redundancy.
 */
#define RABIN_PAD_LEN		8

/**
 * Minimum length in bytes of the random padding.
 */
#define RABIN_RND_LEN		8

/**
 * Byte that starts an encoded block.
 */
#define RABIN_TAG			(0x02)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_rabin_gen(rabin_t pub, rabin_t prv, size_t bits) {
	bn_t r;
	int result = RLC_OK;

	bn_null(r);

	RLC_TRY {
		bn_new(r);

		/* Generate different primes p and q. */
		do {
			bn_gen_prime(prv->p, bits / 2);
			bn_mod_2b(r, prv->p, 2);
		} while (bn_cmp_dig(r, 3) != RLC_EQ);

		do {
			bn_gen_prime(prv->q, bits / 2);
			bn_mod_2b(r, prv->q, 2);
		} while (bn_cmp(prv->p, prv->q) == RLC_EQ ||
				bn_cmp_dig(r, 3) != RLC_EQ);

		/* Swap p and q so that p is smaller. */
		if (bn_cmp(prv->p, prv->q) != RLC_LT) {
			bn_swap(prv->p, prv->q);
		}

		bn_gcd_ext(r, prv->dp, prv->dq, prv->p, prv->q);
		if (bn_cmp_dig(r, 1) != RLC_EQ) {
			result = RLC_ERR;
		}

		bn_mul(prv->n, prv->p, prv->q);
		bn_copy(pub->n, prv->n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(r);
	}

	return result;
}

int cp_rabin_enc(uint8_t *out, size_t *out_len, const uint8_t *in,
		size_t in_len, const rabin_t pub) {
	bn_t m;
	size_t size, len, pad;
	uint8_t *buf;
	int result = RLC_OK;

	size = bn_size_bin(pub->n);
	/* The block takes size - 1 bytes, so that it is smaller than n. */
	if (in_len == 0 || size < 2 + RABIN_RND_LEN + RABIN_PAD_LEN + 2 ||
			in_len > size - 3 - RABIN_RND_LEN - RABIN_PAD_LEN) {
		return RLC_ERR;
	}
	len = size - 1 - RABIN_PAD_LEN;
	pad = len - 2 - in_len;

	buf = RLC_ALLOCA(uint8_t, size - 1);
	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(m);

	RLC_TRY {
		bn_new(m);

		/* EB = 02 || PS || 00 || D || R, with PS random and nonzero, and R
		 * repeating the bytes before it to select the right square root. A
		 * full block is larger than the square root of n, so it wraps. */
		buf[0] = RABIN_TAG;
		rand_bytes(buf + 1, pad);
		for (size_t i = 1; i <= pad; i++) {
			while (buf[i] == 0) {
				rand_bytes(buf + i, 1);
			}
		}
		buf[pad + 1] = 0;
		memcpy(buf + pad + 2, in, in_len);
		memcpy(buf + len, buf + len - RABIN_PAD_LEN, RABIN_PAD_LEN);
		bn_read_bin(m, buf, size - 1);

		bn_sqr(m, m);
		bn_mod(m, m, pub->n);

		if (size <= *out_len) {
			*out_len = size;
			memset(out, 0, *out_len);
			bn_write_bin(out, size, m);
		} else {
			result = RLC_ERR;
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		RLC_FREE(buf);
	}

	return result;
}

int cp_rabin_dec(uint8_t *out, size_t *out_len, const uint8_t *in,
		size_t in_len, const rabin_t prv) {
	bn_t m, m0, m1, t;
	size_t j, size;
	uint8_t *buf;
	int result = RLC_OK;

	size = bn_size_bin(prv->n);
	if (in_len < RABIN_PAD_LEN ||
			size < 2 + RABIN_RND_LEN + RABIN_PAD_LEN + 2) {
		return RLC_ERR;
	}

	buf = RLC_ALLOCA(uint8_t, size);
	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(m);
	bn_null(m0);
	bn_null(m1);
	bn_null(t);

	RLC_TRY {
		bn_new(m);
		bn_new(m0);
		bn_new(m1);
		bn_new(t);

		bn_read_bin(m, in, in_len);
		/* Ciphertexts are reduced modulo n. */
		if (bn_cmp(m, prv->n) != RLC_LT) {
			result = RLC_ERR;
		}

		bn_add_dig(t, prv->p, 1);
		bn_rsh(t, t, 2);
		bn_mxp(m0, m, t, prv->p);

		bn_add_dig(t, prv->q, 1);
		bn_rsh(t, t, 2);
		bn_mxp(m1, m, t, prv->q);

		bn_mul(m, prv->dp, prv->p);
		bn_mul(m, m, m1);
		bn_mul(t, prv->dq, prv->q);
		bn_mul(t, t, m0);
		bn_add(m0, m, t);
		bn_mod(m0, m0, prv->n);
		if (bn_sign(m0) == RLC_NEG) {
			bn_add(m0, m0, prv->n);
		}
		bn_sub(m1, m, t);
		bn_mod(m1, m1, prv->n);
		if (bn_sign(m1) == RLC_NEG) {
			bn_add(m1, m1, prv->n);
		}

		bn_mod_2b(m, m0, 8 * RABIN_PAD_LEN);
		bn_rsh(t, m0, 8 * RABIN_PAD_LEN);
		bn_mod_2b(t, t, 8 * RABIN_PAD_LEN);
		if (bn_cmp(t, m) == RLC_EQ) {
			bn_rsh(m, m0, 8 * RABIN_PAD_LEN);
		} else {
			bn_sub(m0, prv->n, m0);
			bn_mod_2b(m, m0, 8 * RABIN_PAD_LEN);
			bn_rsh(t, m0, 8 * RABIN_PAD_LEN);
			bn_mod_2b(t, t, 8 * RABIN_PAD_LEN);
			if (bn_cmp(t, m) == RLC_EQ) {
				bn_rsh(m, m0, 8 * RABIN_PAD_LEN);
			} else {
				bn_mod_2b(m, m1, 8 * RABIN_PAD_LEN);
				bn_rsh(t, m1, 8 * RABIN_PAD_LEN);
				bn_mod_2b(t, t, 8 * RABIN_PAD_LEN);
				if (bn_cmp(t, m) == RLC_EQ) {
					bn_rsh(m, m1, 8 * RABIN_PAD_LEN);
				} else {
					bn_sub(m1, prv->n, m1);
					bn_mod_2b(m, m1, 8 * RABIN_PAD_LEN);
					bn_rsh(t, m1, 8 * RABIN_PAD_LEN);
					bn_mod_2b(t, t, 8 * RABIN_PAD_LEN);
					if (bn_cmp(t, m) == RLC_EQ) {
						bn_rsh(m, m1, 8 * RABIN_PAD_LEN);
					} else {
						result = RLC_ERR;
					}
				}
			}
		}

		if (result == RLC_OK) {
			/* Parse EB without R: 02 || PS || 00 || D. */
			size = bn_size_bin(prv->n) - 1 - RABIN_PAD_LEN;
			if (bn_size_bin(m) > size) {
				result = RLC_ERR;
			} else {
				bn_write_bin(buf, size, m);
				for (j = 1; j < size && buf[j] != 0; j++);
				if (buf[0] != RABIN_TAG || j <= RABIN_RND_LEN || j >= size - 1
						|| size - j - 1 > *out_len) {
					result = RLC_ERR;
				} else {
					*out_len = size - j - 1;
					memcpy(out, buf + j + 1, *out_len);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		bn_free(m0);
		bn_free(m1);
		bn_free(t);
		RLC_FREE(buf);
	}

	return result;
}
