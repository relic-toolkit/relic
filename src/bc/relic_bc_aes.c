/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2013 RELIC Authors
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
 * Implementation of the AES block cipher.
 *
 * @ingroup bc
 */

#include <limits.h>
#include <string.h>

#include "relic_core.h"
#include "relic_err.h"
#include "relic_bc.h"
#include "relic_util.h"
#include "rijndael-api-fst.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Largest input length in bytes, so that its length in bits plus one padded
 * block fits in the integers of the AES implementation.
 */
#define BC_MAX_LEN		((size_t)INT_MAX / 8 - RLC_BC_LEN)

/**
 * Prepares the key schedule and the CBC state of an AES operation.
 *
 * @param[out] k			- the key schedule.
 * @param[out] c			- the cipher state.
 * @param[in] dir			- the direction, DIR_ENCRYPT or DIR_DECRYPT.
 * @param[in] key			- the key.
 * @param[in] key_len		- the key length in bytes, 16, 24 or 32.
 * @param[in] iv			- the initialization vector.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int bc_aes_init(keyInstance *k, cipherInstance *c, BYTE dir,
		const uint8_t *key, size_t key_len, const uint8_t *iv) {
	if (key_len != 16 && key_len != 24 && key_len != 32) {
		return RLC_ERR;
	}
	if (makeKey2(k, dir, 8 * key_len, (char *)key) != TRUE ||
			cipherInit(c, MODE_CBC, NULL) != TRUE) {
		return RLC_ERR;
	}
	memcpy(c->IV, iv, RLC_BC_LEN);
	return RLC_OK;
}

/**
 * Largest input length of GCM in bytes, 2^36 - 32, from NIST SP 800-38D.
 */
#define BC_GCM_MAX		((((uint64_t)1) << 36) - 32)

/**
 * Loads a 64-bit big-endian integer.
 *
 * @param[in] b				- the bytes.
 * @return the integer.
 */
static uint64_t gcm_load(const uint8_t *b) {
	uint64_t r = 0;

	for (int i = 0; i < 8; i++) {
		r = (r << 8) | b[i];
	}
	return r;
}

/**
 * Stores a 64-bit big-endian integer.
 *
 * @param[out] b			- the bytes.
 * @param[in] v				- the integer.
 */
static void gcm_store(uint8_t *b, uint64_t v) {
	for (int i = 7; i >= 0; i--) {
		b[i] = (uint8_t)v;
		v >>= 8;
	}
}

/**
 * Multiplies the GHASH state by the hash key in GF(2^128), with the bit order
 * of GCM, bit by bit with masks so that the time does not depend on the data.
 *
 * @param[in,out] y			- the state, as two big-endian halves.
 * @param[in] h				- the hash key, as two big-endian halves.
 */
static void gcm_mul(uint64_t y[2], const uint64_t h[2]) {
	uint64_t v0 = h[0], v1 = h[1], z0 = 0, z1 = 0, m;

	for (int i = 0; i < 128; i++) {
		m = -((y[i >> 6] >> (63 - (i & 63))) & 1);
		z0 ^= v0 & m;
		z1 ^= v1 & m;
		/* V = V * x, reduced by x^128 + x^7 + x^2 + x + 1. */
		m = -(v1 & 1);
		v1 = (v1 >> 1) | (v0 << 63);
		v0 = (v0 >> 1) ^ (0xE100000000000000ULL & m);
	}
	y[0] = z0;
	y[1] = z1;
}

/**
 * Absorbs data into the GHASH state, padding the last block with zeros.
 *
 * @param[in,out] y			- the state.
 * @param[in] h				- the hash key.
 * @param[in] in			- the data.
 * @param[in] len			- the data length in bytes.
 */
static void gcm_hash(uint64_t y[2], const uint64_t h[2], const uint8_t *in,
		size_t len) {
	uint8_t block[RLC_BC_LEN];
	size_t l;

	while (len > 0) {
		l = RLC_MIN(len, RLC_BC_LEN);
		memset(block, 0, RLC_BC_LEN);
		memcpy(block, in, l);
		y[0] ^= gcm_load(block);
		y[1] ^= gcm_load(block + 8);
		gcm_mul(y, h);
		in += l;
		len -= l;
	}
}

/**
 * Absorbs the lengths in bits of two inputs into the GHASH state.
 *
 * @param[in,out] y			- the state.
 * @param[in] h				- the hash key.
 * @param[in] a_len			- the first length in bytes.
 * @param[in] c_len			- the second length in bytes.
 */
static void gcm_lens(uint64_t y[2], const uint64_t h[2], uint64_t a_len,
		uint64_t c_len) {
	y[0] ^= 8 * a_len;
	y[1] ^= 8 * c_len;
	gcm_mul(y, h);
}

/**
 * Prepares the hash key H = E(K, 0) and the pre-counter block J0 of GCM.
 *
 * @param[out] k			- the key schedule.
 * @param[out] h			- the hash key.
 * @param[out] j0			- the pre-counter block.
 * @param[in] key			- the key.
 * @param[in] key_len		- the key length in bytes, 16, 24 or 32.
 * @param[in] iv			- the initialization vector.
 * @param[in] iv_len		- the length of the initialization vector in bytes.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int gcm_init(keyInstance *k, uint64_t h[2], uint8_t *j0,
		const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len) {
	uint8_t block[RLC_BC_LEN] = { 0 };
	uint64_t y[2] = { 0, 0 };

	if ((key_len != 16 && key_len != 24 && key_len != 32) || iv_len == 0 ||
			(uint64_t)iv_len > BC_GCM_MAX) {
		return RLC_ERR;
	}
	if (makeKey2(k, DIR_ENCRYPT, 8 * key_len, (char *)key) != TRUE) {
		return RLC_ERR;
	}
	rijndaelEncrypt(k->rk, k->Nr, block, block);
	h[0] = gcm_load(block);
	h[1] = gcm_load(block + 8);

	if (iv_len == 12) {
		/* J0 = IV | 0^31 | 1 for the recommended length. */
		memcpy(j0, iv, 12);
		j0[12] = j0[13] = j0[14] = 0;
		j0[15] = 1;
	} else {
		/* J0 = GHASH(IV | 0^s | [len(IV)]_128) otherwise. */
		gcm_hash(y, h, iv, iv_len);
		gcm_lens(y, h, 0, iv_len);
		gcm_store(j0, y[0]);
		gcm_store(j0 + 8, y[1]);
	}
	util_zero(block, sizeof(block));
	return RLC_OK;
}

/**
 * Encrypts or decrypts in counter mode from the block after J0, incrementing
 * the last 32 bits of the counter. The output may overlap the input.
 *
 * @param[out] out			- the output.
 * @param[in] in			- the input.
 * @param[in] len			- the length in bytes.
 * @param[in] k				- the key schedule.
 * @param[in] j0			- the pre-counter block.
 */
static void gcm_ctr(uint8_t *out, const uint8_t *in, size_t len,
		const keyInstance *k, const uint8_t *j0) {
	uint8_t ctr[RLC_BC_LEN], ks[RLC_BC_LEN];
	uint32_t c;
	size_t l;

	memcpy(ctr, j0, RLC_BC_LEN);
	c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) |
			((uint32_t)ctr[14] << 8) | ctr[15];
	while (len > 0) {
		c++;
		ctr[12] = (uint8_t)(c >> 24);
		ctr[13] = (uint8_t)(c >> 16);
		ctr[14] = (uint8_t)(c >> 8);
		ctr[15] = (uint8_t)c;
		rijndaelEncrypt(k->rk, k->Nr, ctr, ks);
		l = RLC_MIN(len, RLC_BC_LEN);
		for (size_t i = 0; i < l; i++) {
			out[i] = in[i] ^ ks[i];
		}
		in += l;
		out += l;
		len -= l;
	}
	util_zero(ks, sizeof(ks));
}

/**
 * Computes the authentication tag T = E(K, J0) XOR GHASH(A, C) of GCM.
 *
 * @param[out] tag			- the tag of RLC_BC_LEN bytes.
 * @param[in] k				- the key schedule.
 * @param[in] h				- the hash key.
 * @param[in] j0			- the pre-counter block.
 * @param[in] a				- the additional data.
 * @param[in] a_len			- the length of the additional data in bytes.
 * @param[in] c				- the ciphertext.
 * @param[in] c_len			- the length of the ciphertext in bytes.
 */
static void gcm_tag(uint8_t *tag, const keyInstance *k, const uint64_t h[2],
		const uint8_t *j0, const uint8_t *a, size_t a_len, const uint8_t *c,
		size_t c_len) {
	uint64_t y[2] = { 0, 0 };

	gcm_hash(y, h, a, a_len);
	gcm_hash(y, h, c, c_len);
	gcm_lens(y, h, a_len, c_len);
	rijndaelEncrypt(k->rk, k->Nr, j0, tag);
	y[0] ^= gcm_load(tag);
	y[1] ^= gcm_load(tag + 8);
	gcm_store(tag, y[0]);
	gcm_store(tag + 8, y[1]);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int bc_aes_cbc_enc(uint8_t *out, size_t *out_len, const uint8_t *in,
		size_t in_len, const uint8_t *key, size_t key_len, const uint8_t *iv) {
	keyInstance key_inst;
	cipherInstance cipher_inst;
	uint8_t block[RLC_BC_LEN];
	size_t full = in_len - in_len % RLC_BC_LEN;
	size_t pad = RLC_BC_LEN - in_len % RLC_BC_LEN;
	int result = RLC_OK;

	if (in_len > BC_MAX_LEN || *out_len < full + RLC_BC_LEN) {
		return RLC_ERR;
	}
	if (bc_aes_init(&key_inst, &cipher_inst, DIR_ENCRYPT, key, key_len,
			iv) != RLC_OK) {
		result = RLC_ERR;
	} else {
		/* Encrypt the full blocks, then the last one with PKCS#7 padding. */
		if (full > 0) {
			if (blockEncrypt(&cipher_inst, &key_inst, (BYTE *)in, 8 * full,
					out) != (int)(8 * full)) {
				result = RLC_ERR;
			}
			/* The implementation does not chain the IV between calls. */
			memcpy(cipher_inst.IV, out + full - RLC_BC_LEN, RLC_BC_LEN);
		}
		memcpy(block, in + full, in_len - full);
		memset(block + (in_len - full), (int)pad, pad);
		if (result == RLC_OK && blockEncrypt(&cipher_inst, &key_inst, block,
				8 * RLC_BC_LEN, out + full) != 8 * RLC_BC_LEN) {
			result = RLC_ERR;
		}
		if (result == RLC_OK) {
			*out_len = full + RLC_BC_LEN;
		}
	}

	util_zero(block, sizeof(block));
	util_zero(&key_inst, sizeof(key_inst));
	util_zero(&cipher_inst, sizeof(cipher_inst));
	return result;
}

int bc_aes_cbc_dec(uint8_t *out, size_t *out_len, const uint8_t *in,
		size_t in_len, const uint8_t *key, size_t key_len, const uint8_t *iv) {
	keyInstance key_inst;
	cipherInstance cipher_inst;
	uint8_t block[RLC_BC_LEN];
	size_t full = in_len - RLC_BC_LEN;
	uint32_t pad, good, mask;
	int result = RLC_OK;

	if (in_len == 0 || in_len % RLC_BC_LEN != 0 || in_len > BC_MAX_LEN ||
			*out_len < full) {
		return RLC_ERR;
	}
	if (bc_aes_init(&key_inst, &cipher_inst, DIR_DECRYPT, key, key_len,
			iv) != RLC_OK) {
		result = RLC_ERR;
	} else {
		/* Decrypt the last block apart, so that padding is checked first. */
		if (full > 0 && blockDecrypt(&cipher_inst, &key_inst, (BYTE *)in,
				8 * full, out) != (int)(8 * full)) {
			result = RLC_ERR;
		}
		if (result == RLC_OK && blockDecrypt(&cipher_inst, &key_inst,
				(BYTE *)in + full, 8 * RLC_BC_LEN, block) != 8 * RLC_BC_LEN) {
			result = RLC_ERR;
		}

		/* Check the PKCS#7 padding in constant time. */
		pad = block[RLC_BC_LEN - 1];
		/* The padding length must be in [1, 16]. */
		good = ((pad - 1) >> 31) ^ 1;
		good &= (((uint32_t)RLC_BC_LEN - pad) >> 31) ^ 1;
		for (size_t i = 0; i < RLC_BC_LEN; i++) {
			/* All ones if byte i is in the padding, that is, i >= 16 - pad. */
			mask = -(((uint32_t)i - (RLC_BC_LEN - pad)) >> 31 ^ 1);
			good &= ((uint32_t)((block[i] ^ pad) & mask) - 1) >> 31;
		}

		if (result == RLC_OK && good && full + RLC_BC_LEN - pad <= *out_len) {
			memcpy(out + full, block, RLC_BC_LEN - pad);
			*out_len = full + RLC_BC_LEN - pad;
		} else {
			/* Leave no plaintext behind on failure. */
			util_zero(out, full);
			result = RLC_ERR;
		}
	}

	util_zero(block, sizeof(block));
	util_zero(&key_inst, sizeof(key_inst));
	util_zero(&cipher_inst, sizeof(cipher_inst));
	return result;
}

int bc_aes_gcm_enc(uint8_t *out, size_t *out_len, const uint8_t *in,
		size_t in_len, const uint8_t *key, size_t key_len, const uint8_t *iv,
		size_t iv_len, const uint8_t *aad, size_t aad_len) {
	keyInstance key_inst;
	uint64_t h[2];
	uint8_t j0[RLC_BC_LEN];
	int result = RLC_OK;

	if ((uint64_t)in_len > BC_GCM_MAX || in_len > SIZE_MAX - RLC_BC_LEN ||
			*out_len < in_len + RLC_BC_LEN ||
			(aad == NULL && aad_len > 0)) {
		return RLC_ERR;
	}
	if (gcm_init(&key_inst, h, j0, key, key_len, iv, iv_len) != RLC_OK) {
		result = RLC_ERR;
	} else {
		/* The tag is computed after encryption, so the output may overlap
		 * the input. */
		gcm_ctr(out, in, in_len, &key_inst, j0);
		gcm_tag(out + in_len, &key_inst, h, j0, aad, aad_len, out, in_len);
		*out_len = in_len + RLC_BC_LEN;
	}

	util_zero(h, sizeof(h));
	util_zero(j0, sizeof(j0));
	util_zero(&key_inst, sizeof(key_inst));
	return result;
}

int bc_aes_gcm_dec(uint8_t *out, size_t *out_len, const uint8_t *in,
		size_t in_len, const uint8_t *key, size_t key_len, const uint8_t *iv,
		size_t iv_len, const uint8_t *aad, size_t aad_len) {
	keyInstance key_inst;
	uint64_t h[2];
	uint8_t j0[RLC_BC_LEN], tag[RLC_BC_LEN], diff = 0;
	size_t c_len = in_len - RLC_BC_LEN;
	int result = RLC_OK;

	if (in_len < RLC_BC_LEN || (uint64_t)c_len > BC_GCM_MAX ||
			*out_len < c_len || (aad == NULL && aad_len > 0)) {
		return RLC_ERR;
	}
	if (gcm_init(&key_inst, h, j0, key, key_len, iv, iv_len) != RLC_OK) {
		result = RLC_ERR;
	} else {
		/* Check the tag in constant time before releasing any plaintext. */
		gcm_tag(tag, &key_inst, h, j0, aad, aad_len, in, c_len);
		for (size_t i = 0; i < RLC_BC_LEN; i++) {
			diff |= tag[i] ^ in[c_len + i];
		}
		if (diff != 0) {
			result = RLC_ERR;
		} else {
			gcm_ctr(out, in, c_len, &key_inst, j0);
			*out_len = c_len;
		}
	}

	util_zero(h, sizeof(h));
	util_zero(j0, sizeof(j0));
	util_zero(tag, sizeof(tag));
	util_zero(&key_inst, sizeof(key_inst));
	return result;
}
