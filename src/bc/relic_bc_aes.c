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
