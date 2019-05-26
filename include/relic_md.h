/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * @defgroup md Hash functions
 */

/**
 * @file
 *
 * Interface of the module for computing hash functions.
 *
 * @ingroup md
 */

#ifndef RLC_MD_H
#define RLC_MD_H

#include "relic_conf.h"
#include "relic_types.h"
#include "relic_label.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

enum {
	/** Hash length for SHA-1 function. */
	RLC_MD_LEN_SHONE = 20,
	/** Hash length for SHA-224 function. */
	RLC_MD_LEN_SH224 = 28,
	/** Hash length for SHA-256 function. */
	RLC_MD_LEN_SH256 = 32,
	/** Hash length for SHA-384 function. */
	RLC_MD_LEN_SH384 = 48,
	/** Hash length for SHA-512 function. */
	RLC_MD_LEN_SH512 = 64,
	/** Hash length for BLAKE2s-160 function. */
	RLC_MD_LEN_B2S160 = 20,
	/** Hash length for BLAKE2s-256 function. */
	RLC_MD_LEN_B2S256 = 32
};

/**
 * Length in bytes of default hash function output.
 */
#if MD_MAP == SHONE
#define RLC_MD_LEN					RLC_MD_LEN_SHONE
#elif MD_MAP == SH224
#define RLC_MD_LEN					RLC_MD_LEN_SH224
#elif MD_MAP == SH256
#define RLC_MD_LEN					RLC_MD_LEN_SH256
#elif MD_MAP == SH384
#define RLC_MD_LEN					RLC_MD_LEN_SH384
#elif MD_MAP == SH512
#define RLC_MD_LEN					RLC_MD_LEN_SH512
#elif MD_MAP == B2S160
#define RLC_MD_LEN					RLC_MD_LEN_B2S160
#elif MD_MAP == B2S256
#define RLC_MD_LEN					RLC_MD_LEN_B2S256
#endif

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Maps a byte vector to a fixed-length byte vector using the chosen hash
 * function.
 *
 * @param[out] H				- the digest.
 * @param[in] M					- the message to hash.
 * @param[in] L					- the message length in bytes.
 */
#if MD_MAP == SHONE
#define md_map(H, M, L)			md_map_shone(H, M, L)
#elif MD_MAP == SH224
#define md_map(H, M, L)			md_map_sh224(H, M, L)
#elif MD_MAP == SH256
#define md_map(H, M, L)			md_map_sh256(H, M, L)
#elif MD_MAP == SH384
#define md_map(H, M, L)			md_map_sh384(H, M, L)
#elif MD_MAP == SH512
#define md_map(H, M, L)			md_map_sh512(H, M, L)
#elif MD_MAP == BLAKE2S_160
#define md_map(H, M, L)			md_map_b2s160(H, M, L)
#elif MD_MAP == BLAKE2S_256
#define md_map(H, M, L)			md_map_b2s256(H, M, L)
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Computes the SHA-1 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_shone(uint8_t *hash, const uint8_t *msg, int len);

/**
 * Returns the internal state of the hash function.
 *
 * @param[out] state			- the internal state.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_shone_mid(uint8_t *state, uint8_t *msg, int len);
/**
 * Computes the SHA-224 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh224(uint8_t *hash, const uint8_t *msg, int len);

/**
 * Computes the SHA-256 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh256(uint8_t *hash, const uint8_t *msg, int len);

/**
 * Computes the SHA-384 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh384(uint8_t *hash, const uint8_t *msg, int len);

/**
 * Computes the SHA-512 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh512(uint8_t *hash, const uint8_t *msg, int len);

/**
 * Computes the BLAKE2s-160 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_b2s160(uint8_t *hash, const uint8_t *msg, int len);

/**
 * Computes the BLAKE2s-256 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_b2s256(uint8_t *hash, const uint8_t *msg, int len);

/**
 * Derives a key from shared secret material through the standardized KDF1
 * function.
 *
 * @param[out] key				- the resulting key.
 * @param[in] key_len			- the intended key length in bytes.
 * @param[in] in				- the shared secret.
 * @param[in] in_len			- the length of the shared secret in bytes.
 */
void md_kdf1(uint8_t *key, int key_len, const uint8_t *in, int in_len);

/**
 * Derives a key from shared secret material through the standardized KDF2
 * function.
 *
 * @param[out] key				- the resulting key.
 * @param[in] key_len			- the intended key length in bytes.
 * @param[in] in				- the shared secret.
 * @param[in] in_len			- the length of the shared secret in bytes.
 */
void md_kdf2(uint8_t *key, int key_len, const uint8_t *in, int in_len);

/**
 * Derives a mask from shared secret material through the PKCS#1 2.0 MGF1
 * function .
 *
 * @param[out] key				- the resulting mask.
 * @param[in] key_len			- the intended mask length in bytes.
 * @param[in] in				- the shared secret.
 * @param[in] in_len			- the length of the shared secret in bytes.
 */
void md_mgf1(uint8_t *mask, int mask_len, const uint8_t *in, int in_len);

/**
 * Computes a Message Authentication Code through HMAC.
 *
 * @param[out] mac				- the authentication.
 * @param[in] in				- the date to authenticate.
 * @param[in] in_len			- the number of bytes to authenticate.
 * @param[in] key				- the cryptographic key.
 * @param[in] key_len			- the size of the key in bytes.
 */
void md_hmac(uint8_t *mac, const uint8_t *in, int in_len, const uint8_t *key,
		int key_len);

#endif /* !RLC_MD_H */
