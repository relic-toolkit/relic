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
 * Incremental interface of the hash functions, shared by the SHA-2 and BLAKE2s
 * implementations and used inside the module to hash inputs in pieces.
 *
 * @ingroup md
 */

#ifndef RLC_MD_HASH_H
#define RLC_MD_HASH_H

#include "relic_conf.h"
#include "relic_md.h"
#include "sha.h"
#include "blake2.h"

/**
 * BLAKE2s-160 under the names of the SHA-2 implementation.
 */
#define B2S160_Message_Block_Size	BLAKE2S_BLOCKBYTES
#define B2S160HashSize				RLC_MD_LEN_B2S160
#define B2S160Context				blake2s_state
#define B2S160Reset(C)				blake2s_init(C, RLC_MD_LEN_B2S160)
#define B2S160Input					blake2s_update
#define B2S160Result(C, H)			blake2s_final(C, H, RLC_MD_LEN_B2S160)

/**
 * BLAKE2s-256 under the names of the SHA-2 implementation.
 */
#define B2S256_Message_Block_Size	BLAKE2S_BLOCKBYTES
#define B2S256HashSize				RLC_MD_LEN_B2S256
#define B2S256Context				blake2s_state
#define B2S256Reset(C)				blake2s_init(C, RLC_MD_LEN_B2S256)
#define B2S256Input					blake2s_update
#define B2S256Result(C, H)			blake2s_final(C, H, RLC_MD_LEN_B2S256)

/**
 * Incremental interface of the chosen hash function. Every call returns zero
 * on success.
 */
#if MD_MAP == MD_SH224
#define MD_HASH(X)				SHA224 ## X
#elif MD_MAP == MD_SH256
#define MD_HASH(X)				SHA256 ## X
#elif MD_MAP == MD_SH384
#define MD_HASH(X)				SHA384 ## X
#elif MD_MAP == MD_SH512
#define MD_HASH(X)				SHA512 ## X
#elif MD_MAP == MD_B2S160
#define MD_HASH(X)				B2S160 ## X
#elif MD_MAP == MD_B2S256
#define MD_HASH(X)				B2S256 ## X
#endif

/** Context of the chosen hash function. */
#define MD_CTX					MD_HASH(Context)
/** Block size of the chosen hash function in bytes. */
#define MD_BLOCK				MD_HASH(_Message_Block_Size)
/** Starts a hash computation. */
#define MD_RESET				MD_HASH(Reset)
/** Absorbs at most 2^32 - 1 bytes. */
#define MD_INPUT				MD_HASH(Input)
/** Finishes a hash computation. */
#define MD_RESULT				MD_HASH(Result)

/**
 * Absorbs an input of any length with the chosen hash function, in pieces that
 * fit the 32-bit lengths of the SHA-2 implementation.
 *
 * @param[in,out] ctx		- the hash context.
 * @param[in] in			- the input.
 * @param[in] len			- the input length in bytes.
 * @return zero on success, nonzero otherwise.
 */
static inline int md_input(MD_CTX *ctx, const uint8_t *in, size_t len) {
	while (len > 0) {
		unsigned int n = (len > (1U << 30) ? (1U << 30) : (unsigned int)len);
		if (MD_INPUT(ctx, in, n) != 0) {
			return 1;
		}
		in += n;
		len -= n;
	}
	return 0;
}

#endif /* !RLC_MD_HASH_H */
