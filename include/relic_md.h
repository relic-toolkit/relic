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
#include "relic_bn.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

enum {
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
	RLC_MD_LEN_B2S256 = 32,
	/** Hash length for SHA3-224 function. */
	RLC_MD_LEN_S3224 = 28,
	/** Hash length for SHA3-256 function. */
	RLC_MD_LEN_S3256 = 32,
	/** Hash length for SHA3-384 function. */
	RLC_MD_LEN_S3384 = 48,
	/** Hash length for SHA3-512 function. */
	RLC_MD_LEN_S3512 = 64
};

/**
 * Length in bytes of default hash function output.
 */
#if MD_MAP == MD_SH224
#define RLC_MD_LEN					RLC_MD_LEN_SH224
#elif MD_MAP == MD_SH256
#define RLC_MD_LEN					RLC_MD_LEN_SH256
#elif MD_MAP == MD_SH384
#define RLC_MD_LEN					RLC_MD_LEN_SH384
#elif MD_MAP == MD_SH512
#define RLC_MD_LEN					RLC_MD_LEN_SH512
#elif MD_MAP == MD_B2S160
#define RLC_MD_LEN					RLC_MD_LEN_B2S160
#elif MD_MAP == MD_B2S256
#define RLC_MD_LEN					RLC_MD_LEN_B2S256
#elif MD_MAP == MD_S3224
#define RLC_MD_LEN					RLC_MD_LEN_S3224
#elif MD_MAP == MD_S3256
#define RLC_MD_LEN					RLC_MD_LEN_S3256
#elif MD_MAP == MD_S3384
#define RLC_MD_LEN					RLC_MD_LEN_S3384
#elif MD_MAP == MD_S3512
#define RLC_MD_LEN					RLC_MD_LEN_S3512
#endif

/**
 * Default domain separation tag for expanding messages, which can be replaced
 * at build time.
 */
#ifndef RLC_DSTAG
#define RLC_DSTAG				RLC_STRING
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
#if MD_MAP == MD_SH224
#define md_map(H, M, L)			md_map_sh224(H, M, L)
#elif MD_MAP == MD_SH256
#define md_map(H, M, L)			md_map_sh256(H, M, L)
#elif MD_MAP == MD_SH384
#define md_map(H, M, L)			md_map_sh384(H, M, L)
#elif MD_MAP == MD_SH512
#define md_map(H, M, L)			md_map_sh512(H, M, L)
#elif MD_MAP == MD_B2S160
#define md_map(H, M, L)			md_map_b2s160(H, M, L)
#elif MD_MAP == MD_B2S256
#define md_map(H, M, L)			md_map_b2s256(H, M, L)
#elif MD_MAP == MD_S3224
#define md_map(H, M, L)			md_map_s3224(H, M, L)
#elif MD_MAP == MD_S3256
#define md_map(H, M, L)			md_map_s3256(H, M, L)
#elif MD_MAP == MD_S3384
#define md_map(H, M, L)			md_map_s3384(H, M, L)
#elif MD_MAP == MD_S3512
#define md_map(H, M, L)			md_map_s3512(H, M, L)
#endif

/**
 * Maps a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the chosen hash function.
 *
 * @param[out] B					- the output buffer.
 * @param[in] BL					- the requested size of the output.
 * @param[in] I						- the message to hash.
 * @param[in] IL					- the message length in bytes.
 * @param[in] D						- the domain separation tag.
 * @param[in] DL					- the domain separation tag length in bytes.
 */
#if MD_MAP == MD_SH224
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_sh224(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_SH256
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_sh256(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_SH384
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_sh384(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_SH512
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_sh512(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_B2S160
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_b2s160(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_B2S256
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_b2s256(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_S3224
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_s3224(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_S3256
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_s3256(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_S3384
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_s3384(B, BL, I, IL, D, DL)
#elif MD_MAP == MD_S3512
#define md_xmd(B, BL, I, IL, D, DL) 	md_xmd_s3512(B, BL, I, IL, D, DL)
#endif

/**
 * Expands a message to pseudorandom bytes with the chosen extendable-output
 * function, as expand_message_xof of RFC 9380.
 *
 * @param[out] B			- the buffer to write.
 * @param[in] BL			- the number of bytes to write, at most 65535.
 * @param[in] I				- the input message.
 * @param[in] IL			- the length of the input in bytes.
 * @param[in] D				- the domain separation tag.
 * @param[in] DL			- the length of the tag in bytes, at most 255.
 */
#if MD_XOF == MD_SK128
#define md_xof(B, BL, I, IL, D, DL) 	md_xof_sk128(B, BL, I, IL, D, DL)
#elif MD_XOF == MD_SK256
#define md_xof(B, BL, I, IL, D, DL) 	md_xof_sk256(B, BL, I, IL, D, DL)
#else
#define md_xof(B, BL, I, IL, D, DL) 	md_xof_b2xs(B, BL, I, IL, D, DL)
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Computes the SHA-224 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh224(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHA-256 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh256(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHA-384 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh384(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHA-512 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_sh512(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the BLAKE2s-160 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_b2s160(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the BLAKE2s-256 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_b2s256(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHA3-224 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_s3224(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHA3-256 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_s3256(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHA3-384 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_s3384(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHA3-512 hash function.
 *
 * @param[out] hash				- the digest.
 * @param[in] msg				- the message to hash.
 * @param[in] len				- the message length in bytes.
 */
void md_map_s3512(uint8_t *hash, const uint8_t *msg, size_t len);

/**
 * Computes the SHAKE128 extendable-output function, with an output of any
 * length.
 *
 * @param[out] out				- the output.
 * @param[in] out_len			- the output length in bytes.
 * @param[in] in				- the input.
 * @param[in] in_len			- the input length in bytes.
 */
void md_shake128(uint8_t *out, size_t out_len, const uint8_t *in,
		size_t in_len);

/**
 * Computes the SHAKE256 extendable-output function, with an output of any
 * length.
 *
 * @param[out] out				- the output.
 * @param[in] out_len			- the output length in bytes.
 * @param[in] in				- the input.
 * @param[in] in_len			- the input length in bytes.
 */
void md_shake256(uint8_t *out, size_t out_len, const uint8_t *in,
		size_t in_len);

/**
 * Expands a message to pseudorandom bytes with SHAKE128, as
 * expand_message_xof of RFC 9380.
 *
 * @param[out] buf			- the buffer to write.
 * @param[in] buf_len		- the number of bytes to write, at most 65535.
 * @param[in] in			- the input message.
 * @param[in] in_len		- the length of the input in bytes.
 * @param[in] dst			- the domain separation tag.
 * @param[in] dst_len		- the length of the tag in bytes, at most 255.
 */
void md_xof_sk128(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Expands a message to pseudorandom bytes with SHAKE256, as
 * expand_message_xof of RFC 9380.
 *
 * @param[out] buf			- the buffer to write.
 * @param[in] buf_len		- the number of bytes to write, at most 65535.
 * @param[in] in			- the input message.
 * @param[in] in_len		- the length of the input in bytes.
 * @param[in] dst			- the domain separation tag.
 * @param[in] dst_len		- the length of the tag in bytes, at most 255.
 */
void md_xof_sk256(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Expands a message to pseudorandom bytes with the BLAKE2s-based XOF, as
 * expand_message_xof of RFC 9380.
 *
 * @param[out] buf			- the buffer to write.
 * @param[in] buf_len		- the number of bytes to write, at most 65535.
 * @param[in] in			- the input message.
 * @param[in] in_len		- the length of the input in bytes.
 * @param[in] dst			- the domain separation tag.
 * @param[in] dst_len		- the length of the tag in bytes, at most 255.
 */
void md_xof_b2xs(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Derives a key from shared secret material through the standardized KDF2
 * function.
 *
 * @param[out] key				- the resulting key.
 * @param[in] key_len			- the intended key length in bytes.
 * @param[in] in				- the shared secret.
 * @param[in] in_len			- the length of the shared secret in bytes.
 */
void md_kdf(uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len);

/**
 * Derives a mask from shared secret material through the PKCS#1 2.1 MGF1
 * function. This is the same as the standardized KDF1 key derivation function.
 *
 * @param[out] key				- the resulting mask.
 * @param[in] key_len			- the intended mask length in bytes.
 * @param[in] in				- the shared secret.
 * @param[in] in_len			- the length of the shared secret in bytes.
 */
void md_mgf(uint8_t *mask, size_t mask_len, const uint8_t *in, size_t in_len);

/**
 * Computes a Message Authentication Code through HMAC.
 *
 * @param[out] mac				- the authentication.
 * @param[in] in				- the date to authenticate.
 * @param[in] in_len			- the number of bytes to authenticate.
 * @param[in] key				- the cryptographic key.
 * @param[in] key_len			- the size of the key in bytes.
 */
void md_hmac(uint8_t *mac, const uint8_t *in, size_t in_len, const uint8_t *key,
		size_t key_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA-224 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_sh224(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA-256 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_sh256(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA-384 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_sh384(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA-512 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_sh512(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the BLAKE2s-160 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_b2s160(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the BLAKE2s-256 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_b2s256(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA3-224 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_s3224(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA3-256 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_s3256(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA3-384 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_s3384(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * Map a byte vector and optional domain separation tag to an arbitrary-length
 * pseudorandom output using the SHA3-512 hash function.
 *
 * @param[out] buf					- the output buffer.
 * @param[in] buf_len				- the requested size of the output.
 * @param[in] in					- the message to hash.
 * @param[in] in_len				- the message length in bytes.
 * @param[in] dst					- the domain separation tag.
 * @param[in] dst_len				- the domain separation tag length in bytes.
 */
void md_xmd_s3512(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len);

/**
 * State of a Keccak-f[1600] sponge that absorbs a message and then squeezes
 * any number of bytes.
 */
typedef struct {
	/** The 25 lanes of the permutation. */
	uint64_t a[25];
	/** The number of bytes absorbed or squeezed per permutation. */
	size_t rate;
	/** The position inside the current block. */
	size_t pos;
	/** The domain separation byte appended to the message. */
	uint8_t pad;
	/** Whether the message was padded and squeezing started. */
	int squeezing;
} keccak_state;

#if MD_XOF == MD_B2XS

/** Size in bytes of a block produced by the BLAKE2s-based XOF. */
#define RLC_XOF_LEN			32

/**
 * A BLAKE2s-based extendable-output function context. A message is absorbed
 * once at initialization, and pseudorandom bytes can then be squeezed out
 * incrementally, with no bound on the total output length fixed in advance,
 * unlike md_xmd.
 */
typedef struct {
	/** the root hash the message was absorbed into. */
	uint8_t root[RLC_XOF_LEN];
	/** the most recently derived output block. */
	uint8_t block[RLC_XOF_LEN];
	/** number of bytes already read from the current block. */
	size_t pos;
	/** index of the next block to derive from the root. */
	uint32_t ctr;
} xof_t;

#else

/**
 * A SHAKE extendable-output function context. A message is absorbed once at
 * initialization, and pseudorandom bytes can then be squeezed out
 * incrementally, with no bound on the total output length fixed in advance,
 * unlike md_xmd.
 */
typedef keccak_state xof_t;

#endif

/**
 * Initializes an XOF by absorbing a message, so that an unbounded number of
 * pseudorandom bytes can subsequently be read from it.
 *
 * @param[out] ctx				- the XOF context.
 * @param[in] in				- the message to absorb.
 * @param[in] in_len			- the message length in bytes.
 */
void md_xof_init(xof_t *ctx, const uint8_t *in, size_t in_len);

/**
 * Reads the next pseudorandom bytes out of an XOF context.
 *
 * @param[out] out				- the output buffer.
 * @param[in] out_len			- the number of bytes to read.
 * @param[in, out] ctx			- the XOF context.
 */
void md_xof_bytes(uint8_t *out, size_t out_len, xof_t *ctx);

/**
 * Reads a value in [0, 1) out of an XOF context.
 *
 * @param[in, out] ctx				- the XOF context.
 * @return a pseudorandom double in [0, 1).
 */
double md_xof_double(xof_t *ctx);

/**
 * Reads an integer in [0, n) out of an XOF context.
 *
 * @param[in, out] ctx				- the XOF context.
 * @param[in] n						- the exclusive upper bound.
 * @return a pseudorandom integer in [0, n).
 */
size_t md_xof_int(xof_t *ctx, size_t n);

/**
 * Reads a value in [0, 2^bits) out of an XOF context.
 *
 * @param[out] r					- the resulting integer.
 * @param[in] bits					- the number of bits.
 * @param[in, out] ctx				- the XOF context.
 */
void md_xof_bits(bn_t r, size_t bits, xof_t *ctx);

#endif /* !RLC_MD_H */
