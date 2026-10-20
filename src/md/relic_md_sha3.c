/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of the SHA-3 hash functions and of the SHAKE extendable-output
 * functions (FIPS 202), on the Keccak-f[1600] permutation.
 *
 * @ingroup md
 */

#include <string.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_md.h"
#include "keccak.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Round constants of the iota step.
 */
static const uint64_t keccak_rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
	0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/**
 * Rotation offsets of the rho step, for the lane x + 5y.
 */
static const unsigned keccak_rho[25] = {
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
	18, 2, 61, 56, 14
};

/**
 * Rotates a lane to the left by a number of bits below 64.
 */
static uint64_t keccak_rotl(uint64_t v, unsigned n) {
	return (n == 0 ? v : (v << n) | (v >> (64 - n)));
}

/**
 * Applies the 24 rounds of the Keccak-f[1600] permutation.
 *
 * @param[in,out] a			- the 25 lanes of the state.
 */
static void keccak_f1600(uint64_t a[25]) {
	uint64_t b[25], c[5], d;

	for (int r = 0; r < 24; r++) {
		/* Theta: mix each column with its two neighbors. */
		for (int x = 0; x < 5; x++) {
			c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		}
		for (int x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ keccak_rotl(c[(x + 1) % 5], 1);
			for (int y = 0; y < 25; y += 5) {
				a[x + y] ^= d;
			}
		}
		/* Rho and pi: rotate each lane and move it to (y, 2x + 3y). */
		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++) {
				b[y + 5 * ((2 * x + 3 * y) % 5)] =
						keccak_rotl(a[x + 5 * y], keccak_rho[x + 5 * y]);
			}
		}
		/* Chi: the only nonlinear step, along each row. */
		for (int y = 0; y < 25; y += 5) {
			for (int x = 0; x < 5; x++) {
				a[x + y] = b[x + y] ^
						(~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
			}
		}
		/* Iota: break the symmetry between rounds. */
		a[0] ^= keccak_rc[r];
	}
}

/**
 * Computes a fixed-length SHA-3 digest.
 *
 * @param[out] hash			- the digest.
 * @param[in] len			- the digest length in bytes.
 * @param[in] msg			- the message to hash.
 * @param[in] msg_len		- the message length in bytes.
 */
static void md_sha3(uint8_t *hash, size_t len, const uint8_t *msg,
		size_t msg_len) {
	keccak_state s;

	/* The capacity is twice the digest length. */
	if (md_keccak_init(&s, 200 - 2 * len, KECCAK_SHA3) != 0 ||
			md_keccak_absorb(&s, msg, msg_len) != 0 ||
			md_keccak_squeeze(&s, hash, len) != 0) {
		RLC_THROW(ERR_NO_VALID);
	}
}

/**
 * Computes a SHAKE output of any length.
 *
 * @param[out] out			- the output.
 * @param[in] out_len		- the output length in bytes.
 * @param[in] in			- the input.
 * @param[in] in_len		- the input length in bytes.
 * @param[in] rate			- the rate of the sponge in bytes.
 */
static void md_shake(uint8_t *out, size_t out_len, const uint8_t *in,
		size_t in_len, size_t rate) {
	keccak_state s;

	if (md_keccak_init(&s, rate, KECCAK_SHAKE) != 0 ||
			md_keccak_absorb(&s, in, in_len) != 0 ||
			md_keccak_squeeze(&s, out, out_len) != 0) {
		RLC_THROW(ERR_NO_VALID);
	}
}

/**
 * Expands a message with SHAKE, as expand_message_xof of RFC 9380.
 *
 * @param[out] buf			- the buffer to write.
 * @param[in] buf_len		- the number of bytes to write.
 * @param[in] in			- the input message.
 * @param[in] in_len		- the length of the input in bytes.
 * @param[in] dst			- the domain separation tag.
 * @param[in] dst_len		- the length of the tag in bytes.
 * @param[in] rate			- the rate of the sponge in bytes.
 */
static void md_shake_xof(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len, size_t rate) {
	keccak_state s;
	uint8_t len[2], tag;

	/* Longer tags would have to be hashed first, which is not supported. */
	if (buf_len > 65535 || dst_len > 255) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	len[0] = (uint8_t)(buf_len >> 8);
	len[1] = (uint8_t)buf_len;
	tag = (uint8_t)dst_len;

	/* Squeeze H(msg || I2OSP(len, 2) || DST || I2OSP(len(DST), 1)). */
	if (md_keccak_init(&s, rate, KECCAK_SHAKE) != 0 ||
			md_keccak_absorb(&s, in, in_len) != 0 ||
			md_keccak_absorb(&s, len, sizeof(len)) != 0 ||
			md_keccak_absorb(&s, dst, dst_len) != 0 ||
			md_keccak_absorb(&s, &tag, 1) != 0 ||
			md_keccak_squeeze(&s, buf, buf_len) != 0) {
		RLC_THROW(ERR_NO_VALID);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int md_keccak_init(keccak_state *s, size_t rate, uint8_t pad) {
	if (s == NULL || rate == 0 || rate >= 200 || rate % 8 != 0) {
		return 1;
	}
	memset(s->a, 0, sizeof(s->a));
	s->rate = rate;
	s->pos = 0;
	s->pad = pad;
	s->squeezing = 0;
	return 0;
}

int md_keccak_absorb(keccak_state *s, const uint8_t *in, size_t len) {
	if (s == NULL || s->squeezing || (in == NULL && len > 0)) {
		return 1;
	}
	for (size_t i = 0; i < len; i++) {
		/* Lanes are little-endian, whatever the byte order of the host. */
		s->a[s->pos / 8] ^= (uint64_t)in[i] << (8 * (s->pos % 8));
		if (++s->pos == s->rate) {
			keccak_f1600(s->a);
			s->pos = 0;
		}
	}
	return 0;
}

int md_keccak_squeeze(keccak_state *s, uint8_t *out, size_t len) {
	if (s == NULL || (out == NULL && len > 0)) {
		return 1;
	}
	if (!s->squeezing) {
		/* Append the domain separation bits and the final bit of pad10*1. */
		s->a[s->pos / 8] ^= (uint64_t)s->pad << (8 * (s->pos % 8));
		s->a[(s->rate - 1) / 8] ^= (uint64_t)0x80 << (8 * ((s->rate - 1) % 8));
		keccak_f1600(s->a);
		s->pos = 0;
		s->squeezing = 1;
	}
	for (size_t i = 0; i < len; i++) {
		if (s->pos == s->rate) {
			keccak_f1600(s->a);
			s->pos = 0;
		}
		out[i] = (uint8_t)(s->a[s->pos / 8] >> (8 * (s->pos % 8)));
		s->pos++;
	}
	return 0;
}

void md_map_s3224(uint8_t *hash, const uint8_t *msg, size_t len) {
	md_sha3(hash, RLC_MD_LEN_S3224, msg, len);
}

void md_map_s3256(uint8_t *hash, const uint8_t *msg, size_t len) {
	md_sha3(hash, RLC_MD_LEN_S3256, msg, len);
}

void md_map_s3384(uint8_t *hash, const uint8_t *msg, size_t len) {
	md_sha3(hash, RLC_MD_LEN_S3384, msg, len);
}

void md_map_s3512(uint8_t *hash, const uint8_t *msg, size_t len) {
	md_sha3(hash, RLC_MD_LEN_S3512, msg, len);
}

void md_shake128(uint8_t *out, size_t out_len, const uint8_t *in,
		size_t in_len) {
	md_shake(out, out_len, in, in_len, 168);
}

void md_shake256(uint8_t *out, size_t out_len, const uint8_t *in,
		size_t in_len) {
	md_shake(out, out_len, in, in_len, 136);
}

void md_xof_sk128(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len) {
	md_shake_xof(buf, buf_len, in, in_len, dst, dst_len, 168);
}

void md_xof_sk256(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len) {
	md_shake_xof(buf, buf_len, in, in_len, dst, dst_len, 136);
}
