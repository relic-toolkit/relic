/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2018 RELIC Authors
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
 * Implementation of the Hash_DRBG pseudo-random number generator.
 *
 * @ingroup rand
 */

#include <stdlib.h>
#include <stdint.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_label.h"
#include "relic_rand.h"
#include "relic_md.h"
#include "relic_err.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if RAND == HASHD

/*
 * Computes the hash derivation function.
 *
 * param[out] out       - the result.
 * param[in] out_len    - the number of bytes to return.
 * param[in] in         - the input string.
 * param[in] in_len     - the number of bytes in the input.
 */
static void rand_hash(uint8_t *out, size_t out_len, uint8_t *in,
		size_t in_len) {
	size_t len = RLC_CEIL(out_len, RLC_MD_LEN);
	uint8_t* buf = RLC_ALLOCA(uint8_t, 1 + sizeof(uint32_t) + in_len);
	uint8_t hash[RLC_MD_LEN];

	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	buf[0] = 1;
	util_write_uint32(buf + 1, 8 * out_len);
	memcpy(buf + 1 + sizeof(uint32_t), in, in_len);

	for (size_t i = 0; i < len; i++) {
		/* h = Hash(counter || bits_to_return || input_string) */
		md_map(hash, buf, 1 + sizeof(uint32_t) + in_len);
		/* temp = temp || h */
		memcpy(out, hash, RLC_MIN(RLC_MD_LEN, out_len));
		out += RLC_MD_LEN;
		out_len -= RLC_MD_LEN;
		/* counter = counter + 1 */
		buf[0]++;
	}

	util_zero(hash, sizeof(hash));
	util_zero(buf, 1 + sizeof(uint32_t) + in_len);
	RLC_FREE(buf);
}

/**
 * Accumulates an integer in the internal state, seen as a big-endian number.
 *
 * @param[in,out] state		- the internal state.
 * @param[in] size			- the size of the state in bytes.
 * @param[in] digit			- the integer to add.
 * @return the carry out of the state.
 */
static int rand_inc(uint8_t *data, size_t size, uint64_t digit) {
	uint64_t s, carry = digit;
	for (int i = size - 1; i >= 0; i--) {
		/* Add one byte of the integer at a time, so nothing overflows. */
		s = (uint64_t)data[i] + (carry & 0xFF);
		data[i] = s & 0xFF;
		carry = (carry >> 8) + (s >> 8);
	}
	return carry != 0;
}

/**
 * Accumulates the hash value in the internal state.
 *
 * @param[in,out] state		- the internal state.
 * @param[in] hash			- the hash value.
 */
static int rand_add(uint8_t *state, uint8_t *hash, size_t size) {
	int carry = 0;
	for (int i = size - 1; i >= 0; i--) {
		/* Make sure carries are detected. */
		int16_t s;
		s = (state[i] + hash[i] + carry);
		state[i] = s & 0xFF;
		carry = s >> 8;
	}
	return carry;
}

/**
 * Generates pseudo-random bytes by iterating the hash function.
 *
 * @param[out] out 			- the buffer to write.
 * @param[in] out_len		- the number of bytes to write.
 */
static void rand_gen(uint8_t *out, size_t out_len) {
	/* Not RLC_CEIL, which wraps around for an empty output. */
	size_t m = (out_len + RLC_MD_LEN - 1) / RLC_MD_LEN;
	uint8_t hash[RLC_MD_LEN], data[(RLC_RAND_SIZE - 1)/2];
	ctx_t *ctx = core_get();

	/* data = V */
	memcpy(data, ctx->rand + 1, (RLC_RAND_SIZE - 1)/2);
	for (size_t i = 0; i < m; i++) {
		/* w_i = Hash(data) */
		md_map(hash, data, sizeof(data));
		/* W = W || w_i */
		memcpy(out, hash, RLC_MIN(RLC_MD_LEN, out_len));
		out += RLC_MD_LEN;
		out_len -= RLC_MD_LEN;
		/* data = data + 1 mod 2^b. */
		rand_inc(data, (RLC_RAND_SIZE - 1)/2, 1);
	}
	util_zero(hash, sizeof(hash));
	util_zero(data, sizeof(data));
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if RAND == HASHD

void rand_bytes(uint8_t *buf, size_t size) {
	uint8_t hash[RLC_MD_LEN];
	int carry, len  = (RLC_RAND_SIZE - 1)/2;
	ctx_t *ctx = core_get();

	if (sizeof(int) > 2 && size > (1 << 16)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	/* The generator must be reseeded after 2^48 requests. */
	if (ctx->counter > ((uint64_t)1 << 48)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	/* buf = hash_gen(size) */
	rand_gen(buf, size);
	/* H = hash(03 || V) */
	ctx->rand[0] = 0x3;
	md_map(hash, ctx->rand, 1 + len);
	/* V = V + H + C  + reseed_counter. */
	rand_add(ctx->rand + 1, ctx->rand + 1 + len, len);
	carry = rand_add(ctx->rand + 1 + (len - RLC_MD_LEN), hash, RLC_MD_LEN);
	rand_inc(ctx->rand, len - RLC_MD_LEN + 1, carry);
	rand_inc(ctx->rand, len + 1, ctx->counter);
	ctx->counter = ctx->counter + 1;
	util_zero(hash, sizeof(hash));
}

void rand_seed(uint8_t *buf, size_t size) {
	ctx_t *ctx = core_get();
	size_t len = (RLC_RAND_SIZE - 1) / 2;

	if (size <= 0) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	/* The seed has at most 2^35 bits. */
	if ((uint64_t)size > ((uint64_t)1 << 32)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	ctx->rand[0] = 0x0;
	if (ctx->seeded == 0) {
		/* V = hash_df(seed). */
		rand_hash(ctx->rand + 1, len, buf, size);
		/* C = hash_df(00 || V). */
		rand_hash(ctx->rand + 1 + len, len, ctx->rand, len + 1);
	} else {
		/* V = hash_df(01 || V || seed). */
        int tmp_size = 1 + len + size;
		uint8_t* tmp = RLC_ALLOCA(uint8_t, tmp_size);
		if (tmp == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
			return;
		}
		tmp[0] = 1;
		memcpy(tmp + 1, ctx->rand + 1, len);
		memcpy(tmp + 1 + len, buf, size);
		rand_hash(ctx->rand + 1, len, tmp, tmp_size);
		/* C = hash_df(00 || V). */
		rand_hash(ctx->rand + 1 + len, len, ctx->rand, len + 1);
		util_zero(tmp, tmp_size);
		RLC_FREE(tmp);
	}
	ctx->counter = ctx->seeded = 1;
}

#endif
