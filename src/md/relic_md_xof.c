/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Implementation of the extendable-output functions (XOF), the expansion of
 * messages with them, and sampling routines.
 *
 * @ingroup md
 */

#include <stdint.h>
#include <string.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_bn.h"
#include "relic_md.h"
#include "blake2.h"
#include "blake2-impl.h"
#include "keccak.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/** Size in bytes of a block of the BLAKE2s-based XOF. */
#define B2X_LEN				32

/** The BLAKE2X sentinel marking an output of a priori unknown length. */
#define B2X_UNKNOWN			((uint16_t)0xFFFF)

#if MD_XOF == MD_SK128
/** The rate in bytes of the chosen SHAKE sponge. */
#define XOF_RATE			168
#elif MD_XOF == MD_SK256
/** The rate in bytes of the chosen SHAKE sponge. */
#define XOF_RATE			136
#endif

/**
 * Starts the root hash of the BLAKE2s-based XOF.
 *
 * @param[out] s			- the BLAKE2s state.
 * @return zero on success, nonzero otherwise.
 */
static int b2x_init(blake2s_state *s) {
	blake2s_param p;

	memset(&p, 0, sizeof(p));
	p.digest_length = B2X_LEN;
	p.fanout = 1;
	p.depth = 1;
	store16(&p.xof_length, B2X_UNKNOWN);
	return blake2s_init_param(s, &p);
}

/**
 * Derives one output block of the BLAKE2s-based XOF from the root hash, keyed
 * by its index.
 *
 * @param[out] out			- the output block.
 * @param[in] root			- the root hash.
 * @param[in] ctr			- the index of the block.
 */
static void b2x_block(uint8_t out[B2X_LEN], const uint8_t root[B2X_LEN],
		uint32_t ctr) {
	blake2s_state s;
	blake2s_param p;

	memset(&p, 0, sizeof(p));
	p.digest_length = B2X_LEN;
	p.fanout = 0;
	p.depth = 0;
	store32(&p.leaf_length, B2X_LEN);
	store32(&p.node_offset, ctr);
	store16(&p.xof_length, B2X_UNKNOWN);
	p.node_depth = 0;
	p.inner_length = B2X_LEN;

	if (blake2s_init_param(&s, &p) < 0 ||
			blake2s_update(&s, root, B2X_LEN) < 0 ||
			blake2s_final(&s, out, B2X_LEN) < 0) {
		RLC_THROW(ERR_NO_VALID);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void md_xof_b2xs(uint8_t *buf, size_t buf_len, const uint8_t *in,
		size_t in_len, const uint8_t *dst, size_t dst_len) {
	blake2s_state s;
	uint8_t root[B2X_LEN], block[B2X_LEN], len[2], tag;

	/* Longer tags would have to be hashed first, which is not supported. */
	if (buf_len > 65535 || dst_len > 255) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	len[0] = (uint8_t)(buf_len >> 8);
	len[1] = (uint8_t)buf_len;
	tag = (uint8_t)dst_len;

	/* Root of msg || I2OSP(len, 2) || DST || I2OSP(len(DST), 1). */
	if (b2x_init(&s) < 0 || blake2s_update(&s, in, in_len) < 0 ||
			blake2s_update(&s, len, sizeof(len)) < 0 ||
			blake2s_update(&s, dst, dst_len) < 0 ||
			blake2s_update(&s, &tag, 1) < 0 ||
			blake2s_final(&s, root, B2X_LEN) < 0) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	for (size_t i = 0; i < buf_len; i += B2X_LEN) {
		b2x_block(block, root, (uint32_t)(i / B2X_LEN));
		memcpy(buf + i, block, RLC_MIN(B2X_LEN, buf_len - i));
	}
	util_zero(root, sizeof(root));
	util_zero(block, sizeof(block));
}

void md_xof_init(xof_t *ctx, const uint8_t *in, size_t in_len) {
#if MD_XOF == MD_B2XS
	blake2s_state s;

	ctx->ctr = 0;
	ctx->pos = RLC_XOF_LEN;
	if (b2x_init(&s) < 0 || blake2s_update(&s, in, in_len) < 0 ||
			blake2s_final(&s, ctx->root, RLC_XOF_LEN) < 0) {
		RLC_THROW(ERR_NO_VALID);
	}
#else
	if (md_keccak_init(ctx, XOF_RATE, KECCAK_SHAKE) != 0 ||
			md_keccak_absorb(ctx, in, in_len) != 0) {
		RLC_THROW(ERR_NO_VALID);
	}
#endif
}

void md_xof_bytes(uint8_t *out, size_t out_len, xof_t *ctx) {
#if MD_XOF == MD_B2XS
	size_t n;

	while (out_len > 0) {
		if (ctx->pos >= RLC_XOF_LEN) {
			b2x_block(ctx->block, ctx->root, ctx->ctr++);
			ctx->pos = 0;
		}
		n = RLC_XOF_LEN - ctx->pos;
		if (n > out_len) {
			n = out_len;
		}
		memcpy(out, ctx->block + ctx->pos, n);
		ctx->pos += n;
		out += n;
		out_len -= n;
	}
#else
	if (md_keccak_squeeze(ctx, out, out_len) != 0) {
		RLC_THROW(ERR_NO_VALID);
	}
#endif
}

double md_xof_double(xof_t *ctx) {
	uint8_t buf[8];
	uint64_t x = 0;

	md_xof_bytes(buf, sizeof(buf), ctx);
	for (size_t i = 0; i < sizeof(buf); i++) {
		x = (x << 8) | buf[i];
	}
	/* Keep the 53 bits of a double mantissa, so that the result is below 1. */
	return (double)(x >> 11) / 9007199254740992.0;
}

size_t md_xof_int(xof_t *ctx, size_t n) {
	uint8_t buf[sizeof(size_t)];
	size_t v, r;

	if (n <= 1) {
		return 0;
	}
	/* Reject the top 2^w mod n values, so that v mod n is uniform. */
	r = (SIZE_MAX % n + 1) % n;
	do {
		md_xof_bytes(buf, sizeof(buf), ctx);
		v = 0;
		for (size_t i = 0; i < sizeof(buf); i++) {
			v = (v << 8) | buf[i];
		}
	} while (r != 0 && v > SIZE_MAX - r);
	return v % n;
}

void md_xof_bits(bn_t r, size_t bits, xof_t *ctx) {
	size_t i, n = (bits + 7) / 8;
	uint8_t *b;

	if (bits == 0) {
		bn_zero(r);
		return;
	}
	b = RLC_ALLOCA(uint8_t, n);
	if (b == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	/* Keep the output defined even if squeezing fails. */
	memset(b, 0, n);
	md_xof_bytes(b, n, ctx);
	bn_read_bin(r, b, n);
	for (i = bits; i < 8 * n; i++) {
		bn_set_bit(r, i, 0);
	}
	RLC_FREE(b);
}
