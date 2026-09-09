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
 * Implementation of an eXtended Output Function (XOF) and sampling routines.
 *
 * @ingroup md
 */

#include <string.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_bn.h"
#include "relic_md.h"
#include "blake2.h"
#include "blake2-impl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/** The BLAKE2X sentinel marking an output of a priori unknown length. */
#define RLC_XOF_UNKNOWN		((uint16_t)0xFFFF)

/**
 * Derives one output block from the root hash, keyed by its index.
 */
static void md_xof_block(uint8_t out[RLC_XOF_LEN],
		const uint8_t root[RLC_XOF_LEN], uint32_t ctr) {
	blake2s_state s;
	blake2s_param p;

	memset(&p, 0, sizeof(p));
	p.digest_length = RLC_XOF_LEN;
	p.fanout = 0;
	p.depth = 0;
	store32(&p.leaf_length, RLC_XOF_LEN);
	store32(&p.node_offset, ctr);
	store16(&p.xof_length, RLC_XOF_UNKNOWN);
	p.node_depth = 0;
	p.inner_length = RLC_XOF_LEN;

	if (blake2s_init_param(&s, &p) < 0 ||
			blake2s_update(&s, root, RLC_XOF_LEN) < 0 ||
			blake2s_final(&s, out, RLC_XOF_LEN) < 0) {
		RLC_THROW(ERR_NO_VALID);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void md_xof_init(xof_t *ctx, const uint8_t *in, size_t in_len) {
	blake2s_state s;
	blake2s_param p;

	memset(&p, 0, sizeof(p));
	p.digest_length = RLC_XOF_LEN;
	p.fanout = 1;
	p.depth = 1;
	store16(&p.xof_length, RLC_XOF_UNKNOWN);

	if (blake2s_init_param(&s, &p) < 0 ||
			blake2s_update(&s, in, in_len) < 0 ||
			blake2s_final(&s, ctx->root, RLC_XOF_LEN) < 0) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	ctx->ctr = 0;
	ctx->pos = RLC_XOF_LEN;
}

void md_xof_bytes(uint8_t *out, size_t out_len, xof_t *ctx) {
	size_t n;

	while (out_len > 0) {
		if (ctx->pos >= RLC_XOF_LEN) {
			md_xof_block(ctx->block, ctx->root, ctx->ctr++);
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
}

double md_xof_double(xof_t *ctx) {
	uint8_t buf[sizeof(double)];
	size_t i;
	double v = 0.0, s = 1.0;

	md_xof_bytes(buf, sizeof(buf), ctx);
	for (i = 0; i < sizeof(buf); i++) {
		s /= 256.0;
		v += s * (double)buf[i];
	}
	return v;
}

size_t md_xof_int(xof_t *ctx, size_t n) {
	uint8_t buf[sizeof(size_t)];
	size_t v = 0, i;

	if (n <= 1) {
		return 0;
	}
	md_xof_bytes(buf, sizeof(buf), ctx);
	for (i = 0; i < sizeof(buf); i++) {
		v = (v << 8) | buf[i];
	}
	return v % n;
}

void md_xof_bits(bn_t r, size_t bits, xof_t *ctx) {
	size_t i, n = (bits + 7) / 8;
	uint8_t *b = RLC_ALLOCA(uint8_t, n);

	if (b == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	md_xof_bytes(b, n, ctx);
	bn_read_bin(r, b, n);
	for (i = bits; i < 8 * n; i++) {
		bn_set_bit(r, i, 0);
	}
	RLC_FREE(b);
}
