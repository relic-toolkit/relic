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
 * Implementation of the HMAC_DRBG pseudo-random number generator (NIST
 * SP 800-90A), without prediction resistance or additional input.
 *
 * @ingroup rand
 */

#include <stdint.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_label.h"
#include "relic_rand.h"
#include "relic_md.h"
#include "relic_err.h"

#ifdef RLC_RAND_FORK
#include <unistd.h>
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if RLC_RAND == RLC_HMACD

/**
 * Updates the internal state (K, V) with the provided data.
 *
 * @param[in] in			- the provided data, or NULL.
 * @param[in] in_len		- the number of bytes in the provided data.
 */
static void rand_update(const uint8_t *in, size_t in_len) {
	ctx_t *ctx = core_get();
	uint8_t *k = ctx->rand, *v = ctx->rand + RLC_MD_LEN;
	size_t len = RLC_MD_LEN + 1 + in_len;
	uint8_t *buf = RLC_ALLOCA(uint8_t, len);

	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (in_len > 0) {
		memcpy(buf + RLC_MD_LEN + 1, in, in_len);
	}
	/* The second round only happens when there is data. */
	for (int j = 0; j < (in_len > 0 ? 2 : 1); j++) {
		/* K = HMAC(K, V || j || data). */
		memcpy(buf, v, RLC_MD_LEN);
		buf[RLC_MD_LEN] = j;
		md_hmac(k, buf, len, k, RLC_MD_LEN);
		/* V = HMAC(K, V). */
		md_hmac(v, v, RLC_MD_LEN, k, RLC_MD_LEN);
	}

	util_zero(buf, len);
	RLC_FREE(buf);
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if RLC_RAND == RLC_HMACD

void rand_bytes(uint8_t *buf, size_t size) {
	ctx_t *ctx = core_get();
	uint8_t *k = ctx->rand, *v = ctx->rand + RLC_MD_LEN;

	if (!ctx->seeded) {
		RLC_THROW(ERR_NO_RAND);
		return;
	}
#ifdef RLC_RAND_FORK
	/* A forked process instantiates its own generator from fresh entropy. */
	if (ctx->pid != (long)getpid()) {
		rand_init();
		if (!ctx->seeded || ctx->pid != (long)getpid()) {
			RLC_THROW(ERR_NO_RAND);
			return;
		}
	}
#endif
	if (sizeof(int) > 2 && size > (1 << 16)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	/* The generator must be reseeded after 2^48 requests. */
	if (ctx->counter > ((uint64_t)1 << 48)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	for (size_t i = 0; i < size; i += RLC_MD_LEN) {
		/* V = HMAC(K, V), temp = temp || V. */
		md_hmac(v, v, RLC_MD_LEN, k, RLC_MD_LEN);
		memcpy(buf + i, v, RLC_MIN(RLC_MD_LEN, size - i));
	}
	rand_update(NULL, 0);
	ctx->counter = ctx->counter + 1;
}

void rand_seed(uint8_t *buf, size_t size) {
	ctx_t *ctx = core_get();

	if (size < RLC_RAND_MIN) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	/* Seeds are copied to the stack, so their length is bounded. */
	if (size > RLC_RAND_MAX) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (ctx->seeded == 0) {
		/* K = 00...00, V = 01...01. */
		memset(ctx->rand, 0x00, RLC_MD_LEN);
		memset(ctx->rand + RLC_MD_LEN, 0x01, RLC_MD_LEN);
	}
	/* Instantiating and reseeding both update the state with the seed. */
	rand_update(buf, size);
	ctx->counter = ctx->seeded = 1;
}

#endif
