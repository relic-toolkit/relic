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
 * Implementation of the chosen hash function over a message given in pieces.
 *
 * @ingroup md
 */

#include <string.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_md.h"
#include "sha.h"
#include "blake2.h"
#include "keccak.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if MD_MAP == MD_SH224
#define SHA_CTX		SHA224Context
#define SHA_RESET	SHA224Reset
#define SHA_INPUT	SHA224Input
#define SHA_RESULT	SHA224Result
#elif MD_MAP == MD_SH256
#define SHA_CTX		SHA256Context
#define SHA_RESET	SHA256Reset
#define SHA_INPUT	SHA256Input
#define SHA_RESULT	SHA256Result
#elif MD_MAP == MD_SH384
#define SHA_CTX		SHA384Context
#define SHA_RESET	SHA384Reset
#define SHA_INPUT	SHA384Input
#define SHA_RESULT	SHA384Result
#elif MD_MAP == MD_SH512
#define SHA_CTX		SHA512Context
#define SHA_RESET	SHA512Reset
#define SHA_INPUT	SHA512Input
#define SHA_RESULT	SHA512Result
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void md_map_lot(uint8_t *hash, const uint8_t *const *msg, const size_t *len,
		size_t n) {
#if defined(SHA_CTX)
	SHA_CTX ctx;

	if (SHA_RESET(&ctx) != shaSuccess) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		const uint8_t *m = msg[i];
		size_t l = len[i];
		/* The reference implementation takes lengths of at most 32 bits. */
		while (l > 0) {
			unsigned int k = (l > (1U << 30) ? (1U << 30) : (unsigned int)l);
			if (SHA_INPUT(&ctx, m, k) != shaSuccess) {
				RLC_THROW(ERR_NO_VALID);
				return;
			}
			m += k;
			l -= k;
		}
	}
	if (SHA_RESULT(&ctx, hash) != shaSuccess) {
		RLC_THROW(ERR_NO_VALID);
	}
#elif MD_MAP == MD_B2S160 || MD_MAP == MD_B2S256
	blake2s_state s;

	memset(hash, 0, RLC_MD_LEN);
	if (blake2s_init(&s, RLC_MD_LEN) < 0) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		if (blake2s_update(&s, msg[i], len[i]) < 0) {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}
	if (blake2s_final(&s, hash, RLC_MD_LEN) < 0) {
		RLC_THROW(ERR_NO_VALID);
	}
#else
	keccak_state s;

	/* The capacity is twice the digest length. */
	if (md_keccak_init(&s, 200 - 2 * RLC_MD_LEN, KECCAK_SHA3) != 0) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		if (md_keccak_absorb(&s, msg[i], len[i]) != 0) {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}
	if (md_keccak_squeeze(&s, hash, RLC_MD_LEN) != 0) {
		RLC_THROW(ERR_NO_VALID);
	}
#endif
}
