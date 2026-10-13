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
 * Implementation of Hash-based Message Authentication Code.
 *
 * @ingroup md
 */

#include <string.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_util.h"
#include "relic_md.h"
#include "relic_md_hash.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void md_hmac(uint8_t *mac, const uint8_t *in, size_t in_len, const uint8_t *key,
		size_t key_len) {
	uint8_t pad[MD_BLOCK], _key[MD_BLOCK], h[RLC_MD_LEN];
	MD_CTX ctx;

	if (key_len > MD_BLOCK) {
		md_map(_key, key, key_len);
		key_len = RLC_MD_LEN;
	} else {
		memcpy(_key, key, key_len);
	}
	memset(_key + key_len, 0, MD_BLOCK - key_len);

	/* h = H((K XOR ipad) || m), absorbing the message in place. */
	for (size_t i = 0; i < MD_BLOCK; i++) {
		pad[i] = 0x36 ^ _key[i];
	}
	if (MD_RESET(&ctx) != 0 || MD_INPUT(&ctx, pad, MD_BLOCK) != 0 ||
			md_input(&ctx, in, in_len) != 0 || MD_RESULT(&ctx, h) != 0) {
		RLC_THROW(ERR_NO_VALID);
	} else {
		/* mac = H((K XOR opad) || h). */
		for (size_t i = 0; i < MD_BLOCK; i++) {
			pad[i] = 0x5C ^ _key[i];
		}
		if (MD_RESET(&ctx) != 0 || MD_INPUT(&ctx, pad, MD_BLOCK) != 0 ||
				MD_INPUT(&ctx, h, RLC_MD_LEN) != 0 ||
				MD_RESULT(&ctx, mac) != 0) {
			RLC_THROW(ERR_NO_VALID);
		}
	}

	util_zero(_key, sizeof(_key));
	util_zero(pad, sizeof(pad));
	util_zero(h, sizeof(h));
	util_zero(&ctx, sizeof(ctx));
}
