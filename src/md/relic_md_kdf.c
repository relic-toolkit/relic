/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
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
 * Implementation of a Key Derivation Function and Mask Generation Function.
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
/* Private definitions                                                        */
/*============================================================================*/

static void nist_kdf(uint8_t *key, size_t key_len, const uint8_t *in,
		size_t in_len, dig_t value) {
	uint32_t i, d;
	uint8_t c[sizeof(uint32_t)], hash[RLC_MD_LEN];
	size_t n, out_len = 0;
	MD_CTX ctx;

	if (key_len / RLC_MD_LEN >= UINT32_MAX - value) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (key_len == 0) {
		return;
	}

	/* d = ceil(kLen/hLen). */
	d = RLC_CEIL(key_len, RLC_MD_LEN);
	for (i = value; i < d + value; i++) {
		/* t = t || hash(z || c), with c = integer_to_string(i, 4). */
		util_write_uint32(c, i);
		if (MD_RESET(&ctx) != 0 || md_input(&ctx, in, in_len) != 0 ||
				MD_INPUT(&ctx, c, sizeof(c)) != 0 ||
				MD_RESULT(&ctx, hash) != 0) {
			RLC_THROW(ERR_NO_VALID);
			break;
		}
		n = RLC_MIN(RLC_MD_LEN, key_len - out_len);
		memcpy(key + out_len, hash, n);
		out_len += n;
	}

	util_zero(hash, sizeof(hash));
	util_zero(&ctx, sizeof(ctx));
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void md_mgf(uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len) {
	nist_kdf(key, key_len, in, in_len, 0);
}

void md_kdf(uint8_t *key, size_t key_len, const uint8_t *in, size_t in_len) {
	nist_kdf(key, key_len, in, in_len, 1);
}
