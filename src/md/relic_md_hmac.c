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

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void md_hmac(uint8_t *mac, const uint8_t *in, size_t in_len, const uint8_t *key,
    size_t key_len) {
#if MD_MAP == SH224 || MD_MAP == SH256 || MD_MAP == B2S160 || MD_MAP == B2S256
  #define BLOCK_SIZE 64
#elif MD_MAP == SH384 || MD_MAP == SH512
  #define BLOCK_SIZE  128
#endif
    uint8_t opad[BLOCK_SIZE + RLC_MD_LEN];
    uint8_t *ipad = RLC_ALLOCA(uint8_t, BLOCK_SIZE + in_len);
	uint8_t _key[RLC_MAX(RLC_MD_LEN, BLOCK_SIZE)];

    if (ipad == NULL) {
        RLC_THROW(ERR_NO_MEMORY);
		return;
    }

	if (key_len > BLOCK_SIZE) {
		md_map(_key, key, key_len);
		key = _key;
		key_len = RLC_MD_LEN;
	}
	if (key_len <= BLOCK_SIZE) {
		memcpy(_key, key, key_len);
		memset(_key + key_len, 0, BLOCK_SIZE - key_len);
		key = _key;
	}
	for (int i = 0; i < BLOCK_SIZE; i++) {
		opad[i] = 0x5C ^ key[i];
		ipad[i] = 0x36 ^ key[i];
	}
	memcpy(ipad + BLOCK_SIZE, in, in_len);
	md_map(opad + BLOCK_SIZE, ipad, BLOCK_SIZE + in_len);
	md_map(mac, opad, BLOCK_SIZE + RLC_MD_LEN);

    RLC_FREE(ipad);
}
