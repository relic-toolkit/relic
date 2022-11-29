/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2011 RELIC Authors
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

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

static void nist_kdf(uint8_t *key, size_t key_len, const uint8_t *in,
		size_t in_len, dig_t value) {
	uint32_t i, j, d;
	uint8_t *buffer = NULL, hash[RLC_MD_LEN];
	size_t out_len = 0;

	if (((key_len >> 32) > RLC_MD_LEN) ||
		(in_len + sizeof(uint32_t) < in_len)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	buffer = RLC_ALLOCA(uint8_t, in_len + sizeof(uint32_t));
	if (buffer == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	/* d = ceil(kLen/hLen). */
	d = RLC_CEIL(key_len, RLC_MD_LEN);
	memcpy(buffer, in, in_len);
	for (i = value; i < d + value; i++) {
		j = util_conv_big(i);
		/* c = integer_to_string(c, 4). */
		memcpy(buffer + in_len, &j, sizeof(uint32_t));
		/* t = t || hash(z || c). */
		if (out_len + RLC_MD_LEN <= key_len) {
			md_map(key + out_len, buffer, in_len + sizeof(uint32_t));
            out_len += RLC_MD_LEN;
        } else {
			md_map(hash, buffer, in_len + sizeof(uint32_t));
            memcpy(key + out_len, hash, key_len - out_len);
        }
	}

	RLC_FREE(buffer);
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
