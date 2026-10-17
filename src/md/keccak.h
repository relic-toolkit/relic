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
 * Interface of the Keccak-f[1600] sponge of SHA-3 and SHAKE (FIPS 202).
 *
 * @ingroup md
 */

#ifndef RLC_KECCAK_H
#define RLC_KECCAK_H

#include <stddef.h>
#include <stdint.h>

/** Domain separation byte of the SHA-3 hash functions. */
#define KECCAK_SHA3		0x06
/** Domain separation byte of the SHAKE extendable-output functions. */
#define KECCAK_SHAKE	0x1F

/**
 * State of a Keccak-f[1600] sponge that absorbs a message and then squeezes
 * any number of bytes.
 */
typedef struct {
	/** The 25 lanes of the permutation. */
	uint64_t a[25];
	/** The number of bytes absorbed or squeezed per permutation. */
	size_t rate;
	/** The position inside the current block. */
	size_t pos;
	/** The domain separation byte appended to the message. */
	uint8_t pad;
	/** Whether the message was padded and squeezing started. */
	int squeezing;
} keccak_state;

/**
 * Starts a sponge with a given rate and domain separation byte.
 *
 * @param[out] s			- the state.
 * @param[in] rate			- the rate in bytes, below 200.
 * @param[in] pad			- the domain separation byte.
 * @return zero on success, nonzero otherwise.
 */
int md_keccak_init(keccak_state *s, size_t rate, uint8_t pad);

/**
 * Absorbs bytes into a sponge that did not start squeezing.
 *
 * @param[in,out] s			- the state.
 * @param[in] in			- the input.
 * @param[in] len			- the input length in bytes.
 * @return zero on success, nonzero otherwise.
 */
int md_keccak_absorb(keccak_state *s, const uint8_t *in, size_t len);

/**
 * Squeezes bytes out of a sponge, padding the message on the first call.
 *
 * @param[in,out] s			- the state.
 * @param[out] out			- the output.
 * @param[in] len			- the output length in bytes.
 * @return zero on success, nonzero otherwise.
 */
int md_keccak_squeeze(keccak_state *s, uint8_t *out, size_t len);

#endif /* !RLC_KECCAK_H */
