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
 * Interface of a compact ML-KEM-1024 implementation (FIPS 203), built on the
 * SHA-3 functions of RELIC. It favors clarity over speed.
 */

#ifndef MLKEM_H
#define MLKEM_H

#include <stdint.h>

/** Module rank of ML-KEM-1024. */
#define MLKEM_K			4

/** Length of an encapsulation key in bytes. */
#define MLKEM_EK_LEN	(384 * MLKEM_K + 32)

/** Length of a decapsulation key in bytes. */
#define MLKEM_DK_LEN	(768 * MLKEM_K + 96)

/** Length of a ciphertext in bytes, with du = 11 and dv = 5. */
#define MLKEM_CT_LEN	(32 * (11 * MLKEM_K + 5))

/** Length of a shared key in bytes. */
#define MLKEM_SS_LEN	32

/**
 * Generates a key pair from the seeds d and z (ML-KEM.KeyGen_internal).
 *
 * @param[out] ek			- the encapsulation key.
 * @param[out] dk			- the decapsulation key.
 * @param[in] d				- the seed of 32 bytes for K-PKE.
 * @param[in] z				- the seed of 32 bytes for implicit rejection.
 * @return 0 if no errors occurred, -1 otherwise.
 */
int mlkem_keygen_seed(uint8_t *ek, uint8_t *dk, const uint8_t *d,
		const uint8_t *z);

/**
 * Generates a key pair with fresh randomness (ML-KEM.KeyGen).
 *
 * @param[out] ek			- the encapsulation key.
 * @param[out] dk			- the decapsulation key.
 * @return 0 if no errors occurred, -1 otherwise.
 */
int mlkem_keygen(uint8_t *ek, uint8_t *dk);

/**
 * Encapsulates a shared key with fresh randomness (ML-KEM.Encaps), after
 * checking that the encapsulation key is well formed.
 *
 * @param[out] ss			- the shared key.
 * @param[out] ct			- the ciphertext.
 * @param[in] ek			- the encapsulation key.
 * @return 0 if no errors occurred, -1 otherwise.
 */
int mlkem_encaps(uint8_t *ss, uint8_t *ct, const uint8_t *ek);

/**
 * Decapsulates a shared key (ML-KEM.Decaps). An invalid ciphertext yields a
 * pseudorandom key derived from z and the ciphertext (implicit rejection).
 *
 * @param[out] ss			- the shared key.
 * @param[in] ct			- the ciphertext.
 * @param[in] dk			- the decapsulation key.
 * @return 0 if no errors occurred, -1 otherwise.
 */
int mlkem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk);

#endif /* !MLKEM_H */
