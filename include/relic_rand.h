/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * @defgroup rand Pseudo-random number generators.
 */

/**
 * @file
 *
 * Interface of the module for pseudo-random number generation.
 *
 * @ingroup rand
 */

#ifndef RLC_RAND_H
#define RLC_RAND_H

#include "relic_conf.h"
#include "relic_types.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Size of the PRNG internal state in bytes.
 */
#if RLC_RAND == HASHD

#if MD_MAP == SH224 || MD_MAP == SH256 || MD_MAP == B2S160 || MD_MAP == B2S256
#define RLC_RAND_SIZE		(1 + 2*440/8)
#elif MD_MAP == SH384 || MD_MAP == SH512
#define RLC_RAND_SIZE		(1 + 2*888/8)
#endif

#elif RLC_RAND == UDEV
#define RLC_RAND_SIZE		(sizeof(int))
#elif RLC_RAND == CALL
#define RLC_RAND_SIZE		(sizeof(void (*)(uint8_t *, size_t, void *)))
#endif

/**
 * Size of the seed gathered when initializing the PRNG.
 */
#define RLC_RAND_SEED	    64

/**
 * Minimum size of the PRNG seed, for 128 bits of security.
 */
#define RLC_RAND_MIN		16

/**
 * Maximum size of the PRNG seed, which is copied to the stack when seeding.
 */
#define RLC_RAND_MAX		1024

/**
 * Path to the character device that supplies entropy.
 */
#define RLC_RAND_PATH		"/dev/urandom"

/**
 * Flag to reseed the PRNG when its process forks, for generators with state
 * on systems where the process identifier is available.
 */
#if RLC_RAND == HASHD && (OPSYS == LINUX || OPSYS == MACOSX || \
		OPSYS == FREEBSD || OPSYS == NETBSD || OPSYS == DROID)
#define RLC_RAND_FORK
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the pseudo-random number generator.
 */
void rand_init(void);

/**
 * Finishes the pseudo-random number generator.
 */
void rand_clean(void);

#if RLC_RAND != CALL

/**
 * Sets the initial state of the pseudo-random number generator.
 *
 * @param[in] buf			- the buffer that represents the initial state.
 * @param[in] size			- the number of bytes, between RLC_RAND_MIN and
 * 							  RLC_RAND_MAX.
 * @throw ERR_NO_VALID		- if the entropy length is too small or too large.
 */
void rand_seed(uint8_t *buf, size_t size);

#else

/**
 * Sets the initial state of the pseudo-random number generator as a function
 * pointer.
 *
 * @param[in] callback		- the callback to call.
 * @param[in] arg			- the argument for the callback.
 */
void rand_seed(void (*callback)(uint8_t *, size_t, void *), void *arg);

#endif

/**
 * Performs a basic self-test in the pseudo-random number generator output, and
 * raises an exception in case a string of identifical bytes is found.
 *
 * @param[out] buf			- the buffer to check.
 * @param[in] size			- the number of bytes to check.
 * @throw ERR_NO_RAND       - if the pseudo-random number generator is stuck.
 */
int rand_check(uint8_t *buf, size_t size);

/**
 * Gathers pseudo-random bytes from the pseudo-random number generator.
 *
 * @param[out] buf			- the buffer to write.
 * @param[in] size			- the number of bytes to gather.
 * @throw ERR_NO_VALID		- if the required length is too large.
 * @throw ERR_NO_READ		- it the pseudo-random number generator cannot
 * 							generate the specified number of bytes.
 */
void rand_bytes(uint8_t *buf, size_t size);

#endif /* !RLC_RAND_H */
