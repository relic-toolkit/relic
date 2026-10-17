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
 * Implementation of utilities for pseudo-random number generation.
 *
 * @ingroup rand
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_label.h"
#include "relic_rand.h"
#include "relic_md.h"
#include "relic_err.h"

#if RLC_RAND == UDEV || RLC_SEED == UDEV

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#elif RLC_SEED == WCGR

/* Avoid redefinition warning. */
#undef ERROR
#undef WSIZE

#include <windows.h>
#include <wincrypt.h>

#elif RLC_SEED == RDRND

#include <immintrin.h>

#endif

#ifdef RLC_RAND_FORK
#include <unistd.h>
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/** The maximum number of bytes that can be repeated in the output. */
#define RAND_REP			6

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void rand_init(void) {
	uint8_t buf[RLC_RAND_SEED];

	/* The device generator opens its file when seeded and needs no seed. */
#if RLC_RAND != UDEV

#if !defined(RLC_SEED)

	memset(buf, 0, RLC_RAND_SEED);

#elif RLC_SEED == UDEV
	int fd;
	ssize_t c;
	size_t l;

	fd = open(RLC_RAND_PATH, O_RDONLY);
	if (fd == -1) {
		RLC_THROW(ERR_NO_FILE);
		return;
	}

	for (l = 0; l < RLC_RAND_SEED; l += c) {
		c = read(fd, buf + l, RLC_RAND_SEED - l);
		if (c == -1 && errno == EINTR) {
			c = 0;
			continue;
		}
		/* An error or the end of the file leaves the seed incomplete. */
		if (c <= 0) {
			close(fd);
			RLC_THROW(ERR_NO_READ);
			return;
		}
	}
	close(fd);
#elif RLC_SEED == LIBC

#if OPSYS == FREEBSD || OPSYS == NETBSD
	/* This is better than using a fixed value. */
	arc4random_buf(buf, RLC_RAND_SEED);
#else
	/* This is horribly insecure, serves only for benchmarking. A local
	 * generator leaves the state of rand() to the application. */
	uint32_t s = 1;
	for (int i = 0; i < RLC_RAND_SEED; i++) {
		s = s * 1103515245 + 12345;
		buf[i] = (uint8_t)(s >> 16);
	}
#endif

#elif RLC_SEED == WCGR

	HCRYPTPROV hCryptProv;

	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL,
					CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		RLC_THROW(ERR_NO_FILE);
		return;
	}
	if (hCryptProv && !CryptGenRandom(hCryptProv, RLC_RAND_SEED, buf)) {
		RLC_THROW(ERR_NO_READ);
		return;
	}
	if (hCryptProv && !CryptReleaseContext(hCryptProv, 0)) {
		RLC_THROW(ERR_NO_READ);
		return;
	}

#elif RLC_SEED == RDRND

	size_t i = 0, j;
	ull_t r;
	int tries;

	while (i < RLC_RAND_SEED) {
#ifdef __RDRND__
		/* Intel recommends giving up after 10 consecutive failures. */
		for (tries = 0; tries < 10 && _rdrand64_step(&r) == 0; tries++);
		if (tries == 10) {
			RLC_THROW(ERR_NO_RAND);
			return;
		}
#else
#error "RdRand not available, check your compiler settings."
#endif
		for (j = 0; i < RLC_RAND_SEED && j < sizeof(ull_t); i++, j++) {
			buf[i] = r & 0xFF;
			r >>= 8;
		}
	}

#else
#error "Unknown seeder, check the SEED option."
#endif

#endif /* RLC_RAND != UDEV */

#if RLC_RAND != CALL
	core_get()->seeded = 0;
	rand_seed(buf, RLC_RAND_SEED);
	util_zero(buf, RLC_RAND_SEED);
#ifdef RLC_RAND_FORK
	if (core_get()->seeded) {
		core_get()->pid = (long)getpid();
	}
#endif
#else
	rand_seed(NULL, NULL);
#endif
}

int rand_check(uint8_t *buf, size_t size) {
	int count = 0;

	for (size_t i = 1; i < size; i++) {
		if (buf[i] == buf[i - 1]) {
			count++;
		} else {
			count = 0;
		}
	}

	if (count > RAND_REP) {
		return RLC_ERR;
	}
	return RLC_OK;
}

void rand_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
#if RLC_RAND != CALL
#if RLC_RAND == UDEV
		int *fd = (int *)&(ctx->rand);
		/* The descriptor is only open while seeded. */
		if (ctx->seeded) {
			close(*fd);
		}
#endif
		memset(ctx->rand, 0, sizeof(ctx->rand));
#if RLC_RAND == UDEV
		/* A zero descriptor would read from the standard input. */
		*fd = -1;
#endif
#else
		ctx->rand_call = NULL;
		ctx->rand_args = NULL;
#endif
		ctx->seeded = 0;
	}
}
