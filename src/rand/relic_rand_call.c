/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Implementation of stub generator overridden by callback function.
 *
 * @ingroup rand
 */

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_label.h"
#include "relic_rand.h"

/*============================================================================*/
/* Private definitions                                                         */
/*============================================================================*/

#if RLC_RAND == CALL

static void rand_stub(uint8_t *buf, size_t size, void *args) {
	int fd = open(RLC_RAND_PATH, O_RDONLY);
	ssize_t c;
	size_t l;

	(void)args;

	if (fd == -1) {
		RLC_THROW(ERR_NO_FILE);
		return;
	}

	for (l = 0; l < size; l += c) {
		c = read(fd, buf + l, size - l);
		if (c == -1 && errno == EINTR) {
			c = 0;
			continue;
		}
		/* An error or the end of the file leaves the output incomplete. */
		if (c <= 0) {
			close(fd);
			RLC_THROW(ERR_NO_READ);
			return;
		}
	}
	close(fd);
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if RLC_RAND == CALL

void rand_bytes(uint8_t *buf, size_t size) {
	ctx_t *ctx = core_get();

	if (!ctx->seeded || ctx->rand_call == NULL) {
		RLC_THROW(ERR_NO_RAND);
		return;
	}
	ctx->rand_call(buf, size, ctx->rand_args);
	if (rand_check(buf, size) == RLC_ERR) {
		RLC_THROW(ERR_NO_RAND);
	}
}

void rand_seed(void (*callback)(uint8_t *, size_t, void *), void *args) {
	ctx_t *ctx = core_get();

	if (callback == NULL) {
		ctx->rand_call = rand_stub;
		ctx->rand_args = NULL;
	} else {
		ctx->rand_call = callback;
		ctx->rand_args = args;
	}
	core_get()->seeded = 1;
}

#endif
