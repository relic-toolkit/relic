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
 * Implementation of the /dev/urandom wrapper.
 *
 * @ingroup rand
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_label.h"
#include "relic_rand.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if RAND == UDEV

void rand_bytes(uint8_t *buf, size_t size) {
	int *fd = (int *)&(core_get()->rand);
	ssize_t c;
	size_t l;

	if (!core_get()->seeded || *fd == -1) {
		RLC_THROW(ERR_NO_RAND);
		return;
	}
	for (l = 0; l < size; l += c) {
		c = read(*fd, buf + l, size - l);
		if (c == -1 && errno == EINTR) {
			c = 0;
			continue;
		}
		/* An error or the end of the file leaves the output incomplete. */
		if (c <= 0) {
			RLC_THROW(ERR_NO_READ);
			return;
		}
	}
}

void rand_seed(uint8_t *buf, size_t size) {
	ctx_t *ctx = core_get();
	int *fd = (int *)&(ctx->rand);

	/* The seed is not used, the device is opened once. */
	(void)buf;
	(void)size;
	if (!ctx->seeded) {
		*fd = open(RLC_RAND_PATH, O_RDONLY);
		if (*fd == -1) {
			RLC_THROW(ERR_NO_FILE);
			return;
		}
		ctx->seeded = 1;
	}
}

#endif
