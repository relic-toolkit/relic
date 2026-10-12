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
 * Implementation of the low-level binary field squaring functions.
 *
 * @ingroup fb
 */

#include "relic_fb.h"
#include "relic_fb_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fb_sqri_low(dig_t *c, dig_t *t, const dig_t *a);

void fb_sqrm_low(dig_t *c, const dig_t *a) {
	dv_t t;

	dv_new(t);
	fb_sqri_low(c, t, a);
}

void fb_sqrn_low(dig_t *c, const dig_t *a) {
	dig_t *tmp, x, y, z;

	tmp = c;
	for (int i = 0; i < RLC_FB_DIGS; i++, tmp++) {
		x = a[i];
		y = x & 0x0F;
		z = x >> 4;
		y = (y | (y << 2)) & 0x33;
		y = (y | (y << 1)) & 0x55;
		*tmp++ = y;
		z = (z | (z << 2)) & 0x33;
		z = (z | (z << 1)) & 0x55;
		*tmp = z;
	}
}

void fb_sqrl_low(dig_t *c, const dig_t *a) {
	/* Squares of all polynomials of degree less than 4. */
	static const dig_t table[16] = {
		0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15,
		0x40, 0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55
	};

	for (int i = 0; i < RLC_FB_DIGS; i++) {
		c[2 * i] = table[RLC_LOW(a[i])];
		c[2 * i + 1] = table[RLC_HIGH(a[i])];
	}
}
