/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of AVR-dependent routines.
 *
 * @ingroup arch
 */

#include <avr/pgmspace.h>

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void arch_init(void) {
}

void arch_clean(void) {
}

void arch_copy_rom(char *dest, const char *src, size_t len) {
	int i = 0;
	char c;

	while ((c = pgm_read_byte(src++)) && (i++ < len - 1)) {
		*dest++ = c;
	}
	*dest = 0;
}

uint_t arch_lzcnt(dig_t a) {
	/* Leading zeros of a nibble. */
	static const uint8_t table[16] = {
		4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
	};

	/* The high nibble decides, unless it is zero. Zero gives RLC_WSIZE. */
	if (a >> 4 == 0) {
		return table[a & 0xF] + 4;
	}
	return table[a >> 4];
}

uint_t arch_tzcnt(dig_t a) {
	/* Trailing zeros of a nibble. */
	static const uint8_t table[16] = {
		4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
	};

	/* The low nibble decides, unless it is zero. Zero gives RLC_WSIZE. */
	if ((a & 0xF) == 0) {
		return table[a >> 4] + 4;
	}
	return table[a & 0xF];
}
