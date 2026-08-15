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
 * Implementation of architecture-dependent routines.
 *
 * @ingroup arch
 */

#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void arch_init(void) {
}

void arch_clean(void) {
}

ull_t arch_cycles(void) {
	return 0;
}

uint_t arch_lzcnt(dig_t a) {
#if WSIZE == 8 || WSIZE == 16
	/* Leading zeros of a nibble. */
	static const uint8_t table[16] = {
		4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
	};
#endif

	/*
	 * Zero is handled explicitly so that every width agrees on the result. The
	 * compiler builtins used below for the wider digits are undefined at zero,
	 * and so is the MSVC fallback on processors without LZCNT, whereas the
	 * nibble table would naturally return WSIZE.
	 */
	if (a == 0) {
		return WSIZE;
	}

#if WSIZE == 8
	/*
	 * The leading zeros are those of the most significant non-zero nibble. If
	 * the high nibble is zero the count is four plus those of the low nibble;
	 * otherwise the high nibble alone decides it.
	 */
	if (a >> 4 == 0) {
		return table[a & 0xF] + 4;
	} else {
		return table[a >> 4];
	}
#elif WSIZE == 16
	/*
	 * Same idea one level up: isolate the most significant non-zero byte, then
	 * apply the nibble table to it. The offset counts the zeros already known
	 * to be above that byte, which is why it is eight exactly when the high
	 * byte is empty, the opposite sense to the shift that selects the byte.
	 * Working on a copy keeps both table indices inside the array.
	 */
	{
		uint_t offset;
		dig_t t;

		if (a >> 8 == 0) {
			offset = 8;
			t = a & 0xFF;
		} else {
			offset = 0;
			t = (a >> 8) & 0xFF;
		}
		if (t >> 4 == 0) {
			return table[t & 0xF] + 4 + offset;
		} else {
			return table[t >> 4] + offset;
		}
	}
#elif WSIZE == 32
#ifdef _MSC_VER
	return __lzcnt(a);
#else
	return __builtin_clz(a);
#endif
#elif WSIZE == 64
#ifdef _MSC_VER
	return __lzcnt64(a);
#else
	/*
	 * Not __builtin_clzl: it takes an unsigned long, which is only 64 bits
	 * under LP64 and 32 bits under LLP64, where it would count the zeros of the
	 * wrong half of the digit. The long long variant is at least 64 bits
	 * everywhere.
	 */
	return __builtin_clzll(a);
#endif
#endif
}

uint_t arch_tzcnt(dig_t a) {
#if WSIZE == 8 || WSIZE == 16
	/* Trailing zeros of a nibble. */
	static const uint8_t table[16] = {
		4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
	};
#endif

	/* As above: pin down zero rather than let it differ by width. */
	if (a == 0) {
		return WSIZE;
	}

#if WSIZE == 8
	/*
	 * Mirror image of the leading-zero case: the trailing zeros are those of
	 * the least significant non-zero nibble, so it is the *low* nibble that
	 * decides which branch applies.
	 */
	if ((a & 0xF) != 0) {
		return table[a & 0xF];
	} else {
		return table[a >> 4] + 4;
	}
#elif WSIZE == 16
	{
		uint_t offset;
		dig_t t;

		if ((a & 0xFF) == 0) {
			offset = 8;
			t = (a >> 8) & 0xFF;
		} else {
			offset = 0;
			t = a & 0xFF;
		}
		/*
		 * Note that t is masked to a byte before use. Indexing the table with
		 * an unmasked a >> 4 would run off the end of it, since a is still a
		 * full digit in the branch where the low byte is non-zero.
		 */
		if ((t & 0xF) != 0) {
			return table[t & 0xF] + offset;
		} else {
			return table[t >> 4] + 4 + offset;
		}
	}
#elif WSIZE == 32
#ifdef _MSC_VER
	return _tzcnt_u32(a);
#else
	return __builtin_ctz(a);
#endif
#elif WSIZE == 64
#ifdef _MSC_VER
	return _tzcnt_u64(a);
#else
	/* See the note on __builtin_clzll above. */
	return __builtin_ctzll(a);
#endif
#endif
}