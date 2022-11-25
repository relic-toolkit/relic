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
 * Implementation of comparison in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp2_cmp(const fp2_t a, const fp2_t b) {
	return (fp_cmp(a[0], b[0]) == RLC_EQ) && (fp_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp2_cmp_dig(const fp2_t a, const dig_t b) {
	return (fp_cmp_dig(a[0], b) == RLC_EQ) && fp_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp3_cmp(const fp3_t a, const fp3_t b) {
	return (fp_cmp(a[0], b[0]) == RLC_EQ) && (fp_cmp(a[1], b[1]) == RLC_EQ) &&
			(fp_cmp(a[2], b[2]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp3_cmp_dig(const fp3_t a, const dig_t b) {
	return (fp_cmp_dig(a[0], b) == RLC_EQ) && fp_is_zero(a[1]) &&
			fp_is_zero(a[2]) ? RLC_EQ : RLC_NE;
}

int fp4_cmp(const fp4_t a, const fp4_t b) {
	return (fp2_cmp(a[0], b[0]) == RLC_EQ) && (fp2_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp4_cmp_dig(const fp4_t a, const dig_t b) {
	return (fp2_cmp_dig(a[0], b) == RLC_EQ) && fp2_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp6_cmp(const fp6_t a, const fp6_t b) {
	return (fp2_cmp(a[0], b[0]) == RLC_EQ) && (fp2_cmp(a[1], b[1]) == RLC_EQ) &&
			(fp2_cmp(a[2], b[2]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp6_cmp_dig(const fp6_t a, const dig_t b) {
	return (fp2_cmp_dig(a[0], b) == RLC_EQ) && fp2_is_zero(a[1]) &&
			fp2_is_zero(a[2]) ?	RLC_EQ : RLC_NE;
}

int fp9_cmp(const fp9_t a, const fp9_t b) {
	return (fp3_cmp(a[0], b[0]) == RLC_EQ) && (fp3_cmp(a[1], b[1]) == RLC_EQ) &&
			(fp3_cmp(a[2], b[2]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp9_cmp_dig(const fp9_t a, const dig_t b) {
	return (fp3_cmp_dig(a[0], b) == RLC_EQ) && fp3_is_zero(a[1]) &&
			fp3_is_zero(a[2]) ?	RLC_EQ : RLC_NE;
}

int fp8_cmp(const fp8_t a, const fp8_t b) {
	return (fp4_cmp(a[0], b[0]) == RLC_EQ) && (fp4_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp8_cmp_dig(const fp8_t a, const dig_t b) {
	return (fp4_cmp_dig(a[0], b) == RLC_EQ) && fp4_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp12_cmp(const fp12_t a, const fp12_t b) {
	return (fp6_cmp(a[0], b[0]) == RLC_EQ) && (fp6_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp12_cmp_dig(const fp12_t a, const dig_t b) {
	return (fp6_cmp_dig(a[0], b) == RLC_EQ) && fp6_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp18_cmp(const fp18_t a, const fp18_t b) {
	return (fp9_cmp(a[0], b[0]) == RLC_EQ) && (fp9_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp18_cmp_dig(const fp18_t a, const dig_t b) {
	return (fp9_cmp_dig(a[0], b) == RLC_EQ) && fp9_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp24_cmp(const fp24_t a, const fp24_t b) {
	return (fp8_cmp(a[0], b[0]) == RLC_EQ) && (fp8_cmp(a[1], b[1]) == RLC_EQ) &&
			(fp8_cmp(a[2], b[2]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp24_cmp_dig(const fp24_t a, const dig_t b) {
	return (fp8_cmp_dig(a[0], b) == RLC_EQ) && fp8_is_zero(a[1]) &&
			fp8_is_zero(a[2]) ? RLC_EQ : RLC_NE;
}

int fp48_cmp(const fp48_t a, const fp48_t b) {
	return (fp24_cmp(a[0], b[0]) == RLC_EQ) &&
		(fp24_cmp(a[1], b[1]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp48_cmp_dig(const fp48_t a, const dig_t b) {
	return (fp24_cmp_dig(a[0], b) == RLC_EQ) && fp24_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp54_cmp(const fp54_t a, const fp54_t b) {
	return (fp18_cmp(a[0], b[0]) == RLC_EQ) && (fp18_cmp(a[1], b[1]) == RLC_EQ)
			&& (fp18_cmp(a[2], b[2]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp54_cmp_dig(const fp54_t a, const dig_t b) {
	return (fp18_cmp_dig(a[0], b) == RLC_EQ) && fp18_is_zero(a[1]) &&
			fp18_is_zero(a[2]) ? RLC_EQ : RLC_NE;
}
