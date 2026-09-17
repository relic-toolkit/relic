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
 * or <https://www.apache.org/licenses/>
 */

/**
 * @file
 *
 * Implementation of the low-level multiple precision integer greatest common
 * divisor functions.
 *
 * @ingroup bn
 */

#include <gmp.h>

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

size_t bn_gcdn_low(dig_t *c, dig_t *a, size_t sa, dig_t *b, size_t sb) {
	return mpn_gcd((mp_ptr)c, (mp_ptr)a, sa, (mp_ptr)b, sb);
}
 
size_t bn_gcde_low(dig_t *c, dig_t *d, int *sd, dig_t *a, size_t sa,
		dig_t *b, size_t sb) {
	mp_size_t sn;
	size_t r;

	/*
	 * Not (mp_size_t *)sd: mpn_gcdext writes an mp_size_t, which is a long,
	 * while dis_t tracks WSIZE. The two coincide only for a 64-bit WSIZE on
	 * LP64. With a 32-bit WSIZE the callee writes eight bytes into a four-byte
	 * object, and under LLP64 it writes four into eight and leaves the rest
	 * indeterminate, which breaks the sign of the cofactor.
	 */
	r = mpn_gcdext((mp_ptr)c, (mp_ptr)d, &sn, (mp_ptr)a, sa, (mp_ptr)b, sb);
	*sd = sn;
	return r;
}

/*
 * mpn_hgcd and its matrix helpers live in GMP's gmp-impl.h rather than gmp.h,
 * so the struct layout and the prototypes are reproduced here. The symbols are
 * exported by the library and the layout has been stable across the 6.x series,
 * but this is not a supported interface: if a future GMP changes it, this file
 * is where it breaks.
 */
struct hgcd_matrix {
	mp_size_t alloc;
	mp_size_t n;
	mp_ptr p[2][2];
};

__GMP_DECLSPEC mp_size_t __gmpn_hgcd_itch(mp_size_t);
__GMP_DECLSPEC mp_size_t __gmpn_hgcd(mp_ptr, mp_ptr, mp_size_t,
		struct hgcd_matrix *, mp_ptr);

size_t bn_gcdh_low(dig_t *m00, dig_t *m01, dig_t *m10, dig_t *m11, size_t *sm,
		dig_t *a, dig_t *b, size_t size) {
	struct hgcd_matrix M;
	dig_t *t = RLC_ALLOCA(dig_t, __gmpn_hgcd_itch(size));
	size_t s = ((size + 1) / 2 + 1);
	mp_size_t nn;

	/*
	 * The matrix is built here rather than through mpn_hgcd_matrix_init, so
	 * that its four entries point straight at the caller's areas: mpn_hgcd then
	 * writes the result where the caller wants it and nothing is copied
	 * afterwards. What init would have done is set the identity, which is done
	 * below.
	 */
	M.alloc = (mp_size_t)s;
	M.n = 1;
	M.p[0][0] = (mp_ptr)m00;
	M.p[0][1] = (mp_ptr)m01;
	M.p[1][0] = (mp_ptr)m10;
	M.p[1][1] = (mp_ptr)m11;
	dv_zero(m00, s);
	dv_zero(m01, s);
	dv_zero(m10, s);
	dv_zero(m11, s);
	m00[0] = 1;
	m11[0] = 1;

	nn = __gmpn_hgcd((mp_ptr)a, (mp_ptr)b, (mp_size_t)size, &M, (mp_ptr)t);

	*sm = (size_t)M.n;
	return (size_t)nn;
}
 