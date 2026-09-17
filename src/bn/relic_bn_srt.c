/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2015 RELIC Authors
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
 * Implementation of the multiple precision integer square root extraction.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_srt(bn_t c, bn_t a) {
	bn_t h, l, m, t;
	size_t bits;
	int cmp;

	if (bn_sign(a) == RLC_NEG) {
		RLC_THROW(ERR_NO_VALID);
	}

	bits = bn_bits(a);
	bits += (bits % 2);

	bn_null(h);
	bn_null(l);
	bn_null(m);
	bn_null(t);

	RLC_TRY {
		bn_new(h);
		bn_new(l);
		bn_new(m);
		bn_new(t);

		bn_zero(l);
		bn_set_2b(h, bits >> 1);
		if (bits >= 2) {
			bn_set_2b(l, (bits >> 1) - 1);
		}

		/* Trivial binary search approach. */
		do {
			bn_add(m, h, l);
			bn_hlv(m, m);
			bn_sqr(t, m);
			cmp = bn_cmp(t, a);
			bn_sub(t, h, l);

			if (cmp == RLC_GT) {
				bn_copy(h, m);
			} else if (cmp == RLC_LT) {
				bn_copy(l, m);
			}
		} while (bn_cmp_dig(t, 1) == RLC_GT && cmp != RLC_EQ);

		bn_copy(c, m);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(h);
		bn_free(l);
		bn_free(m);
		bn_free(t);
	}
}

int bn_srt_mod(bn_t c, const bn_t a, const bn_t b) {
	bn_t e, n, t, u, w;
	size_t i, j, s;
	int result = 0;

	if (bn_sign(b) == RLC_NEG || bn_is_even(b) || bn_cmp_dig(b, 3) == RLC_LT) {
		RLC_THROW(ERR_NO_VALID);
		return 0;
	}

	bn_null(e);
	bn_null(n);
	bn_null(t);
	bn_null(u);
	bn_null(w);

	RLC_TRY {
		bn_new(e);
		bn_new(n);
		bn_new(t);
		bn_new(u);
		bn_new(w);

		bn_mod(t, a, b);
		if (bn_is_zero(t)) {
			bn_zero(c);
			result = 1;
		} else {
			if (bn_smb_leg(t, b) == 1) {
				/* b - 1 = e * 2^s with e odd */
				bn_sub_dig(e, b, 1);
				s = 0;
				while (bn_is_even(e)) {
					bn_hlv(e, e);
					s++;
				}

				if (s == 1) {
					/*
					* For a modulus that is 3 mod 4 four the root is a power, and
					* the general path below would do the same work with a search for a
					* non-residue in front of it.
					*/
					bn_add_dig(u, b, 1);
					bn_rsh(u, u, 2);
					bn_mxp(c, t, u, b);
				} else {
					bn_set_dig(n, 2);
					while (bn_smb_leg(n, b) != -1) {
						bn_add_dig(n, n, 1);
					}
					bn_mxp(n, n, e, b);
					bn_mxp(w, t, e, b);
					bn_add_dig(u, e, 1);
					bn_hlv(u, u);
					bn_mxp(c, t, u, b);

					while (bn_cmp_dig(w, 1) != RLC_EQ) {
						bn_copy(u, w);
						for (i = 0; i < s; i++) {
							if (bn_cmp_dig(u, 1) == RLC_EQ) {
								break;
							}
							bn_sqr(u, u);
							bn_mod(u, u, b);
						}
						if (i >= s) {
							break;
						}
						bn_copy(t, n);
						for (j = 0; j + i + 1 < s; j++) {
							bn_sqr(t, t);
							bn_mod(t, t, b);
						}
						s = i;
						bn_sqr(n, t);
						bn_mod(n, n, b);
						bn_mul(w, w, n);
						bn_mod(w, w, b);
						bn_mul(c, c, t);
						bn_mod(c, c, b);
					}
				}
				bn_sub(u, b, c);
				if (bn_cmp(u, c) == RLC_LT) {
					bn_copy(c, u);
				}
				result = 1;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(e);
		bn_free(n);
		bn_free(t);
		bn_free(u);
		bn_free(w);
	}
	return result;
}
