/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of hashing to a prime elliptic curve over a nonic extension
 * field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep9_map(ep9_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t sign, done, bit, zero, *r = RLC_ALLOCA(uint8_t, 18 * elm + 1);
	fp9_t t, u, v, w, y, x1, y1, z1;
	ctx_t *ctx = core_get();
	dig_t c2, c3;
	bn_t k;

	bn_null(k);
	fp9_null(t);
	fp9_null(u);
	fp9_null(v);
	fp9_null(w);
	fp9_null(y);
	fp9_null(x1);
	fp9_null(y1);
	fp9_null(z1);

	RLC_TRY {
		bn_new(k);
		fp9_new(t);
		fp9_new(u);
		fp9_new(v);
		fp9_new(w);
		fp9_new(y);
		fp9_new(x1);
		fp9_new(y1);
		fp9_new(z1);

		md_xmd(r, 18 * elm + 1, msg, len, (const uint8_t *)"RELIC", 5);

		for (int i = 0; i < 3; i++) {
			for (int j = 0; j < 3; j++) {
				bn_read_bin(k, r, elm);
				fp_prime_conv(u[i][j], k);
				r += elm;
				bn_read_bin(k, r, elm);
				fp_prime_conv(t[i][j], k);
				r += elm;
			}
		}
		sign = r[0] & 1;
		r -= 18 * elm;

		/* Assume that a = 0. */
		fp9_sqr(x1, u);
		fp9_mul(x1, x1, u);
		fp9_sqr(y1, t);
		fp9_add(x1, x1, ctx->ep9_b);
		fp9_sub(x1, x1, y1);
		fp9_dbl(y1, y1);
		fp9_add(y1, y1, x1);
		fp9_copy(z1, u);
		for (int i = 0; i < 3; i++) {
			for (int j = 0; j < 3; j++) {
				fp_mul(z1[i][j], z1[i][j], ctx->ep_map_c[4]);
			}
		}
		fp9_mul(x1, x1, z1);
		fp9_mul(z1, z1, t);
		fp9_dbl(z1, z1);

		fp9_dbl(y, y1);
		fp9_sqr(y, y);
		fp9_mul(v, y1, u);
		fp9_sub(v, x1, v);
		fp9_mul(v, v, z1);
		fp9_mul(w, y1, z1);
		fp9_dbl(w, w);

		if (fp9_is_zero(w)) {
			ep9_set_infty(p);
		} else {
			fp9_inv(w, w);
			fp9_mul(x1, v, w);
			fp9_add(y1, u, x1);
			fp9_neg(y1, y1);
			fp9_mul(z1, y, w);
			fp9_sqr(z1, z1);
			fp9_add(z1, z1, u);

			ep9_rhs(t, x1);
			ep9_rhs(u, y1);
			ep9_rhs(v, z1);

			c2 = fp9_is_sqr(u);
			c3 = fp9_is_sqr(v);

			fp9_copy_sec(t, u, c2);
			fp9_copy_sec(x1, y1, c2);
			fp9_copy_sec(t, v, c3);
			fp9_copy_sec(x1, z1, c3);

			if (!fp9_srt(t, t)) {
				RLC_THROW(ERR_NO_VALID);
			}

			/* sgn0(t) is the sign of the first nonzero coefficient. */
			done = 0;
			bit = 0;
			for (int i = 0; i < 3; i++) {
				for (int j = 0; j < 3; j++) {
					zero = fp_is_zero(t[i][j]);
					fp_prime_back(k, t[i][j]);
					bit |= (~done) & bn_get_bit(k, 0);
					done |= !zero;
				}
			}
			sign ^= (bit & 1);

			fp9_neg(u, t);
			fp9_copy_sec(t, u, sign);

			fp9_copy(p->x, x1);
			fp9_copy(p->y, t);
			fp9_set_dig(p->z, 1);
			p->coord = BASIC;

			ep9_mul_cof(p, p);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp9_free(t);
		fp9_free(u);
		fp9_free(v);
		fp9_free(w);
		fp9_free(y);
		fp9_free(x1);
		fp9_free(y1);
		fp9_free(z1);
		RLC_FREE(r);
	}
}
