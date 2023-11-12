/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of hashing to a prime elliptic curve over a quadratic
 * extension.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep8_map(ep8_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t t0z, t0, t1, s[2][2], sign, *r = RLC_ALLOCA(uint8_t, 16 * elm + 1);
	fp8_t t, u, v, w, y, x1, y1, z1;
	ctx_t *ctx = core_get();
	dig_t c2, c3;
	bn_t k;

	bn_null(k);
	fp8_null(t);
	fp8_null(u);
	fp8_null(v);
	fp8_null(w);
	fp8_null(y);
	fp8_null(x1);
	fp8_null(y1);
	fp8_null(z1);

	RLC_TRY {
		bn_new(k);
		fp8_new(t);
		fp8_new(u);
		fp8_new(v);
		fp8_new(w);
		fp8_new(y);
		fp8_new(x1);
		fp8_new(y1);
		fp8_new(z1);

		md_xmd(r, 16 * elm + 1, msg, len, (const uint8_t *)"RELIC", 5);

		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				for (int l = 0; l < 2; l++) {
					bn_read_bin(k, r, elm);
					fp_prime_conv(u[i][j][l], k);
					r += elm;
					bn_read_bin(k, r, elm);
					fp_prime_conv(t[i][j][l], k);
					r += elm;
				}
			}
		}
		sign = r[0] & 1;
		r -= 16*elm;

		/* Assume that a = 0. */
		fp8_sqr(x1, u);
		fp8_mul(x1, x1, u);
		fp8_sqr(y1, t);
		fp8_add(x1, x1, ctx->ep8_b);
		fp8_sub(x1, x1, y1);
		fp8_dbl(y1, y1);
		fp8_add(y1, y1, x1);
		fp8_copy(z1, u);
		for (int i = 0; i < 2; i++) {
			for (int j = 0; j < 2; j++) {
				for (int l = 0; l < 2; l++) {
					fp_mul(z1[i][j][l], z1[i][j][l], ctx->ep_map_c[4]);
				}
			}
		}

		fp8_mul(x1, x1, z1);
		fp8_mul(z1, z1, t);
		fp8_dbl(z1, z1);

		fp8_dbl(y, y1);
		fp8_sqr(y, y);
		fp8_mul(v, y1, u);
		fp8_sub(v, x1, v);
		fp8_mul(v, v, z1);
		fp8_mul(w, y1, z1);
		fp8_dbl(w, w);

		if (fp8_is_zero(w)) {
			ep8_set_infty(p);
		} else {
			fp8_inv(w, w);
			fp8_mul(x1, v, w);
			fp8_add(y1, u, x1);
			fp8_neg(y1, y1);
			fp8_mul(z1, y, w);
			fp8_sqr(z1, z1);
			fp8_add(z1, z1, u);

			ep8_curve_get_b(w);

			fp8_sqr(t, x1);
			fp8_mul(t, t, x1);
			fp8_add(t, t, w);

			fp8_sqr(u, y1);
			fp8_mul(u, u, y1);
			fp8_add(u, u, w);

			fp8_sqr(v, z1);
			fp8_mul(v, v, z1);
			fp8_add(v, v, w);

			c2 = fp8_is_sqr(u);
			c3 = fp8_is_sqr(v);

			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					for (int l = 0; l < 2; l++) {
						dv_swap_cond(x1[i][j][l], y1[i][j][l], RLC_FP_DIGS, c2);
						dv_swap_cond(t[i][j][l], u[i][j][l], RLC_FP_DIGS, c2);
						dv_swap_cond(x1[i][j][l], z1[i][j][l], RLC_FP_DIGS, c3);
						dv_swap_cond(t[i][j][l], v[i][j][l], RLC_FP_DIGS, c3);
					}
				}
			}

			if (!fp8_srt(t, t)) {
				RLC_THROW(ERR_NO_VALID);
			}

			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					t0z = fp_is_zero(t[i][j][0]);
					fp_prime_back(k, t[i][j][0]);
					t0 = bn_get_bit(k, 0);
					fp_prime_back(k, t[i][j][1]);
					t1 = bn_get_bit(k, 0);
					/* t[0] == 0 ? sgn0(t[1]) : sgn0(t[0]) */
					s[i][j] = t0 | (t0z & t1);
				}

				t0z = fp4_is_zero(t[i]);
				sign ^= (s[i][0] | (t0z & s[i][1]));
			}

			fp8_neg(u, t);
			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					for (int l = 0; l < 2; l++) {
						dv_swap_cond(t[i][j][l], u[i][j][l], RLC_FP_DIGS, sign);
					}
				}
			}

			fp8_copy(p->x, x1);
			fp8_copy(p->y, t);
			fp8_set_dig(p->z, 1);
			p->coord = BASIC;

			ep8_mul_cof(p, p);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp8_free(t);
		fp8_free(u);
		fp8_free(v);
		fp8_free(w);
		fp8_free(y);
		fp8_free(x1);
		fp8_free(y1);
		fp8_free(z1);
		RLC_FREE(r);
	}
}
