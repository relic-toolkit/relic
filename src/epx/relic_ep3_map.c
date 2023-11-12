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

void ep3_map(ep3_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t t0z, t0, t1, t1z, t2, sign, *r = RLC_ALLOCA(uint8_t, 6 * elm + 1);
	fp3_t t, u, v, w, y, x1, y1, z1;
	ctx_t *ctx = core_get();
	dig_t c2, c3;
	bn_t k;

	bn_null(k);
	fp3_null(t);
	fp3_null(u);
	fp3_null(v);
	fp3_null(w);
	fp3_null(y);
	fp3_null(x1);
	fp3_null(y1);
	fp3_null(z1);

	RLC_TRY {
		bn_new(k);
		fp3_new(t);
		fp3_new(u);
		fp3_new(v);
		fp3_new(w);
		fp3_new(y);
		fp3_new(x1);
		fp3_new(y1);
		fp3_new(z1);

		md_xmd(r, 6 * elm + 1, msg, len, (const uint8_t *)"RELIC", 5);

		for (int i = 0; i < 3; i++) {
			bn_read_bin(k, r, elm);
			fp_prime_conv(u[i], k);
			r += elm;
			bn_read_bin(k, r, elm);
			fp_prime_conv(t[i], k);
			r += elm;
		}
		sign = r[0] & 1;
		r -= 6*elm;

		/* Assume that a = 0. */
		fp3_sqr(x1, u);
		fp3_mul(x1, x1, u);
		fp3_sqr(y1, t);
		fp3_add(x1, x1, ctx->ep3_b);
		fp3_sub(x1, x1, y1);
		fp3_dbl(y1, y1);
		fp3_add(y1, y1, x1);
		fp3_copy(z1, u);
		fp_mul(z1[0], z1[0], ctx->ep_map_c[4]);
		fp_mul(z1[1], z1[1], ctx->ep_map_c[4]);
		fp_mul(z1[2], z1[2], ctx->ep_map_c[4]);
		fp3_mul(x1, x1, z1);
		fp3_mul(z1, z1, t);
		fp3_dbl(z1, z1);

		fp3_dbl(y, y1);
		fp3_sqr(y, y);
		fp3_mul(v, y1, u);
		fp3_sub(v, x1, v);
		fp3_mul(v, v, z1);
		fp3_mul(w, y1, z1);
		fp3_dbl(w, w);

		if (fp3_is_zero(w)) {
			ep3_set_infty(p);
		} else {
			fp3_inv(w, w);
			fp3_mul(x1, v, w);
			fp3_add(y1, u, x1);
			fp3_neg(y1, y1);
			fp3_mul(z1, y, w);
			fp3_sqr(z1, z1);
			fp3_add(z1, z1, u);

			ep3_curve_get_b(w);

			fp3_sqr(t, x1);
			fp3_mul(t, t, x1);
			fp3_add(t, t, w);

			fp3_sqr(u, y1);
			fp3_mul(u, u, y1);
			fp3_add(u, u, w);

			fp3_sqr(v, z1);
			fp3_mul(v, v, z1);
			fp3_add(v, v, w);

			c2 = fp3_is_sqr(u);
			c3 = fp3_is_sqr(v);

			for (int i = 0; i < 3; i++) {
				dv_swap_cond(x1[i], y1[i], RLC_FP_DIGS, c2);
				dv_swap_cond(t[i], u[i], RLC_FP_DIGS, c2);
				dv_swap_cond(x1[i], z1[i], RLC_FP_DIGS, c3);
				dv_swap_cond(t[i], v[i], RLC_FP_DIGS, c3);
			}

			if (!fp3_srt(t, t)) {
				RLC_THROW(ERR_NO_VALID);
			}

			t0z = fp_is_zero(t[0]);
			fp_prime_back(k, t[0]);
			t0 = bn_get_bit(k, 0);
			t1z = fp_is_zero(t[1]);
			fp_prime_back(k, t[1]);
			t1 = bn_get_bit(k, 0);
			fp_prime_back(k, t[2]);
			t2 = bn_get_bit(k, 0);

			/* t[0] == 0 ? sgn0(t[1]) : sgn0(t[0]) */
			sign ^= (t0 | (t0z & (t1 | (t1z & t2))));

			fp3_neg(u, t);
			dv_swap_cond(t[0], u[0], RLC_FP_DIGS, sign);
			dv_swap_cond(t[1], u[1], RLC_FP_DIGS, sign);
			dv_swap_cond(t[2], u[2], RLC_FP_DIGS, sign);

			fp3_copy(p->x, x1);
			fp3_copy(p->y, t);
			fp3_set_dig(p->z, 1);
			p->coord = BASIC;

			ep3_mul_cof(p, p);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp3_free(t);
		fp3_free(u);
		fp3_free(v);
		fp3_free(w);
		fp3_free(y);
		fp3_free(x1);
		fp3_free(y1);
		fp3_free(z1);
		RLC_FREE(r);
	}
}
