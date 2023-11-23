/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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

void ep4_map(ep4_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t t0z, t0, t1, s[2], sign, *h = RLC_ALLOCA(uint8_t, 8 * elm + 1);
	fp4_t a, c, t, u, v, w, y, x1, y1, z1;
	ctx_t *ctx = core_get();
	bn_t k;

	bn_null(k);
	fp4_null(a);
	fp4_null(c);
	fp4_null(t);
	fp4_null(u);
	fp4_null(v);
	fp4_null(w);
	fp4_null(y);
	fp4_null(x1);
	fp4_null(y1);
	fp4_null(z1);

	RLC_TRY {
		bn_new(k);
		fp4_new(a);
		fp4_new(c);
		fp4_new(t);
		fp4_new(u);
		fp4_new(v);
		fp4_new(w);
		fp4_new(y);
		fp4_new(x1);
		fp4_new(y1);
		fp4_new(z1);

		if (ep4_curve_opt_b() == RLC_ZERO) {
			/* This is the approach due to Koshelev introduced in
			 * https://eprint.iacr.org/2021/1034.pdf */
			
			md_xmd(h, 4 * elm + 1, msg, len, (const uint8_t *)"RELIC", 5);
			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					bn_read_bin(k, h, elm);
					fp_prime_conv(u[i][j], k);
					h += elm;
				}
			}
			h -= 4*elm;

			/* Compute c = 3*a^2, t^2 = 6a(9u^5 − 14au^3 + 3cu).*/
			ep4_curve_get_a(a);
			fp4_neg(a, a);
			fp4_sqr(c, a);
			fp4_dbl(t, c);
			fp4_add(c, c, t);
			fp4_dbl(t, c);
			fp4_add(t, t, c);
			fp4_mul(t, t, u);

			fp4_sqr(v, u);
			fp4_mul(w, v, u);
			fp4_mul(x1, w, a);
			fp4_mul_dig(x1, x1, 14);
			fp4_sub(t, t, x1);

			fp4_mul(w, w, v);
			fp4_dbl(x1, w);
			fp4_add(w, w, x1);
			fp4_dbl(x1, w);
			fp4_add(w, w, x1);
			fp4_add(t, t, w);
			fp4_mul(t, t, a);
			fp4_dbl(t, t);
			fp4_dbl(x1, t);
			fp4_add(t, t, x1);
			dig_t c1 = fp4_is_sqr(t);
			/* If t is not square, compute u = a/u, t = a*sqrt(a*t)/u^3*/
			fp4_inv(x1, u);
			fp4_mul(y1, t, a);
			/* If t is a square, extract its square root. */
			dv_copy_cond(t[0][0], y1[0][0], RLC_FP_DIGS, !c1);
			dv_copy_cond(t[0][1], y1[0][1], RLC_FP_DIGS, !c1);
			dv_copy_cond(t[1][0], y1[1][0], RLC_FP_DIGS, !c1);
			dv_copy_cond(t[1][1], y1[1][1], RLC_FP_DIGS, !c1);
			fp4_srt(t, t);
			fp4_mul(y1, t, a);
			fp4_sqr(y, x1);
			fp4_mul(y, y, x1);
			fp4_mul(y1, y1, y);
			fp4_mul(x1, x1, a);
			dv_copy_cond(u[0][0], x1[0][0], RLC_FP_DIGS, !c1);
			dv_copy_cond(u[0][1], x1[0][1], RLC_FP_DIGS, !c1);
			dv_copy_cond(u[1][0], x1[1][0], RLC_FP_DIGS, !c1);
			dv_copy_cond(u[1][1], x1[1][1], RLC_FP_DIGS, !c1);
			dv_copy_cond(t[0][0], y1[0][0], RLC_FP_DIGS, !c1);
			dv_copy_cond(t[0][1], y1[0][1], RLC_FP_DIGS, !c1);
			dv_copy_cond(t[1][0], y1[1][0], RLC_FP_DIGS, !c1);
			dv_copy_cond(t[1][1], y1[1][1], RLC_FP_DIGS, !c1);

			/* Compute x = 2^4*i*3*a^2*u / (3*(3*u^2 - a))^2. */
			fp4_zero(y);
			fp_copy(y[0][0], ctx->ep_map_c[6]);
			fp4_mul(c, c, u);
			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					fp_mul(x1[i][j], c[i][j], y[0][0]);
				}
			}
			fp4_dbl(x1, x1);
			fp4_dbl(x1, x1);
			fp4_dbl(x1, x1);
			fp4_dbl(p->x, x1);
			fp4_sqr(v, u);
			fp4_dbl(z1, v);
			fp4_add(z1, z1, v);
			fp4_sub(z1, z1, a);
			fp4_dbl(p->z, z1);
			fp4_add(p->z, p->z, z1);

			/* Compute y = 3*2*(i-1)*a*(3^2*u^2 + a)*t / (3*(3*u^2 - a))^3. */
			fp_sub_dig(y[0][0], y[0][0], 1);
			fp4_mul(y1, y, a);
			fp4_dbl(y1, y1);
			fp4_dbl(p->y, y1);
			fp4_add(p->y, p->y, y1);
			fp4_mul(p->y, p->y, t);
			fp4_dbl(y1, v);
			fp4_add(y1, y1, v);
			fp4_dbl(v, y1);
			fp4_add(y1, y1, v);
			fp4_add(y1, y1, a);
			fp4_mul(p->y, p->y, y1);

			/* Multiply by cofactor. */
			p->coord = JACOB;
			ep4_norm(p, p);
		}

		if (ep_curve_opt_a() == RLC_ZERO) {
			md_xmd(h, 8 * elm + 1, msg, len, (const uint8_t *)"RELIC", 5);			
			for (int i = 0; i < 2; i++) {
				for (int j = 0; j < 2; j++) {
					bn_read_bin(k, h, elm);
					fp_prime_conv(u[i][j], k);
					h += elm;
					bn_read_bin(k, h, elm);
					fp_prime_conv(t[i][j], k);
					h += elm;
				}
			}
			sign = h[0] & 1;
			h -= 8*elm;

			fp4_sqr(x1, u);
			fp4_mul(x1, x1, u);
			fp4_sqr(y1, t);
			fp4_add(x1, x1, ctx->ep4_b);
			fp4_sub(x1, x1, y1);
			fp4_dbl(y1, y1);
			fp4_add(y1, y1, x1);
			fp4_copy(z1, u);
			fp_mul(z1[0][0], z1[0][0], ctx->ep_map_c[4]);
			fp_mul(z1[0][1], z1[0][1], ctx->ep_map_c[4]);
			fp_mul(z1[1][0], z1[1][0], ctx->ep_map_c[4]);
			fp_mul(z1[1][1], z1[1][1], ctx->ep_map_c[4]);
			fp4_mul(x1, x1, z1);
			fp4_mul(z1, z1, t);
			fp4_dbl(z1, z1);

			fp4_dbl(y, y1);
			fp4_sqr(y, y);
			fp4_mul(v, y1, u);
			fp4_sub(v, x1, v);
			fp4_mul(v, v, z1);
			fp4_mul(w, y1, z1);
			fp4_dbl(w, w);

			if (fp4_is_zero(w)) {
				ep4_set_infty(p);
			} else {
				fp4_inv(w, w);
				fp4_mul(x1, v, w);
				fp4_add(y1, u, x1);
				fp4_neg(y1, y1);
				fp4_mul(z1, y, w);
				fp4_sqr(z1, z1);
				fp4_add(z1, z1, u);

				ep4_curve_get_b(w);

				fp4_sqr(t, x1);
				fp4_mul(t, t, x1);
				fp4_add(t, t, w);

				fp4_sqr(u, y1);
				fp4_mul(u, u, y1);
				fp4_add(u, u, w);

				fp4_sqr(v, z1);
				fp4_mul(v, v, z1);
				fp4_add(v, v, w);

				dig_t c2 = fp4_is_sqr(u);
				dig_t c3 = fp4_is_sqr(v);

				for (int i = 0; i < 2; i++) {
					for (int j = 0; j < 2; j++) {
						dv_swap_cond(x1[i][j], y1[i][j], RLC_FP_DIGS, c2);
						dv_swap_cond(t[i][j], u[i][j], RLC_FP_DIGS, c2);
						dv_swap_cond(x1[i][j], z1[i][j], RLC_FP_DIGS, c3);
						dv_swap_cond(t[i][j], v[i][j], RLC_FP_DIGS, c3);
					}
				}

				if (!fp4_srt(t, t)) {
					RLC_THROW(ERR_NO_VALID);
				}

				for (int i = 0; i < 2; i++) {
					t0z = fp_is_zero(t[i][0]);
					fp_prime_back(k, t[i][0]);
					t0 = bn_get_bit(k, 0);
					fp_prime_back(k, t[i][1]);
					t1 = bn_get_bit(k, 0);
					/* t[0] == 0 ? sgn0(t[1]) : sgn0(t[0]) */
					s[i] = t0 | (t0z & t1);
				}

				t0z = fp2_is_zero(t[0]);
				sign ^= (s[0] | (t0z & s[1]));

				fp4_neg(u, t);
				dv_swap_cond(t[0][0], u[0][0], RLC_FP_DIGS, sign);
				dv_swap_cond(t[0][1], u[0][1], RLC_FP_DIGS, sign);
				dv_swap_cond(t[1][0], u[1][0], RLC_FP_DIGS, sign);
				dv_swap_cond(t[1][1], u[1][1], RLC_FP_DIGS, sign);

				fp4_copy(p->x, x1);
				fp4_copy(p->y, t);
				fp4_set_dig(p->z, 1);
				p->coord = BASIC;
			}
		}
		
		ep4_mul_cof(p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp4_free(a);
		fp4_free(c);
		fp4_free(t);
		fp4_free(u);
		fp4_free(v);
		fp4_free(w);
		fp4_free(y);
		fp4_free(x1);
		fp4_free(y1);
		fp4_free(z1);
		RLC_FREE(h);
	}
}
