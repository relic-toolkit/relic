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
 * Implementation of hashing to a prime elliptic curve over a quartic extension
 * field.
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
	fp4_t a, b, c, d, t, u, v, w, y, x1, y1, z1, den[3];
	ctx_t *ctx = core_get();
	bn_t k;

	bn_null(k);
	fp4_null(a);
	fp4_null(b);
	fp4_null(c);
	fp4_null(d);
	fp4_null(t);
	fp4_null(u);
	fp4_null(v);
	fp4_null(w);
	fp4_null(y);
	fp4_null(x1);
	fp4_null(y1);
	fp4_null(z1);
	fp4_null(den[0]);
	fp4_null(den[1]);
	fp4_null(den[2]);

	RLC_TRY {
		bn_new(k);
		fp4_new(a);
		fp4_new(b);
		fp4_new(c);
		fp4_new(d);
		fp4_new(t);
		fp4_new(u);
		fp4_new(v);
		fp4_new(w);
		fp4_new(y);
		fp4_new(x1);
		fp4_new(y1);
		fp4_new(z1);
		fp4_new(den[0]);
		fp4_new(den[1]);
		fp4_new(den[2]);

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

		if (ep_curve_opt_b() == RLC_ZERO) {
			fp4_sqr(a, u);
			fp4_sqr(b, a);
			fp4_mul(c, b, a);
			fp4_dbl(p->y, ep4_curve_get_a());
			fp4_dbl(p->y, p->y);
			fp4_sqr(p->z, p->y);
			fp4_mul(p->z, p->z, p->y);
			fp4_add(c, c, p->z);
			fp4_sqr(d, t);

			fp4_mul(v, a, d);
			fp4_mul(v, v, u);
			fp4_mul_dig(v, v, 24);
			fp_mul(v[0][0], v[0][0], core_get()->ep_map_c[4]);
			fp_mul(v[0][1], v[0][1], core_get()->ep_map_c[4]);
			fp_mul(v[1][0], v[1][0], core_get()->ep_map_c[4]);
			fp_mul(v[1][1], v[1][1], core_get()->ep_map_c[4]);

			fp4_zero(p->x);
			fp_sub_dig(p->x[0][0], core_get()->ep_map_c[4], 1);
			fp_hlv(p->x[0][0], p->x[0][0]);

			fp4_sqr(w, b);
			fp4_mul(y, v, a);
			fp4_mul(t, p->y, c);
			fp4_add(y, y, t);
			fp_mul(y[0][0], y[0][0], p->x[0][0]);
			fp_mul(y[0][1], y[0][1], p->x[0][0]);
			fp_mul(y[1][0], y[1][0], p->x[0][0]);
			fp_mul(y[1][1], y[1][1], p->x[0][0]);

			fp4_add(den[0], c, v);
			fp4_mul(den[0], den[0], u);
			fp_mul(den[0][0][0], den[0][0][0], core_get()->ep_map_c[4]);
			fp_mul(den[0][0][1], den[0][0][1], core_get()->ep_map_c[4]);
			fp_mul(den[0][1][0], den[0][1][0], core_get()->ep_map_c[4]);
			fp_mul(den[0][1][1], den[0][1][1], core_get()->ep_map_c[4]);
			fp4_mul(den[0], den[0], p->x);
			fp4_dbl(den[0], den[0]);
			fp4_neg(den[0], den[0]);
			fp4_mul(den[1], den[0], p->x);
			fp4_sub(den[2], a, p->y);
			fp4_sqr(den[2], den[2]);
			fp4_mul_dig(den[2], den[2], 216);
			fp4_dbl(den[2], den[2]);
			fp4_neg(den[2], den[2]);
			fp4_mul(den[2], den[2], b);
			fp4_mul(den[2], den[2], d);

			if (fp4_is_zero(den[0]) || fp4_is_zero(den[1]) || fp4_is_zero(den[2])) {
				ep4_set_infty(p);
			} else {
				fp4_inv_sim(den, den, 3);
				fp4_mul(t, a, p->z);
				fp4_mul(y1, p->y, v);
				fp4_add(y1, y1, t);
				fp4_add(y1, y1, w);
				fp_mul(z1[0][0], y[0][0], p->x[0][0]);
				fp_mul(z1[0][1], y[0][1], p->x[0][0]);
				fp_mul(z1[1][0], y[1][0], p->x[0][0]);
				fp_mul(z1[1][1], y[1][1], p->x[0][0]);
				fp4_add(x1, y1, z1);
				fp4_add(y1, y1, y);
				fp4_mul(z1, a, p->y);
				fp4_add(z1, z1, b);
				fp4_mul(z1, z1, p->y);
				fp4_dbl(p->x, z1);
				fp4_add(z1, z1, p->x);
				fp4_add(z1, z1, v);
				fp4_sub(z1, c, z1);
				fp4_mul(z1, z1, v);
				fp4_sqr(p->z, p->z);
				fp4_sub(z1, p->z, z1);
				fp4_add(w, w, t);
				fp4_add(w, w, t);
				fp4_mul(w, w, b);
				fp4_add(z1, z1, w);

				fp4_mul(x1, x1, den[0]);
				fp4_mul(y1, y1, den[1]);
				fp4_mul(z1, z1, den[2]);
				
				ep4_rhs(t, x1);
				ep4_rhs(u, y1);
				ep4_rhs(v, z1);

				int c2 = fp4_is_sqr(u);
				int c3 = fp4_is_sqr(v);

				fp4_copy_sec(t, u, c2);
				fp4_copy_sec(x1, y1, c2);
				fp4_copy_sec(t, v, c3);
				fp4_copy_sec(x1, z1, c3);

				if (!fp4_srt(t, t)) {
					RLC_THROW(ERR_NO_VALID);
				}
				fp4_neg(u, t);
				fp4_copy_sec(t, u, fp_is_even(t[0][0]) ^ sign);

				fp4_copy(p->x, x1);
				fp4_copy(p->y, t);
				fp4_set_dig(p->z, 1);
				p->coord = BASIC;
			}
		} else {
			if (ep_curve_opt_a() == RLC_ZERO) {
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

					ep4_rhs(t, x1);
					ep4_rhs(u, y1);
					ep4_rhs(v, z1);

					dig_t c2 = fp4_is_sqr(u);
					dig_t c3 = fp4_is_sqr(v);

					fp4_copy_sec(x1, y1, c2);
					fp4_copy_sec(t, u, c2);
					fp4_copy_sec(x1, z1, c3);
					fp4_copy_sec(t, v, c3);

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
					fp4_copy_sec(t, u, sign);

					fp4_copy(p->x, x1);
					fp4_copy(p->y, t);
					fp4_set_dig(p->z, 1);
					p->coord = BASIC;
				}
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
		fp4_free(b);
		fp4_free(c);
		fp4_free(d);
		fp4_free(t);
		fp4_free(u);
		fp4_free(v);
		fp4_free(w);
		fp4_free(y);
		fp4_free(x1);
		fp4_free(y1);
		fp4_free(z1);
		fp4_free(den[0]);
		fp4_free(den[1]);
		fp4_free(den[2]);
		RLC_FREE(h);
	}
}
