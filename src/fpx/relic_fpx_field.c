/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of configuration for prime field extensions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp2_field_get_qnr(void) {
#if FP_PRIME == 256
	/* The search below finds 2 + u, but keep 4 + u = c^2 + d^3 * u for
	 * c = 2, d = 1, as in "A family of implementation-friendly BN elliptic
	 * curves" by Pereira, Simplicio, Naehrig and Barreto. */
	return 4;
#else
	return core_get()->qnr2;
#endif
}

int fp3_field_get_cnr(void) {
#if FP_PRIME == 638
	if (fp_param_get() == K18_638) {
		return 8;
	} else {
		return 3;
	}
#elif FP_PRIME == 768
	return -4;
#endif
	return core_get()->cnr3;
}

void fp2_field_init(void) {
	bn_t e;
	fp2_t t0, t1, t2;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp2_null_all(t0, t1, t2);

	RLC_TRY {
		bn_new(e);
		fp2_new_all(t0, t1, t2);

		/* Start by finding a quadratic/cubic non-residue. */
#ifdef FP_QNRES
		ctx->qnr2 = 1;
#else
		if (fp_prime_get_mod8() % 4 == 1) {
			/* If p = 1 mod 4, fp2_mul_nor() always uses u, a non-square. */
			ctx->qnr2 = 0;
		} else {
			/* Otherwise, try (u + 1) and double the constant, as supported by
			 * fp2_mul_nor(). The non-residue must be a non-square, and also a
			 * non-cube if p = 1 mod 3 so that it defines cubic extensions. */
			ctx->qnr2 = 1;
			fp_set_dig(t0[0], ctx->qnr2);
			fp_set_dig(t0[1], 1);
			while (fp2_is_sqr(t0) ||
					(fp_prime_get_mod18() % 3 == 1 && fp2_is_cub(t0))) {
				ctx->qnr2 *= 2;
				if (util_bits_dig(ctx->qnr2) >= RLC_DIG - 1) {
					RLC_THROW(ERR_NO_VALID);
					break;
				}
				fp_set_dig(t0[0], ctx->qnr2);
			}
		}
#endif /* !FP_QNRES */

		/* Compute the constants g_j = QNR^floor(j * p / 6), such that the
		 * Frobenius maps x^j to g_j * x^(j * p mod 6) for x^6 = QNR, starting
		 * with g_1 = QNR^floor((p - 1) / 6). */
		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 6);
		fp2_exp(t0, t0, e);

		fp_copy(ctx->fp2_p1[0][0], t0[0]);
		fp_copy(ctx->fp2_p1[0][1], t0[1]);
		if (fp_prime_get_mod18() % 3 == 1) {
			/* For p = 1 mod 6, g_j = g_1^j. */
			fp2_sqr(t1, t0);
			fp_copy(ctx->fp2_p1[1][0], t1[0]);
			fp_copy(ctx->fp2_p1[1][1], t1[1]);
			fp2_mul(t1, t1, t0);
			fp_copy(ctx->fp2_p1[2][0], t1[0]);
			fp_copy(ctx->fp2_p1[2][1], t1[1]);
			fp2_sqr(t1, t0);
			fp2_sqr(t1, t1);
			fp_copy(ctx->fp2_p1[3][0], t1[0]);
			fp_copy(ctx->fp2_p1[3][1], t1[1]);
			fp2_mul(t1, t1, t0);
			fp_copy(ctx->fp2_p1[4][0], t1[0]);
			fp_copy(ctx->fp2_p1[4][1], t1[1]);

			/* Compute the norm z of g_1, a sixth root of unity in Fp that
			 * gives the constants of the even powers of Frobenius, and z^2. */
			fp2_frb(t1, t0, 1);
			fp2_mul(t1, t1, t0);
			fp_copy(ctx->fp2_p0[0], t1[0]);
			fp_sqr(ctx->fp2_p0[1], t1[0]);
		} else {
			/* For p = 5 mod 6, g_j = g_1^j * QNR^(j - 1). */
			fp2_set_dig(t2, 1);
			fp2_mul_nor(t2, t2);
			fp2_copy(t1, t0);
			for (int j = 1; j < 5; j++) {
				fp2_mul(t1, t1, t0);
				fp2_mul(t1, t1, t2);
				fp_copy(ctx->fp2_p1[j][0], t1[0]);
				fp_copy(ctx->fp2_p1[j][1], t1[1]);
			}

			/* The sixth root of unity z = g_1^p * g_5 of the even powers of
			 * Frobenius now lies in Fp^2, so store it and z^2 there. */
			fp2_frb(t2, t0, 1);
			fp2_mul(t2, t2, t1);
			fp_copy(ctx->fp2_pz[0][0], t2[0]);
			fp_copy(ctx->fp2_pz[0][1], t2[1]);
			fp2_sqr(t2, t2);
			fp_copy(ctx->fp2_pz[1][0], t2[0]);
			fp_copy(ctx->fp2_pz[1][1], t2[1]);
		}

		/* Compute QNR^(p - (p mod 4))/4. */
		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 4);
		fp2_exp(t0, t0, e);
		fp_copy(ctx->fp2_p2[0][0], t0[0]);
		fp_copy(ctx->fp2_p2[0][1], t0[1]);

		/* Compute QNR^(p - (p mod 8))/8. */
		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 8);
		fp2_exp(t0, t0, e);
		fp_copy(ctx->fp2_p2[1][0], t0[0]);
		fp_copy(ctx->fp2_p2[1][1], t0[1]);

		/* Compute QNR^(p - (p mod 12))/12. */
		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 12);
		fp2_exp(t0, t0, e);
		fp_copy(ctx->fp2_p2[2][0], t0[0]);
		fp_copy(ctx->fp2_p2[2][1], t0[1]);

		/* Compute QNR^(p - (p mod 24))/24. */
		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 24);
		fp2_exp(t0, t0, e);
		fp_copy(ctx->fp2_p2[3][0], t0[0]);
		fp_copy(ctx->fp2_p2[3][1], t0[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(e);
		fp2_free_all(t0, t1, t2);
	}
}

void fp3_field_init(void) {
	bn_t e;
	fp3_t t0, t1;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp3_null_all(t0, t1);

	RLC_TRY {
		bn_new(e);
		fp3_new_all(t0, t1);

		/* Compute t0 = u^((p - (p mod 3))/3). */
		if (fp_prime_get_cnr() < 0) {
			fp_set_dig(ctx->fp3_p0[0], -fp_prime_get_cnr());
			fp_neg(ctx->fp3_p0[0], ctx->fp3_p0[0]);
		} else {
			fp_set_dig(ctx->fp3_p0[0], fp_prime_get_cnr());
		}
		bn_read_raw(e, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 3);
		fp_exp(ctx->fp3_p0[0], ctx->fp3_p0[0], e);
		fp_sqr(ctx->fp3_p0[1], ctx->fp3_p0[0]);

		/* The non-residue (u + c) must be neither a square nor a cube in Fp^3,
		 * so that it defines both the cubic extension Fp^9 and the quadratic
		 * extension Fp^18 above it. The tests only need the Frobenius constant
		 * computed above. Start with u, then attempt (u + 1) and double. */
		ctx->cnr3 = 0;
		fp_zero(t0[0]);
		fp_set_dig(t0[1], 1);
		fp_zero(t0[2]);
		while (fp3_is_sqr(t0) || fp3_is_cub(t0)) {
			ctx->cnr3 = (ctx->cnr3 == 0 ? 1 : 2 * ctx->cnr3);
			if (util_bits_dig(ctx->cnr3) >= RLC_DIG - 1) {
				RLC_THROW(ERR_NO_VALID);
				break;
			}
			fp_set_dig(t0[0], ctx->cnr3);
		}

		/* Compute t0 = u^((p - (p mod 6))/6). */
		fp3_set_dig(t1, 1);
		fp3_mul_nor(t0, t1);
		bn_read_raw(e, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 6);
		fp3_exp(t0, t0, e);
		if (fp3_field_get_cnr() == 0) {
			/* Look for a non-trivial subfield element.. */
			ctx->frb3[0] = 0;
			while (ctx->frb3[0] < 3 && fp_is_zero(t0[ctx->frb3[0]++]));
			/* Fill rest of table with powers of constant. */
			fp_copy(ctx->fp3_p1[0][0], t0[--ctx->frb3[0] % 3]);
			fp3_sqr(t1, t0);
			fp_copy(ctx->fp3_p1[1][0], t1[(2 * ctx->frb3[0]) % 3]);
			fp3_mul(t1, t1, t0);
			fp_copy(ctx->fp3_p1[2][0], t1[(3 * ctx->frb3[0]) % 3]);
			fp3_sqr(t1, t0);
			fp3_sqr(t1, t1);
			fp_copy(ctx->fp3_p1[3][0], t1[(4 * ctx->frb3[0]) % 3]);
			fp3_mul(t1, t1, t0);
			fp_copy(ctx->fp3_p1[4][0], t1[(5 * ctx->frb3[0]) % 3]);
		} else {
			fp_copy(ctx->fp3_p1[0][0], t0[0]);
			fp_copy(ctx->fp3_p1[0][1], t0[1]);
			fp_copy(ctx->fp3_p1[0][2], t0[2]);
			fp3_sqr(t1, t0);
			fp_copy(ctx->fp3_p1[1][0], t1[0]);
			fp_copy(ctx->fp3_p1[1][1], t1[1]);
			fp_copy(ctx->fp3_p1[1][2], t1[2]);
			fp3_mul(t1, t1, t0);
			fp_copy(ctx->fp3_p1[2][0], t1[0]);
			fp_copy(ctx->fp3_p1[2][1], t1[1]);
			fp_copy(ctx->fp3_p1[2][2], t1[2]);
			fp3_sqr(t1, t0);
			fp3_sqr(t1, t1);
			fp_copy(ctx->fp3_p1[3][0], t1[0]);
			fp_copy(ctx->fp3_p1[3][1], t1[1]);
			fp_copy(ctx->fp3_p1[3][2], t1[2]);
			fp3_mul(t1, t1, t0);
			fp_copy(ctx->fp3_p1[4][0], t1[0]);
			fp_copy(ctx->fp3_p1[4][1], t1[1]);
			fp_copy(ctx->fp3_p1[4][2], t1[2]);
		}

		/* Compute t0 = u^((p - (p mod 9))/9). */
		fp3_set_dig(t1, 1);
		fp3_mul_nor(t0, t1);
		bn_read_raw(e, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 9);
		fp3_exp(t0, t0, e);
		/* Look for a non-trivial subfield element.. */
		if (fp3_field_get_cnr() == 0) {
			ctx->frb3[1] = 0;
			while (ctx->frb3[1] < 3 && fp_is_zero(t0[ctx->frb3[1]++]));
			fp_copy(ctx->fp3_p2[0][0], t0[--ctx->frb3[1]]);
		} else {
			fp_copy(ctx->fp3_p2[0][0], t0[0]);
			fp_copy(ctx->fp3_p2[0][1], t0[1]);
			fp_copy(ctx->fp3_p2[0][2], t0[2]);
		}

		/* Compute t0 = u^((p - (p mod 18))/18). */
		fp3_set_dig(t1, 1);
		fp3_mul_nor(t0, t1);
		bn_read_raw(e, fp_prime_get(), RLC_FP_DIGS);
		bn_div_dig(e, e, 18);
		fp3_exp(t0, t0, e);
		/* Look for a non-trivial subfield element.. */
		if (fp3_field_get_cnr() == 0) {
			ctx->frb3[2] = 0;
			while (ctx->frb3[2] < 3 && fp_is_zero(t0[ctx->frb3[2]++]));
			fp_copy(ctx->fp3_p2[1][0], t0[--ctx->frb3[2]]);
		} else {
			fp_copy(ctx->fp3_p2[1][0], t0[0]);
			fp_copy(ctx->fp3_p2[1][1], t0[1]);
			fp_copy(ctx->fp3_p2[1][2], t0[2]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(e);
		fp3_free_all(t0, t1);
	}
}

void fp4_field_init(void) {
	bn_t e;
	fp4_t t0;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp4_null(t0);

	RLC_TRY {
		bn_new(e);
		fp4_new(t0);

		fp4_set_dig(t0, 1);
		fp4_mul_art(t0, t0);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 6);
		fp4_exp(t0, t0, e);
		if (fp2_is_zero(t0[1])) {
			ctx->frb4 = 0;
			fp_copy(ctx->fp4_p1[0], t0[0][0]);
			fp_copy(ctx->fp4_p1[1], t0[0][1]);
		} else {
			ctx->frb4 = 1;
			fp_copy(ctx->fp4_p1[0], t0[1][0]);
			fp_copy(ctx->fp4_p1[1], t0[1][1]);
		}
	} RLC_CATCH_ANY {
	    RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(e);
		fp4_free(t0);
	}
}

void fp8_field_init(void) {
	bn_t e;
	fp8_t t0;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp8_null(t0);

	RLC_TRY {
		bn_new(e);
		fp8_new(t0);

		fp8_set_dig(t0, 1);
		fp8_mul_art(t0, t0);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 6);
		fp8_exp(t0, t0, e);
		if (fp4_is_zero(t0[1])) {
			ctx->frb8 = 0;
			fp_copy(ctx->fp8_p1[0], t0[0][0][0]);
			fp_copy(ctx->fp8_p1[1], t0[0][0][1]);
		} else {
			ctx->frb8 = 1;
			fp_copy(ctx->fp8_p1[0], t0[1][1][0]);
			fp_copy(ctx->fp8_p1[1], t0[1][1][1]);
		}
	} RLC_CATCH_ANY {
	    RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(e);
		fp8_free(t0);
	}
}
