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

int fp2_field_get_qnr() {
	/* Override some of the results when cubic non-residue is also needed. */
#if FP_PRIME == 1150
	return 32;
#elif FP_PRIME == 158 || FP_PRIME == 256
	return 4;
#elif defined(EP_SUPER) && FP_PRIME == 382
	return 8;
#elif FP_PRIME == 446 && !defined(FP_QNRES)
	return 16;
#else
	return core_get()->qnr2;
#endif
}

int fp3_field_get_cnr() {
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
	fp2_t t0, t1;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp2_null(t0);
	fp2_null(t1);

	RLC_TRY {
		bn_new(e);
		fp2_new(t0);
		fp2_new(t1);

		/* Start by finding a quadratic/cubic non-residue. */
#ifdef FP_QNRES
		ctx->qnr2 = 1;
#else
		/* First start with u as quadratic non-residue. */
		ctx->qnr2 = 0;
		fp_zero(t0[0]);
		fp_set_dig(t0[1], 1);
		/* If it does not work, attempt (u + 1), otherwise double. */
		/* We cannot used QR test here due to Frobenius constants below. */
		if (fp2_srt(t1, t0)) {
			ctx->qnr2 = 1;
			fp_set_dig(t0[0], ctx->qnr2);
			while (fp2_srt(t1, t0) && util_bits_dig(ctx->qnr2) < RLC_DIG - 1) {
				/* Pick a power of 2 for efficiency. */
				ctx->qnr2 *= 2;
				fp_set_dig(t0[0], ctx->qnr2);
			}
		}
#endif /* !FP_QNRES */

		/* Compute QNR^(p - 1)/6 and consecutive powers. */
		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 6);
		fp2_exp(t0, t0, e);

		fp_copy(ctx->fp2_p1[0][0], t0[0]);
		fp_copy(ctx->fp2_p1[0][1], t0[1]);
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
		fp2_free(t0);
		fp2_free(t1);
	}
}

void fp3_field_init(void) {
	bn_t e;
	fp3_t t0, t1;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp3_null(t0);
	fp3_null(t1);

	RLC_TRY {
		bn_new(e);
		fp3_new(t0);
		fp3_new(t1);

		/* Start by trying a trivial quadratic non-residue. */
		ctx->cnr3 = 0;
		fp_zero(t0[0]);
		fp_set_dig(t0[1], 1);
		fp_zero(t0[2]);
		/* If it does not work, attempt (u + 1), otherwise double. */
		/* This code will fail if p \neq 1 mod 8 because square root in Fp^3
		 * relies on Frobenius. Must implement explicit test for those cases. */
		if (fp3_srt(t1, t0)) {
			ctx->cnr3 = 1;
			fp_set_dig(t0[0], ctx->cnr3);
			while (fp3_srt(t1, t0) && util_bits_dig(ctx->qnr2) < RLC_DIG - 1) {
				/* Pick a power of 2 for efficiency. */
				ctx->cnr3 *= 2;
				fp_set_dig(t0[0], ctx->cnr3);
			}
		}

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
		fp3_free(t0);
		fp3_free(t1);
	}
}

void fp4_field_init() {
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

void fp8_field_init() {
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
