/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the prime field prime manipulation functions.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_ep.h"
#include "relic_fpx.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Assigns the prime field modulus.
 *
 * @param[in] p			- the new prime field modulus.
 */
static void fp_prime_set(const bn_t p) {
	bn_t t;
	fp_t r;
	ctx_t *ctx = core_get();
	dig_t rem;

	if (p->used != RLC_FP_DIGS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_null(t);
	fp_null(r);

	RLC_TRY {
		bn_new(t);
		fp_new(r);

		bn_copy(&(ctx->prime), p);

#if FP_RDC == MONTY || !defined(STRIP)

		bn_mod_pre_monty(t, &(ctx->prime));
		ctx->u = t->dp[0];

		/* compute R mod p */
		bn_set_2b(&(ctx->one), ctx->prime.used * RLC_DIG);
		bn_mod(&(ctx->one), &(ctx->one), &(ctx->prime));

		/* compute the R^2 mod p */
		fp_add(r, ctx->one.dp, ctx->one.dp);
		bn_set_dig(t, RLC_FP_DIGS);
		bn_lsh(t, t, RLC_DIG_LOG);
		fp_exp(ctx->conv.dp, r, t);
		ctx->conv.used = RLC_FP_DIGS;
		bn_trim(&(ctx->conv));

#endif /* FP_RDC == MONTY */

#if FP_INV == JMPDS || !defined(STRIP)

		int d = (45907 * FP_PRIME + 26313) / 19929;

#if WSIZE == 8
		bn_set_dig(t, d >> 8);
		bn_lsh(t, t, 8);
		bn_add_dig(t, t, d & 0xFF);
#else
		bn_set_dig(t, d);
#endif
		ctx->inv.used = RLC_FP_DIGS;
		dv_copy(ctx->inv.dp, fp_prime_get(), RLC_FP_DIGS);
		fp_add_dig(ctx->inv.dp, ctx->inv.dp, 1);
		fp_hlv(ctx->inv.dp, ctx->inv.dp);
		fp_exp(ctx->inv.dp, ctx->inv.dp, t);

#if FP_RDC == MONTY

#ifdef RLC_FP_ROOM
		fp_mul(ctx->inv.dp, ctx->inv.dp, ctx->conv.dp);
		fp_mul(ctx->inv.dp, ctx->inv.dp, ctx->conv.dp);

		for (int i = 1, j = 0; i < d / (RLC_DIG - 2); i++) {
			j = i % RLC_FP_DIGS;
			if (j == 0) {
				fp_mulm_low(ctx->inv.dp, ctx->inv.dp, ctx->conv.dp);
			}
		}
#endif

#endif /* FP_RDC == MONTY */

#endif /* FP_INV */

		/* Now look for proper quadratic/cubic non-residues. */
		ctx->qnr = ctx->cnr = 0;
		bn_mod_dig(&(ctx->mod8), &(ctx->prime), 8);
		bn_mod_dig(&(ctx->mod18), &(ctx->prime), 18);

		switch (ctx->mod8) {
			case 3:
				ctx->qnr = -1;
				ctx->cnr = 2;
				break;
			case 7:
				ctx->qnr = -1;
				/* Try this one, pick another later if not a CNR. */
				ctx->cnr = -2;
				break;
			case 1:
			case 5:
				ctx->qnr = -2;
				ctx->cnr = 2;
#if FP_PRIME == 638
				if (fp_param_get() == K18_638) {
					ctx->qnr = -6;
				} else {
					ctx->qnr = -7;
				}
#endif
				break;
		}

		/* Check if qnr is a quadratic non-residue or find another. */
		fp_set_dig(r, -ctx->qnr);
		fp_neg(r, r);
		while (fp_is_sqr(r)) {
			ctx->qnr--;
			fp_set_dig(r, -ctx->qnr);
			fp_neg(r, r);
		};

		/* Check if cnr is a cubic non-residue or find another. */
		if (ctx->mod18 % 3 == 1) {
			if (ctx->cnr > 0) {
				fp_set_dig(r, ctx->cnr);
				while (fp_is_cub(r)) {
					ctx->cnr++;
					fp_set_dig(r, ctx->cnr);
				};
			} else {
				fp_set_dig(r, -ctx->cnr);
				fp_neg(r, r);
				while (fp_is_cub(r)) {
					ctx->cnr--;
					fp_set_dig(r, -ctx->cnr);
					fp_neg(r, r);
				};
			}
		} else {
			ctx->cnr = 0;
		}

#ifdef FP_QNRES
		if (ctx->mod8 != 3) {
			RLC_THROW(ERR_NO_VALID);
		}
#endif

		/* Compute root of unity by computing QNR to (p - 1)/2^f. */
		ctx->ad2 = 0;
		bn_sub_dig(t, p, 1);
		while (bn_is_even(t)) {
			ctx->ad2++;
			bn_hlv(t, t);
		}

		ctx->srt.used = RLC_FP_DIGS;
		if (ctx->qnr < 0) {
			fp_set_dig(ctx->srt.dp, -ctx->qnr);
		} else {
			fp_set_dig(ctx->srt.dp, ctx->qnr);
		}
		fp_exp(ctx->srt.dp, ctx->srt.dp, t);

		/* Write p - 1 as (e * 3^f), with e = 3l \pm 1. */
		bn_sub_dig(t, p, 1);
		bn_mod_dig(&rem, t, 3);
		while (rem == 0) {
			bn_div_dig(t, t, 3);
			bn_mod_dig(&rem, t, 3);
		}

		/* Compute root of unity by computing CNR to (p - 1)/3^f. */
		if (ctx->cnr < 0) {
			fp_set_dig(ctx->crt.dp, -fp_prime_get_cnr());
		} else {
			fp_set_dig(ctx->crt.dp, fp_prime_get_cnr());
		}
		fp_exp(ctx->crt.dp, ctx->crt.dp, t);

		fp_prime_calc();
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		fp_free(r);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_prime_init(void) {
	ctx_t *ctx = core_get();
	ctx->fp_id = 0;
	bn_make(&(ctx->prime), RLC_FP_DIGS);
	bn_make(&(ctx->par), RLC_FP_DIGS);
#if FP_RDC == QUICK || !defined(STRIP)
	ctx->sps_len = 0;
	memset(ctx->sps, 0, sizeof(ctx->sps));
#endif
#if FP_RDC == MONTY || !defined(STRIP)
	bn_make(&(ctx->conv), RLC_FP_DIGS);
	bn_make(&(ctx->one), RLC_FP_DIGS);
#endif
#if FP_INV == JMPDS || !defined(STRIP)
	bn_make(&(ctx->inv), RLC_FP_DIGS);
#endif /* FP_INV */
	bn_make(&(ctx->srt), RLC_FP_DIGS);
	bn_make(&(ctx->crt), RLC_FP_DIGS);
}

void fp_prime_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
		ctx->fp_id = 0;
#if FP_RDC == QUICK || !defined(STRIP)
		ctx->sps_len = 0;
		memset(ctx->sps, 0, sizeof(ctx->sps));
#endif
#if FP_RDC == MONTY || !defined(STRIP)
		bn_clean(&(ctx->one));
		bn_clean(&(ctx->conv));
#endif
#if FP_INV == JMPDS || !defined(STRIP)
		bn_clean(&(ctx->inv));
#endif /* FP_INV */
		bn_clean(&(ctx->srt));
		bn_clean(&(ctx->crt));
		bn_clean(&(ctx->prime));
		bn_clean(&(ctx->par));
	}
}

const dig_t *fp_prime_get(void) {
	return core_get()->prime.dp;
}

const dig_t *fp_prime_get_rdc(void) {
	return &(core_get()->u);
}

void fp_prime_get_par(bn_t x) {
	bn_copy(x, &(core_get()->par));
}

const int *fp_prime_get_par_sps(int *len) {
	ctx_t *ctx = core_get();
	if (ctx->par_len > 0) {
		if (len != NULL) {
			*len = ctx->par_len;
		}
		return ctx->par_sps;
	}
	if (len != NULL) {
		*len = 0;
	}
	return NULL;
}

const int *fp_prime_get_sps(int *len) {
#if FP_RDC == QUICK || !defined(STRIP)
	ctx_t *ctx = core_get();
	if (ctx->sps_len > 0 && ctx->sps_len < RLC_TERMS) {
		if (len != NULL) {
			*len = ctx->sps_len;
		}
		return ctx->sps;
	} else {
		if (len != NULL) {
			*len = 0;
		}
		return NULL;
	}
#else
	return NULL;
#endif
}

const dig_t *fp_prime_get_conv(void) {
#if FP_RDC == MONTY || !defined(STRIP)
	return core_get()->conv.dp;
#else
	return NULL;
#endif
}

const dig_t *fp_prime_get_srt(void) {
	return core_get()->srt.dp;
}

const dig_t *fp_prime_get_crt(void) {
	return core_get()->crt.dp;
}

dig_t fp_prime_get_mod8(void) {
	return core_get()->mod8;
}

dig_t fp_prime_get_mod18(void) {
	return core_get()->mod18;
}

int fp_prime_get_qnr(void) {
	return core_get()->qnr;
}

int fp_prime_get_cnr(void) {
	return core_get()->cnr;
}

int fp_prime_get_2ad(void) {
	return core_get()->ad2;
}

void fp_prime_set_dense(const bn_t p) {
	fp_prime_set(p);
#if FP_RDC == QUICK
	RLC_THROW(ERR_NO_CONFIG);
#endif
}

void fp_prime_set_pairf(const bn_t x, int pairf) {
	bn_t p, t0, t1;
	ctx_t *ctx = core_get();
	size_t len = bn_bits(x) + 1;
	int8_t s[RLC_FP_BITS + 1];

	bn_null(p);
	bn_null(t0);
	bn_null(t1);

	RLC_TRY {
		bn_new(p);
		bn_new(t0);
		bn_new(t1);

		bn_copy(&(ctx->par), x);
		bn_copy(t0, x);

		switch (pairf) {
			case EP_BN:
				/* p = 36 * x^4 + 36 * x^3 + 24 * x^2 + 6 * x + 1. */
				bn_set_dig(p, 1);
				bn_mul_dig(t1, t0, 6);
				bn_add(p, p, t1);
				bn_mul(t1, t0, t0);
				bn_mul_dig(t1, t1, 24);
				bn_add(p, p, t1);
				bn_mul(t1, t0, t0);
				bn_mul(t1, t1, t0);
				bn_mul_dig(t1, t1, 36);
				bn_add(p, p, t1);
				bn_mul(t0, t0, t0);
				bn_mul(t1, t0, t0);
				bn_mul_dig(t1, t1, 36);
				bn_add(p, p, t1);
				fp_prime_set_dense(p);
				break;
			case EP_B12:
				/* p = (x^2 - 2x + 1) * (x^4 - x^2 + 1)/3 + x. */
				bn_sqr(t1, t0);
				bn_sqr(p, t1);
				bn_sub(p, p, t1);
				bn_add_dig(p, p, 1);
				bn_sub(t1, t1, t0);
				bn_sub(t1, t1, t0);
				bn_add_dig(t1, t1, 1);
				bn_mul(p, p, t1);
				bn_div_dig(p, p, 3);
				bn_add(p, p, t0);
				fp_prime_set_dense(p);
				break;
			case EP_N16:
				/* p = (x^16 + 2*x^13 + x^10 + 5*x^8 + 6*x^5 + x^2 + 4)/4 */
				bn_sqr(p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 2);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 1);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 5);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 6);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 1);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 4);
				bn_div_dig(p, p, 4);
				fp_prime_set_dense(p);
				break;
			case EP_FM16:
				/* p = (x^16 + x^10 + 5*x^8 + x^2 + 4*x + 4)/4 */
				bn_sqr(t1, t0);
				bn_mul(p, t1, t0);
				bn_sqr(p, p);
				bn_add_dig(p, p, 1);
				bn_mul(p, p, t1);
				bn_add_dig(p, p, 5);
				bn_mul(p, p, t1);
				bn_mul(p, p, t1);
				bn_mul(p, p, t1);
				bn_add_dig(p, p, 1);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 4);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 4);
				bn_div_dig(p, p, 4);
				fp_prime_set_dense(p);
				break;
			case EP_K16:
				/* p = (u^10 + 2*u^9 + 5*u^8 + 48*u^6 + 152*u^5 + 240*u^4 +
						625*u^2 + 2398*u + 3125) div 980 */
				bn_add_dig(p, t0, 2);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 5);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 48);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 152);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 240);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 256);
				bn_add_dig(p, p, 256);
				bn_add_dig(p, p, 113);
				bn_mul(p, p, t0);
				bn_set_dig(t1, 9);
				bn_lsh(t1, t1, 8);
				bn_add_dig(t1, t1, 94);
				bn_add(p, p, t1);
				bn_mul(p, p, t0);
				bn_set_dig(t0, 12);
				bn_lsh(t0, t0, 8);
				bn_add_dig(t0, t0, 53);
				bn_add(p, p, t0);
				bn_set_dig(t1, 3);
				bn_lsh(t1, t1, 8);
				bn_add_dig(t1, t1, 212);
 				bn_div(p, p, t1);
 				fp_prime_set_dense(p);
 				break;
			case EP_K18:
				/* p = (x^8 + 5x^7 + 7x^6 + 37x^5 + 188x^4 + 259x^3 + 343x^2 +
				       1763x + 2401)/21 */
				bn_add_dig(p, t0, 5);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 7);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 37);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 188);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 256);
				bn_add_dig(p, p, 3);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 256);
				bn_add_dig(p, p, 87);
				bn_mul(p, p, t0);
				bn_set_dig(t1, 6);
				bn_lsh(t1, t1, 8);
				bn_add_dig(t1, t1, 227);
				bn_add(p, p, t1);
				bn_mul(p, p, t0);
				bn_set_dig(t0, 9);
				bn_lsh(t0, t0, 8);
				bn_add_dig(t0, t0, 97);
				bn_add(p, p, t0);
 				bn_div_dig(p, p, 21);
 				fp_prime_set_dense(p);
 				break;
			case EP_FM18:
				/* p = (3x^{12} - 3x^9 + x^8 - 2x^7 + 7x^6 - x^5 - x^4 - 4x^3 +
						+ x^2 - 2x + 4)/3 */
				bn_sqr(p, t0);
				bn_mul(p, p, t0);
				bn_mul_dig(p, p, 3);
				bn_sub_dig(p, p, 3);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 1);
				bn_mul(p, p, t0);
				bn_sub_dig(p, p, 2);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 7);
				bn_mul(p, p, t0);
				bn_sub_dig(p, p, 1);
				bn_mul(p, p, t0);
				bn_sub_dig(p, p, 1);
				bn_mul(p, p, t0);
				bn_sub_dig(p, p, 4);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 1);
				bn_mul(p, p, t0);
				bn_sub_dig(p, p, 2);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 4);
 				bn_div_dig(p, p, 3);
				fp_prime_set_dense(p);
				break;
 			case EP_SG18:
 				/* p = 243x^10 - 162x^8 + 81*x^7 + 27x^6 - 54x^5 + 9x^4 + 9x^3 -
 				       3x^2 + 1 */
 				bn_sqr(p, t0);
 				bn_mul_dig(p, p, 243);
				bn_sub_dig(p, p, 162);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 81);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 27);
				bn_mul(p, p, t0);
				bn_sub_dig(p, p, 54);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 9);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 9);
				bn_mul(p, p, t0);
				bn_sub_dig(p, p, 3);
				bn_mul(p, p, t0);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 1);
 				fp_prime_set_dense(p);
 				break;
			case EP_B24:
				/* p = (x - 1)^2 * (x^8 - x^4 + 1)/3 + x. */
				bn_sqr(t1, t0);
				bn_sqr(t1, t1);
				bn_sqr(p, t1);
				bn_sub(p, p, t1);
				bn_add_dig(p, p, 1);
				bn_sub_dig(t1, t0, 1);
				bn_sqr(t1, t1);
				bn_mul(p, p, t1);
				bn_div_dig(p, p, 3);
				bn_add(p, p, t0);
				fp_prime_set_dense(p);
				break;
			case EP_B48:
				/* p = (x - 1)^2*(x^16 - x^8 + 1) / 3 + x. */
				bn_sqr(t1, t0);
				bn_sqr(t1, t1);
				bn_sqr(p, t1);
				bn_sqr(t1, p);
				bn_sub(t1, t1, p);
				bn_add_dig(t1, t1, 1);
				bn_sub_dig(p, t0, 1);
				bn_sqr(p, p);
				bn_mul(p, p, t1);
				bn_div_dig(p, p, 3);
				bn_add(p, p, t0);
				fp_prime_set_dense(p);
				break;
			case EP_SG54:
				/* p = (1+3*x+3*x^2+(3^5)*x^9+(3^5)*x^10+(3^6)*x^10+(3^6)*x^11+
				       (3^9)*x^18+(3^10)*x^19+(3^10)*x^20) */
				bn_set_dig(p, 1);
				bn_mul_dig(t1, t0, 3);
				bn_add(p, p, t1);
				bn_sqr(t1, t0);
				bn_add(p, p, t1);
				bn_add(p, p, t1);
				bn_add(p, p, t1);
				bn_sqr(t1, t1);
				bn_sqr(t1, t1);
				bn_mul(t1, t1, t0);
				bn_mul_dig(t1, t1, 243);
				bn_add(p, p, t1);
				bn_mul(t1, t1, t0);
				bn_add(p, p, t1);
				bn_mul_dig(t1, t1, 3);
				bn_add(p, p, t1);
				bn_mul(t1, t1, t0);
				bn_add(p, p, t1);
				bn_mul_dig(t1, t1, 27);
				bn_mul(t1, t1, t0);
				bn_mul(t1, t1, t0);
				bn_mul(t1, t1, t0);
				bn_mul(t1, t1, t0);
				bn_mul(t1, t1, t0);
				bn_mul(t1, t1, t0);
				bn_mul(t1, t1, t0);
				bn_add(p, p, t1);
				bn_mul_dig(t1, t1, 3);
				bn_mul(t1, t1, t0);
				bn_add(p, p, t1);
				bn_mul(t1, t1, t0);
				bn_add(p, p, t1);
				fp_prime_set_dense(p);
				break;
		}

		/* Store parameter in NAF form. */
		ctx->par_len = 0;
		bn_rec_naf(s, &len, &(ctx->par), 2);
		/* Fix corner case to avoid problems with sparse representation. */
		if (s[0] == -1) {
			s[0] = 1;
			s[1] = -1;
		}
		for (int i = 0; i < len && ctx->par_len < RLC_TERMS; i++) {
			if (s[i] > 0) {
				ctx->par_sps[ctx->par_len++] = i;
			}
			if (s[i] < 0) {
				ctx->par_sps[ctx->par_len++] = -i;
			}
		}
		if (ctx->par_len == RLC_TERMS) {
			RLC_THROW(ERR_NO_VALID);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(t0);
		bn_free(t1);
	}
}

void fp_prime_set_pmers(const int *f, size_t len) {
	bn_t p, t;

	bn_null(p);
	bn_null(t);

	RLC_TRY {
		bn_new(p);
		bn_new(t);

		if (len >= RLC_TERMS) {
			RLC_THROW(ERR_NO_VALID);
			return;
		}

		bn_set_2b(p, f[len - 1]);
		for (int i = len - 2; i > 0; i--) {
			if (f[i] > 0) {
				bn_set_2b(t, f[i]);
				bn_add(p, p, t);
			} else {
				bn_set_2b(t, -f[i]);
				bn_sub(p, p, t);
			}
		}
		if (f[0] > 0) {
			bn_add_dig(p, p, f[0]);
		} else {
			bn_sub_dig(p, p, -f[0]);
		}

#if FP_RDC == QUICK || !defined(STRIP)
		ctx_t *ctx = core_get();
		for (int i = 0; i < len; i++) {
			ctx->sps[i] = f[i];
		}
		ctx->sps[len] = 0;
		ctx->sps_len = len;
#endif /* FP_RDC == QUICK */

		fp_prime_set(p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(p);
		bn_free(t);
	}
}

void fp_prime_calc(void) {
#ifdef WITH_FPX
	if (fp_prime_get_qnr() != 0) {
		fp2_field_init();
		fp4_field_init();
		fp8_field_init();
	}
	if (fp_prime_get_cnr() != 0) {
		fp3_field_init();
	}
#endif
}

void fp_prime_conv(fp_t c, const bn_t a) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		/* Reduce a modulo the prime to ensure bounds. */
		bn_mod(t, a, &(core_get()->prime));

		if (bn_is_zero(t)) {
			fp_zero(c);
		} else {
			/* Copy used digits, fill the rest with zero. */
			dv_copy(c, t->dp, t->used);
			dv_zero(c + t->used, RLC_FP_DIGS - t->used);
#if FP_RDC == MONTY
			fp_mul(c, c, core_get()->conv.dp);
#endif
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

void fp_prime_conv_dig(fp_t c, dig_t a) {
	dv_t t;
	ctx_t *ctx = core_get();

	bn_null(t);

	RLC_TRY {
		dv_new(t);

#if FP_RDC == MONTY
		if (a != 1) {
			dv_zero(t, 2 * RLC_FP_DIGS + 1);
			t[RLC_FP_DIGS] = fp_mul1_low(t, ctx->conv.dp, a);
			fp_rdc(c, t);
		} else {
			dv_copy(c, ctx->one.dp, RLC_FP_DIGS);
		}
#else
		(void)ctx;
		fp_zero(c);
		c[0] = a;
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free(t);
	}
}

void fp_prime_back(bn_t c, const fp_t a) {
	dv_t t;

	dv_null(t);

	RLC_TRY {
		dv_new(t);

		bn_grow(c, RLC_FP_DIGS);
		fp_norm(c->dp, a);

#if FP_RDC == MONTY
		dv_zero(t, 2 * RLC_FP_DIGS + 1);
		dv_copy(t, c->dp, RLC_FP_DIGS);
		fp_rdc(c->dp, t);
#endif
		c->used = RLC_FP_DIGS;
		c->sign = RLC_POS;
		bn_trim(c);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free(t);
	}
}
