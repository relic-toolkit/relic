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
 * Converts a signed integer to a prime field element.
 *
 * @param[out] c		- the result.
 * @param[in] a			- the integer, with absolute value below p.
 */
static void fp_prime_conv_sgn(fp_t c, const bn_t a) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		bn_abs(t, a);
		fp_prime_conv(c, t);
		if (bn_sign(a) == RLC_NEG) {
			fp_neg(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

/**
 * Computes, for p = 1 mod 3, the primary prime pi = a + b * w of norm p in the
 * Eisenstein integers Z[w], with w^2 + w + 1 = 0, and the cube root of unity
 * congruent to w modulo pi, which define the cubic residue symbol.
 *
 * @param[in] p			- the prime field modulus.
 */
static void fp_prime_set_cub(const bn_t p) {
	ctx_t *ctx = core_get();
	dig_t z[RLC_FP_DIGS + 1], ra, rb;
	bn_t a, b, c, d;
	fp_t s, t;
	int neg;

	bn_null_all(a, b, c, d);
	fp_null_all(s, t);

	RLC_TRY {
		bn_new_all(a, b, c, d);
		fp_new_all(s, t);

		/* A cube root of unity z = cnr^((p - 1)/3) gives sqrt(-3) = 2z + 1. */
		fp_set_dig(s, (ctx->cnr < 0 ? -ctx->cnr : ctx->cnr));
		if (ctx->cnr < 0) {
			fp_neg(s, s);
		}
		fp_exp(s, s, &(ctx->over3));
		fp_dbl(s, s);
		fp_add_dig(s, s, 1);
		fp_prime_back(b, s);

		/* Cornacchia's algorithm finds x^2 + 3y^2 = p, with x the first
		 * remainder of the Euclidean algorithm below sqrt(p). */
		bn_copy(a, p);
		bn_sqr(c, b);
		while (bn_cmp(c, p) == RLC_GT) {
			bn_mod(c, a, b);
			bn_copy(a, b);
			bn_copy(b, c);
			bn_sqr(c, b);
		}
		bn_sub(c, p, c);
		bn_div_dig(c, c, 3);
		bn_srt(d, c);

		/* x + y * sqrt(-3) = (x + y) + 2y * w has norm p. */
		bn_add(a, b, d);
		bn_dbl(b, d);

		/* Its primary associate is the one with a = 2 and b = 0 mod 3. */
		bn_mod_dig(&ra, a, 3);
		bn_mod_dig(&rb, b, 3);
		if (rb == 0) {
			neg = (ra == 1);
		} else if (ra == 0) {
			/* w^2 * pi = (b - a) - a * w. */
			bn_sub(c, b, a);
			bn_neg(b, a);
			bn_copy(a, c);
			neg = (rb == 1);
		} else {
			/* w * pi = -b + (a - b) * w. */
			bn_sub(c, a, b);
			bn_neg(a, b);
			bn_copy(b, c);
			neg = (rb == 2);
		}
		if (neg) {
			bn_neg(a, a);
			bn_neg(b, b);
		}

		/* Store the coordinates in two's complement. */
		dv_zero(z, RLC_FP_DIGS + 1);
		for (int k = 0; k < 2; k++) {
			bn_copy(c, (k == 0 ? a : b));
			dv_zero(ctx->cub_pi[k], RLC_FP_DIGS + 1);
			dv_copy(ctx->cub_pi[k], c->dp, c->used);
			if (bn_sign(c) == RLC_NEG) {
				bn_subn_low(ctx->cub_pi[k], z, ctx->cub_pi[k], RLC_FP_DIGS + 1);
			}
		}

		/* As a / pi = a * ((a - b) - b * w) / p, the coordinates (a - b) / p
		 * and -b / p, scaled by 2^K for K = RLC_DIG * (RLC_FP_DIGS + 1),
		 * divide by pi with one multiplication each. */
		for (int k = 0; k < 2; k++) {
			if (k == 0) {
				bn_sub(c, a, b);
			} else {
				bn_neg(c, b);
			}
			ctx->cub_sgn[k] = bn_sign(c);
			bn_abs(c, c);
			bn_lsh(c, c, RLC_DIG * (RLC_FP_DIGS + 1));
			bn_div(c, c, p);
			dv_zero(ctx->cub_inv[k], RLC_FP_DIGS + 1);
			dv_copy(ctx->cub_inv[k], c->dp, c->used);
		}

		/* As pi = a + b * w = 0 modulo pi, w = -a / b. */
		fp_prime_conv_sgn(s, a);
		fp_prime_conv_sgn(t, b);
		fp_inv(t, t);
		fp_mul(s, s, t);
		fp_neg(ctx->cub, s);

		/* The symbol of R, stored as R^2 mod p in Montgomery form, for the
		 * k such that R^((p - 1)/3) = z^k. */
		ctx->cub_r = 0;
#if FP_RDC == FP_MONTY
		fp_exp(s, ctx->conv, &(ctx->over3));
		fp_copy(t, ctx->cub);
		ctx->cub_r = (fp_cmp(s, t) == RLC_EQ);
		fp_sqr(t, t);
		ctx->cub_r += 2 * (fp_cmp(s, t) == RLC_EQ);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(a, b, c, d);
		fp_free_all(s, t);
	}
}

/**
 * Computes, for p = 1 mod 4, the primary prime pi = a + b * i of norm p in the
 * Gaussian integers Z[i] and the fourth root of unity congruent to i modulo
 * pi, which define the quartic residue symbol.
 *
 * @param[in] p			- the prime field modulus.
 */
static void fp_prime_set_qrt(const bn_t p) {
	ctx_t *ctx = core_get();
	dig_t z[RLC_FP_DIGS + 1], ra, rb;
	bn_t a, b, c, d;
	fp_t s, t;

	bn_null_all(a, b, c, d);
	fp_null_all(s, t);

	RLC_TRY {
		bn_new_all(a, b, c, d);
		fp_new_all(s, t);

		/* A square root of -1 is qnr^((p - 1)/4). */
		fp_set_dig(s, (ctx->qnr < 0 ? -ctx->qnr : ctx->qnr));
		if (ctx->qnr < 0) {
			fp_neg(s, s);
		}
		bn_sub_dig(d, p, 1);
		bn_rsh(d, d, 2);
		fp_exp(s, s, d);
		fp_prime_back(b, s);

		/* Cornacchia's algorithm finds x^2 + y^2 = p, with x the first
		 * remainder of the Euclidean algorithm below sqrt(p). */
		bn_copy(a, p);
		bn_sqr(c, b);
		while (bn_cmp(c, p) == RLC_GT) {
			bn_mod(c, a, b);
			bn_copy(a, b);
			bn_copy(b, c);
			bn_sqr(c, b);
		}
		bn_sub(c, p, c);
		bn_srt(d, c);

		/* x + y * i has norm p, and so does i * (x + y * i) = -y + x * i, one
		 * of which has an odd real part. */
		if (bn_is_even(b)) {
			bn_neg(a, d);
		} else {
			bn_copy(a, b);
			bn_copy(b, d);
		}
		/* Its primary associate is the one with a + b = 1 mod 4. */
		bn_abs(c, a);
		bn_mod_dig(&ra, c, 4);
		if (bn_sign(a) == RLC_NEG) {
			ra = (4 - ra) % 4;
		}
		bn_mod_dig(&rb, b, 4);
		if ((ra + rb) % 4 == 3) {
			bn_neg(a, a);
			bn_neg(b, b);
		}

		/* Store the coordinates in two's complement. */
		dv_zero(z, RLC_FP_DIGS + 1);
		for (int k = 0; k < 2; k++) {
			bn_copy(c, (k == 0 ? a : b));
			dv_zero(ctx->qrt_pi[k], RLC_FP_DIGS + 1);
			dv_copy(ctx->qrt_pi[k], c->dp, c->used);
			if (bn_sign(c) == RLC_NEG) {
				bn_subn_low(ctx->qrt_pi[k], z, ctx->qrt_pi[k], RLC_FP_DIGS + 1);
			}
		}

		/* As a / pi = a * (a - b * i) / p, the coordinates a / p and -b / p,
		 * scaled by 2^K for K = RLC_DIG * (RLC_FP_DIGS + 1), divide by pi
		 * with one multiplication each. */
		for (int k = 0; k < 2; k++) {
			if (k == 0) {
				bn_copy(c, a);
			} else {
				bn_neg(c, b);
			}
			ctx->qrt_sgn[k] = bn_sign(c);
			bn_abs(c, c);
			bn_lsh(c, c, RLC_DIG * (RLC_FP_DIGS + 1));
			bn_div(c, c, p);
			dv_zero(ctx->qrt_inv[k], RLC_FP_DIGS + 1);
			dv_copy(ctx->qrt_inv[k], c->dp, c->used);
		}

		/* As pi = a + b * i = 0 modulo pi, i = -a / b. */
		fp_prime_conv_sgn(s, a);
		fp_prime_conv_sgn(t, b);
		fp_inv(t, t);
		fp_mul(s, s, t);
		fp_neg(ctx->qrt, s);

		/* The symbol of R, stored as R^2 mod p in Montgomery form, for the
		 * k such that R^((p - 1)/4) = z^k. */
		ctx->qrt_r = 0;
#if FP_RDC == FP_MONTY
		bn_sub_dig(d, p, 1);
		bn_rsh(d, d, 2);
		fp_exp(s, ctx->conv, d);
		fp_copy(t, ctx->qrt);
		for (int k = 1; k < 4; k++) {
			ctx->qrt_r += k * (fp_cmp(s, t) == RLC_EQ);
			fp_mul(t, t, ctx->qrt);
		}
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(a, b, c, d);
		fp_free_all(s, t);
	}
}

/**
 * Assigns the prime field modulus.
 *
 * @param[in] p			- the new prime field modulus.
 */
static void fp_prime_set(const bn_t p) {
	bn_t t;
	fp_t r, s;
	ctx_t *ctx = core_get();
	dig_t rem;

	if (p->used != RLC_FP_DIGS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_null(t);
	fp_null(r);
	fp_null(s);

	RLC_TRY {
		bn_new(t);
		fp_new(r);
		fp_new(s);

		bn_copy(&(ctx->prime), p);
		bn_sub_dig(&(ctx->over3), p, 1);
		bn_div_dig(&(ctx->over3), &(ctx->over3), 3);

		bn_mod_pre_monty(t, &(ctx->prime));
		ctx->u = t->dp[0];

		bn_set_2b(t, bn_bits(&(ctx->prime)) + RLC_DIG - 1);
		bn_div(t, t, &(ctx->prime));
		ctx->rdc1 = t->dp[0];

		/* compute R mod p */
		bn_set_2b(t, ctx->prime.used * RLC_DIG);
		bn_mod(t, t, &(ctx->prime));
		fp_copy(ctx->one, t->dp);

		/* compute the R^2 mod p */
		fp_add(r, ctx->one, ctx->one);
		bn_set_dig(t, RLC_FP_DIGS);
		bn_lsh(t, t, RLC_DIG_LOG);
		fp_exp(ctx->conv, r, t);

#if FP_RDC == FP_MONTY
		/* Compute R^3 mod p for the inversion by jump division steps. */
		fp_mul(ctx->inv, ctx->conv, ctx->conv);
#endif

		/* Backends with a prime built in reduce modulo that prime only, and
		 * the searches below would not end, so check that (-1)^2 = 1. */
		fp_set_dig(r, 1);
		fp_neg(r, r);
		fp_sqr(r, r);
		fp_prime_back(t, r);
		bn_mod(t, t, &(ctx->prime));
		if (bn_cmp_dig(t, 1) != RLC_EQ) {
			RLC_THROW(ERR_NO_CONFIG);
		} else {
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
			fp_inv(ctx->iqnr, r);

			/* Check if cnr is a cubic non-residue or find another, by Euler's
			 * criterion, as fp_is_cub() needs the cube root of unity that it
			 * gives. */
			if (ctx->mod18 % 3 == 1) {
				if (ctx->cnr > 0) {
					fp_set_dig(r, ctx->cnr);
					fp_exp(s, r, &(ctx->over3));
					while (fp_cmp_dig(s, 1) == RLC_EQ) {
						ctx->cnr++;
						fp_set_dig(r, ctx->cnr);
						fp_exp(s, r, &(ctx->over3));
					}
				} else {
					fp_set_dig(r, -ctx->cnr);
					fp_neg(r, r);
					fp_exp(s, r, &(ctx->over3));
					while (fp_cmp_dig(s, 1) == RLC_EQ) {
						ctx->cnr--;
						fp_set_dig(r, -ctx->cnr);
						fp_neg(r, r);
						fp_exp(s, r, &(ctx->over3));
					}
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

			if (ctx->qnr < 0) {
				fp_set_dig(ctx->srt, -ctx->qnr);
			} else {
				fp_set_dig(ctx->srt, ctx->qnr);
			}
			fp_exp(ctx->srt, ctx->srt, t);

			/* The tables of the windowed square root, for z = srt: z^(-2^t)
			 * for t < f, and the powers of z^(2^(f - w)), of order 2^w. */
			for (int i = 0; i < RLC_FP_SRT_MAX; i++) {
				fp_zero(ctx->srt_pow[i]);
			}
			for (int k = 0; k < (1 << RLC_WIDTH); k++) {
				fp_zero(ctx->srt_tab[k]);
			}
			if (ctx->mod8 % 4 == 1 && ctx->ad2 >= RLC_FP_SRT_MIN &&
					ctx->ad2 <= RLC_FP_SRT_MAX) {
				fp_inv(ctx->srt_pow[0], ctx->srt);
				for (dig_t i = 1; i < ctx->ad2; i++) {
					fp_sqr(ctx->srt_pow[i], ctx->srt_pow[i - 1]);
				}
				fp_inv(s, ctx->srt_pow[ctx->ad2 - RLC_WIDTH]);
				fp_set_dig(ctx->srt_tab[0], 1);
				for (int k = 1; k < (1 << RLC_WIDTH); k++) {
					fp_mul(ctx->srt_tab[k], ctx->srt_tab[k - 1], s);
				}
			}

			/* Write p - 1 as (e * 3^f), with e = 3l \pm 1. */
			bn_sub_dig(t, p, 1);
			bn_mod_dig(&rem, t, 3);
			while (rem == 0) {
				bn_div_dig(t, t, 3);
				bn_mod_dig(&rem, t, 3);
			}

			/* Compute fth root of unity by computing CNR to (p - 1)/3^f. */
			if (ctx->cnr < 0) {
				fp_set_dig(ctx->crt, -fp_prime_get_cnr());
			} else {
				fp_set_dig(ctx->crt, fp_prime_get_cnr());
			}
			fp_exp(ctx->crt, ctx->crt, t);

			/* The cubic residue symbol, before anything testing for cubes. */
			if (ctx->mod18 % 3 == 1) {
				fp_prime_set_cub(p);
			} else {
				fp_zero(ctx->cub);
				dv_zero(ctx->cub_pi[0], RLC_FP_DIGS + 1);
				dv_zero(ctx->cub_pi[1], RLC_FP_DIGS + 1);
				dv_zero(ctx->cub_inv[0], RLC_FP_DIGS + 1);
				dv_zero(ctx->cub_inv[1], RLC_FP_DIGS + 1);
				ctx->cub_r = 0;
			}

			/* The quartic residue symbol. */
			if (ctx->mod8 % 4 == 1) {
				fp_prime_set_qrt(p);
			} else {
				fp_zero(ctx->qrt);
				dv_zero(ctx->qrt_pi[0], RLC_FP_DIGS + 1);
				dv_zero(ctx->qrt_pi[1], RLC_FP_DIGS + 1);
				dv_zero(ctx->qrt_inv[0], RLC_FP_DIGS + 1);
				dv_zero(ctx->qrt_inv[1], RLC_FP_DIGS + 1);
				ctx->qrt_r = 0;
			}

			fp_prime_calc();
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		fp_free(r);
		fp_free(s);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_prime_init(void) {
	ctx_t *ctx = core_get();
	ctx->fp_id = 0;
	bn_make(&(ctx->prime), RLC_FP_DIGS);
	bn_make(&(ctx->over3), RLC_FP_DIGS);
	bn_make(&(ctx->par), RLC_FP_DIGS);
	ctx->sps_len = 0;
	memset(ctx->sps, 0, sizeof(ctx->sps));
}

void fp_prime_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
		ctx->fp_id = 0;
		ctx->sps_len = 0;
		memset(ctx->sps, 0, sizeof(ctx->sps));
		bn_clean(&(ctx->prime));
		bn_clean(&(ctx->over3));
		bn_clean(&(ctx->par));
	}
}

const dig_t *fp_prime_get(void) {
	return core_get()->prime.dp;
}

const dig_t *fp_prime_get_rdc(void) {
	return &(core_get()->u);
}

const dig_t *fp_prime_get_rdc1(void) {
	return &(core_get()->rdc1);
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
}

const dig_t *fp_prime_get_conv(void) {
	return core_get()->conv;
}

const dig_t *fp_prime_get_srt(void) {
	return core_get()->srt;
}

const dig_t *fp_prime_get_crt(void) {
	return core_get()->crt;
}

const dig_t *fp_prime_get_cub(void) {
	return core_get()->cub;
}

const dig_t *fp_prime_get_qrt(void) {
	return core_get()->qrt;
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
#if FP_RDC == FP_QUICK || FP_RDC == FP_LOWER
	/* The reduction needs a prime in special form, even to set the prime. */
	(void)p;
	RLC_THROW(ERR_NO_CONFIG);
#else
	/* Accept a prime of the configured size, by trial division and a Fermat
	 * test to base 2, which rejects squares, on which the search for
	 * non-residues would not end, and other composites set by mistake. */
	if (bn_bits(p) != RLC_FP_BITS || !bn_is_prime_basic(p) ||
			!bn_is_prime_fermt(p)) {
		RLC_THROW(ERR_NO_VALID);
	} else {
		fp_prime_set(p);
	}
#endif
}

void fp_prime_set_pairf(const bn_t x, int pairf) {
	bn_t p, t0, t1;
	ctx_t *ctx = core_get();
	size_t len = bn_bits(x) + 1;
	int8_t s[RLC_FP_BITS + 1];

	bn_null_all(p, t0, t1);

	RLC_TRY {
		bn_new_all(p, t0, t1);

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
			case EP_AFG16:
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
				bn_add_dig(p, p, 255);
				bn_add_dig(p, p, 255);
				bn_add_dig(p, p, 115);
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
				bn_add_dig(p, p, 255);
				bn_add_dig(p, p, 4);
				bn_mul(p, p, t0);
				bn_add_dig(p, p, 255);
				bn_add_dig(p, p, 88);
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
		for (int i = 0; i < (int)len && ctx->par_len < RLC_TERMS; i++) {
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
		bn_free_all(p, t0, t1);
	}
}

void fp_prime_set_pmers(const int *f, size_t len) {
	bn_t p, t;

	if (len == 0 || len >= RLC_TERMS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_null_all(p, t);

	RLC_TRY {
		bn_new_all(p, t);

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
		bn_add_dis(p, p, f[0]);

		ctx_t *ctx = core_get();
		for (size_t i = 0; i < len; i++) {
			ctx->sps[i] = f[i];
		}
		ctx->sps[len] = 0;
		ctx->sps_len = len;

		fp_prime_set(p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(p, t);
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
#if FP_RDC == FP_MONTY
			fp_mul(c, c, core_get()->conv);
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

void fp_prime_conv_bin(fp_t c, const uint8_t *bin, size_t len) {
	const size_t n = RLC_CEIL(len, RLC_DIG / 8);
	fp_t t, u;
	dig_t d;

	fp_null_all(t, u);

	RLC_TRY {
		fp_new_all(t, u);

		/* t = 2^RLC_DIG, a public constant. */
		fp_set_dig(t, (dig_t)1 << (RLC_DIG - 1));
		fp_dbl(t, t);

		/* By Horner's rule over the digits, each stored as an element as it
		 * is, which is below the prime. The stored values then accumulate the
		 * input, which is converted once at the end, as in fp_prime_conv(). */
		fp_zero(c);
		fp_zero(u);
		for (size_t j = n; j > 0; j--) {
			d = 0;
			for (size_t b = RLC_DIG / 8; b > 0; b--) {
				/* Byte b - 1 of digit j - 1, counted from the end. */
				size_t k = (j - 1) * (RLC_DIG / 8) + b - 1;
				d = (dig_t)(d << 8);
				d |= (k < len ? bin[len - 1 - k] : 0);
			}
			u[0] = d;
			fp_mul(c, c, t);
			fp_add(c, c, u);
		}
#if FP_RDC == FP_MONTY
		fp_mul(c, c, core_get()->conv);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free_all(t, u);
	}
}

void fp_prime_conv_dig(fp_t c, dig_t a) {
#if FP_RDC == FP_MONTY
	ctx_t *ctx = core_get();

	/* Compute a * R mod p from R mod p. */
	if ((a >> (RLC_DIG - 1)) == 0) {
		fp_mul1_low(c, ctx->one, a);
	} else {
		/* Halve digits too large for a single reduction. */
		fp_mul1_low(c, ctx->one, a >> 1);
		fp_dbl(c, c);
		if (a & 1) {
			fp_add(c, c, ctx->one);
		}
	}
#else
	fp_zero(c);
	c[0] = a;
#endif
}

void fp_prime_back(bn_t c, const fp_t a) {
	dv_t t;

	dv_null(t);

	RLC_TRY {
		dv_new(t);

		bn_grow(c, RLC_FP_DIGS);
		fp_norm(c->dp, a);

#if FP_RDC == FP_MONTY
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
