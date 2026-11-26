/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
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
 * Implementation of the square root function.
 *
 * @ingroup bn
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies c by z^(-e/2) for y = z^e, where z is the root of unity of order
 * 2^f, as in "Computing square roots faster than the Tonelli-Shanks/Bernstein
 * algorithm" by Sarkar, with windows of w = RLC_DEPTH bits from the bottom.
 * Window i has y = z^(e_i * 2^(wi) + ...), so y^(2^(f - w(i + 1))) is the
 * e_i-th power of z^(2^(f - w)), found by scanning its powers in constant
 * time. Each bit t of e_i * 2^(wi) then multiplies c by z^(-2^(t - 1)) and y
 * by z^(-2^t), which removes it. A last window of w' < w bits finds its digit
 * times 2^(w - w'). Bit 0 is zero for a square, and a non-square gives a wrong
 * c that the caller rejects.
 *
 * @param[in,out] c			- the element to correct.
 * @param[in,out] y			- the power of z, destroyed.
 * @param[in] f				- the 2-adicity of p - 1.
 */
static void fp_srt_win(fp_t c, fp_t y, int f) {
	ctx_t *ctx = core_get();
	fp_t t;

	fp_null(t);

	RLC_TRY {
		fp_new(t);

		for (int i = 0; i < f; i += RLC_DEPTH) {
			int bits = RLC_MIN(RLC_DEPTH, f - i);
			dig_t k = 0;

			fp_copy(t, y);
			for (int j = 0; j < f - i - bits; j++) {
				fp_sqr(t, t);
			}
			/* dv_equ_sec() gives RLC_EQ = 0 on a match, and RLC_NE else. */
			for (dig_t j = 0; j < (1 << RLC_DEPTH); j++) {
				k |= j & ((dig_t)(dv_equ_sec(t, ctx->srt_tab[j],
					RLC_FP_DIGS) / RLC_NE) - 1);
			}
			k >>= RLC_DEPTH - bits;
			for (int j = (i == 0); j < bits; j++) {
				fp_mul(t, c, ctx->srt_pow[i + j - 1]);
				fp_copy_sec(c, t, (k >> j) & 1);
				fp_mul(t, y, ctx->srt_pow[i + j]);
				fp_copy_sec(y, t, (k >> j) & 1);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(t);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_is_sqr(const fp_t a) {
	if (fp_is_zero(a)) {
		return 1;
	}
	
	return (fp_smb2(a) == 1);
}

int fp_srt(fp_t c, const fp_t a) {
	bn_t e;
	fp_t t0, t1, t2, t3;
	int f = 0, r = 0;
#if RLC_ALLOC == RLC_AUTO
	const dig_t *srt = (const dig_t *)fp_prime_get_srt();
#else
	const fp_t srt = (fp_t)fp_prime_get_srt();
#endif

	bn_null(e);
	fp_null_all(t0, t1, t2, t3);

	if (fp_is_zero(a)) {
		fp_zero(c);
		return 1;
	}

	RLC_TRY {
		bn_new(e);
		fp_new_all(t0, t1, t2, t3);

		/* Make e = p. */
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);

		switch(fp_prime_get_mod8() % 4) {
			case 3:
				/* Easy case, compute a^((p + 1)/4). */
				bn_add_dig(e, e, 1);
				bn_rsh(e, e, 2);

				fp_exp(t0, a, e);
				fp_sqr(t1, t0);
				r = (fp_cmp(t1, a) == RLC_EQ);
				fp_copy(c, t0);
				break;
			default:
				/* Implement constant-time version of Tonelli-Shanks algorithm
				 * as per https://eprint.iacr.org/2020/1497.pdf */

				/* First check that a is a square. */
				r = fp_is_sqr(a);

				/* Compute progenitor as x^(p-1-2^f)/2^(f+1) where 2^f|(p-1). */

				/* Write p - 1 as (e * 2^f), odd e. */
				f = fp_prime_get_2ad();
				bn_rsh(e, e, f);

				/* Make it e = (p - 1 - 2^f)/2^(f + 1), compute t0 = a^e. */
				bn_rsh(e, e, 1);
				fp_exp(t0, a, e);

				fp_sqr(t1, t0);
				fp_mul(t1, t1, a);
				fp_mul(c, t0, a);
				if (f >= RLC_FP_SRT_MIN && f <= RLC_FP_SRT_MAX) {
					fp_srt_win(c, t1, f);
					fp_neg(t0, c);
					fp_copy_sec(c, t0, fp_is_even(c) == 0);
					break;
				}

				/* Recover 2^f-root of unity, and continue algorithm. */
				fp_copy(t3, srt);

				for (int j = f; j > 1; j--) {
					fp_copy(t2, t1);
					for (int i = 1; i < j - 1; i++) {
						fp_sqr(t2, t2);
					}
					fp_mul(t0, c, t3);
					fp_copy_sec(c, t0, fp_cmp_dig(t2, 1) != RLC_EQ);
					fp_sqr(t3, t3);
					fp_mul(t0, t1, t3);
					fp_copy_sec(t1, t0, fp_cmp_dig(t2, 1) != RLC_EQ);
				}

				fp_neg(t0, c);
				fp_copy_sec(c, t0, fp_is_even(c) == 0);
				break;
		}
	}
	RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(e);
		fp_free_all(t0, t1, t2, t3);
	}
	return r;
}
