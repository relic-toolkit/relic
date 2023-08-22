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
/* Public definitions                                                         */
/*============================================================================*/

int fp_is_sqr(const fp_t a) {
	if (fp_is_zero(a)) {
		return 1;
	}
	
	return (fp_smb(a) == 1);
}

int fp_srt(fp_t c, const fp_t a) {
	bn_t e;
	fp_t t0, t1, t2, t3;
	int f = 0, r = 0;

	bn_null(e);
	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);

	if (fp_is_zero(a)) {
		fp_zero(c);
		return 1;
	}

	RLC_TRY {
		bn_new(e);
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);

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

				/* Recover 2^f-root of unity, and continue algorithm. */
				fp_copy(t3, fp_prime_get_srt());

				fp_sqr(t1, t0);
				fp_mul(t1, t1, a);
				fp_mul(c, t0, a);
				for (int j = f; j > 1; j--) {
					fp_copy(t2, t1);
					for (int i = 1; i < j - 1; i++) {
						fp_sqr(t2, t2);
					}
					fp_mul(t0, c, t3);
					dv_copy_cond(c, t0, RLC_FP_DIGS,
							fp_cmp_dig(t2, 1) != RLC_EQ);
					fp_sqr(t3, t3);
					fp_mul(t0, t1, t3);
					dv_copy_cond(t1, t0, RLC_FP_DIGS,
							fp_cmp_dig(t2, 1) != RLC_EQ);
				}

				fp_neg(t0, c);
				dv_copy_cond(c, t0, RLC_FP_DIGS, fp_is_even(c) == 0);
				break;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(e);
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
	}
	return r;
}
