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
 * Implementation of the cube root function.
 *
 * @ingroup bn
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_is_cub(const fp_t a) {
	bn_t t;
	int r = 0;

	bn_null(t);

	if (fp_is_zero(a) || (fp_prime_get_mod18() % 3 == 2)) {
		return 1;
	}

	RLC_TRY {
		bn_new(t);

		/* t = (b - 1)/3. */
		t->sign = RLC_POS;
		t->used = RLC_FP_DIGS;
		dv_copy(t->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(t, t, 1);
		bn_div_dig(t, t, 3);

		fp_exp(t->dp, a, t);
		r = (fp_cmp_dig(t->dp, 1) == RLC_EQ);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
	return r;
}

int fp_crt(fp_t c, const fp_t a) {
	bn_t e;
	fp_t t0, t1, t2, t3, t4, t5;
	int f = 0, r = 0;

	bn_null(e);
	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);

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
		fp_new(t4);
		fp_new(t5);

		/* Make e = p. */
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);

		/* Special cases and algorithm taken from "New Cube Root Algorithm Based
		 * on Third Order Linear Recurrence Relation in Finite Field"
		 * https://eprint.iacr.org/2013/024.pdf
		 */
		if (fp_prime_get_mod18() % 3 == 2) {
			/* Easy case, compute a^((2q - 1)/3). */
			bn_dbl(e, e);
			bn_sub_dig(e, e, 1);
			bn_div_dig(e, e, 3);

			fp_exp(t0, a, e);
			fp_sqr(t1, t0);
			fp_mul(t1, t1, t0);
			r = (fp_cmp(t1, a) == RLC_EQ);
			fp_copy(c, t0);
		} else if (fp_prime_get_mod18() % 9 == 4) {
			/* Easy case, compute a^((2q + 1)/9). */
			bn_dbl(e, e);
			bn_add_dig(e, e, 1);
			bn_div_dig(e, e, 9);

			fp_exp(t0, a, e);
			fp_sqr(t1, t0);
			fp_mul(t1, t1, t0);
			r = (fp_cmp(t1, a) == RLC_EQ);
			fp_copy(c, t0);
		} else if (fp_prime_get_mod18() % 9 == 7) {
			/* Easy case, compute a^((q + 2)/9). */
			bn_add_dig(e, e, 2);
			bn_div_dig(e, e, 9);

			fp_exp(t0, a, e);
			fp_sqr(t1, t0);
			fp_mul(t1, t1, t0);
			r = (fp_cmp(t1, a) == RLC_EQ);
			fp_copy(c, t0);
		} else {
			dig_t rem;

			/* First check that a is a square. */
			r = fp_is_cub(a);

			/* Compute progenitor as x^(p-1-3^f)/3^(f+1) where 3^f|(p-1). */

			/* Write p - 1 as (e * 3^f), with e = 3l \pm 1. */
			bn_sub_dig(e, e, 1);
			bn_mod_dig(&rem, e, 3);
			while (rem == 0) {
				bn_div_dig(e, e, 3);
				bn_mod_dig(&rem, e, 3);
				f++;
			}

			/* Make it e = (p - 1 - 3^f)/3^(f + 1), compute t0 = a^e. */
			bn_mod_dig(&rem, e, 3);
			bn_div_dig(e, e, 3);
			fp_exp(t0, a, e);

			/* Recover 3^f-root of unity, and continue algorithm. */
			fp_copy(t3, fp_prime_get_crt());

			fp_copy(c, t3);
			for (int i = 0; i < f - 1; i++) {
				fp_sqr(t4, c);
				fp_mul(c, c, t4);
			}
			fp_sqr(t1, t0);
			fp_mul(t1, t1, t0);
			fp_mul(t1, t1, a);
			if (rem == 2) {
				fp_mul(t0, t0, a);
				fp_mul(t1, t1, a);
			}
			fp_set_dig(t5, 1);
			for (int j = f; j > 1; j--) {
				fp_copy(t2, t1);
				for (int i = 1; i < j - 1; i++) {
					fp_sqr(t4, t2);
					fp_mul(t2, t2, t4);
				}
				if (fp_cmp(t2, c) == RLC_EQ) {
					fp_sqr(t4, t3);
					fp_mul(t5, t5, t4);
					fp_mul(t4, t4, t3);
					fp_sqr(t4, t4);
					fp_mul(t1, t1, t4);
				} else if (fp_cmp_dig(t2, 1) != RLC_EQ) {
					fp_mul(t5, t5, t3);
					fp_sqr(t4, t3);
					fp_mul(t4, t4, t3);
					fp_mul(t1, t1, t4);
				}
				fp_sqr(t4, t3);
				fp_mul(t3, t3, t4);
			}

			fp_mul(c, t0, t5);
			if (rem == 1) {
				fp_inv(c, c);
			}
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
		fp_free(t4);
		fp_free(t5);
	}
	return r;
}
