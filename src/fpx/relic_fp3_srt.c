/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of square roots in the cubic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp3_is_sqr(const fp3_t a) {
	fp3_t t, u;
	int r;

	fp3_null_all(t, u);

	RLC_TRY {
		fp3_new_all(t, u);

		fp3_frb(u, a, 1);
		fp3_mul(t, u, a);
		fp3_frb(u, u, 1);
		fp3_mul(t, t, u);
		r = fp_is_sqr(t[0]);
	} RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free_all(t, u);
	}

	return r;
}

int fp3_srt(fp3_t c, const fp3_t a) {
	int f = 0, r = 0;
	fp_t root;
	fp3_t t0, t1, t2, t3;
	bn_t d, e;

	fp_null(root);
	fp3_null_all(t0, t1, t2, t3);
	bn_null_all(d, e);

	if (fp3_is_zero(a)) {
		fp3_zero(c);
		return 1;
	}

	RLC_TRY {
		fp_new(root);
		fp3_new_all(t0, t1, t2, t3);
		bn_new_all(d, e);

		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);

		switch (fp_prime_get_mod8()) {
			case 1:
				/* Implement constant-time version of Tonelli-Shanks algorithm
				 * as per https://eprint.iacr.org/2020/1497.pdf */

				/* Compute progenitor as x^(p^3-1-2^f)/2^(f+1) for 2^f|(p-1).
				 * Let q = (p-1)/2^f. We will write the exponent in p and q.
				 * Write (p^3-1-2^f)/2^(f+1) as (q*(p^2+p))/2 + (q - 1)/2 */
				bn_sqr(d, e);
				bn_add(d, d, e);
				bn_rsh(d, d, 1);
				/* Compute (q - 1)/2 = (p-1)/2^(f+1).*/
				f = fp_prime_get_2ad();
				bn_sub_dig(e, e, 1);
				bn_rsh(e, e, f + 1);
				fp3_exp(t1, a, e);
				/* Now compute the power (q*(p^2+p))/2. */
				fp3_sqr(t0, t1);
				fp3_mul(t0, t0, a);
				fp3_exp(t0, t0, d);
				fp3_mul(t0, t0, t1);

				/* Generate root of unity, and continue algorithm. */
				dv_copy(root, fp_prime_get_srt(), RLC_FP_DIGS);

				fp3_sqr(t1, t0);
				fp3_mul(t1, t1, a);
				fp3_mul(t3, t0, a);
				fp3_copy(t2, t1);
				for (int j = f; j > 1; j--) {
					for (int i = 1; i < j - 1; i++) {
						fp3_sqr(t2, t2);
					}
					fp_mul(t0[0], t3[0], root);
					fp_mul(t0[1], t3[1], root);
					fp_mul(t0[2], t3[2], root);
					fp3_copy_sec(t3, t0, fp3_cmp_dig(t2, 1) != RLC_EQ);
					fp_sqr(root, root);
					fp_mul(t0[0], t1[0], root);
					fp_mul(t0[1], t1[1], root);
					fp_mul(t0[2], t1[2], root);
					fp3_copy_sec(t1, t0, fp3_cmp_dig(t2, 1) != RLC_EQ);
					fp3_copy(t2, t1);
				}
				break;
			case 5:
				fp3_dbl(t3, a);
				fp3_frb(t0, t3, 1);

				fp3_sqr(t1, t0);
				fp3_mul(t2, t1, t0);
				fp3_mul(t1, t1, t2);

				fp3_frb(t0, t0, 1);
				fp3_mul(t3, t3, t1);
				fp3_mul(t0, t0, t3);

				bn_div_dig(e, e, 8);
				fp3_exp(t0, t0, e);

				fp3_mul(t0, t0, t2);
				fp3_sqr(t1, t0);
				fp3_mul(t1, t1, a);
				fp3_dbl(t1, t1);

				fp3_mul(t0, t0, a);
				fp_sub_dig(t1[0], t1[0], 1);
				fp3_mul(t3, t0, t1);
				break;
			case 3:
			case 7:
				fp3_frb(t0, a, 1);
				fp3_sqr(t1, t0);
				fp3_mul(t2, t1, t0);
				fp3_frb(t0, t0, 1);
				fp3_mul(t3, t2, a);
				fp3_mul(t0, t0, t3);

				bn_div_dig(e, e, 4);
				fp3_exp(t0, t0, e);

				fp3_mul(t0, t0, a);
				fp3_mul(t3, t0, t1);
				break;
			default:
				fp3_zero(c);
				break;
		}
		/* Assume it is a square and test at the end. */
		/* We cannot use QR test because it depends on Frobenius constants. */
		fp3_sqr(t0, t3);
		r = (fp3_cmp(t0, a) == RLC_EQ ? 1 : 0);
		fp3_zero(c);
		fp3_copy_sec(c, t3, r);
	} RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(root);
		fp3_free_all(t0, t1, t2, t3);
		bn_free_all(d, e);
	}

	return r;
}
