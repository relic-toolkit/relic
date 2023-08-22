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
 * Implementation of square root in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp2_is_sqr(const fp2_t a) {
	fp2_t t;
	int r = 0;

	fp2_null(t);

	/* QR testing in extension fields from  "Square root computation over
	 * even extension fields", by Gora Adj and Francisco Rodríguez-Henríquez.
	 * https://eprint.iacr.org/2012/685 */

	RLC_TRY {
		fp2_new(t);

		fp2_frb(t, a, 1);
		fp2_mul(t, t, a);
		r = fp_is_sqr(t[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t);
	}

	return r;
}

int fp2_srt(fp2_t c, const fp2_t a) {
	int r = 0;
	fp_t t0;
	fp_t t1;
	fp_t t2;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);

	if (fp2_is_zero(a)) {
		fp2_zero(c);
		return 1;
	}

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);

		if (fp_is_zero(a[1])) {
			/* special case: either a[0] is square and sqrt is purely 'real'
			 * or a[0] is non-square and sqrt is purely 'imaginary' */
			r = 1;
			if (fp_is_sqr(a[0])) {
				fp_srt(t0, a[0]);
				fp_copy(c[0], t0);
				fp_zero(c[1]);
			} else {
				/* Compute a[0]/i^2. */
#ifdef FP_QNRES
				fp_copy(t0, a[0]);
#else
				if (fp_prime_get_qnr() == -2) {
					fp_hlv(t0, a[0]);
				} else {
					fp_set_dig(t0, -fp_prime_get_qnr());
					fp_inv(t0, t0);
					fp_mul(t0, t0, a[0]);
				}
#endif
				fp_neg(t0, t0);
				fp_zero(c[0]);
				if (!fp_srt(c[1], t0)) {
					/* should never happen! */
					RLC_THROW(ERR_NO_VALID);
				}
			}
		} else {
			/* t0 = a[0]^2 - i^2 * a[1]^2 */
			fp_sqr(t0, a[0]);
			fp_sqr(t1, a[1]);
			for (int i = -1; i > fp_prime_get_qnr(); i--) {
				fp_add(t0, t0, t1);
			}
			fp_add(t0, t0, t1);

			if (fp_is_sqr(t0)) {
				fp_srt(t1, t0);
				/* t0 = (a_0 + sqrt(t0)) / 2 */
				fp_add(t0, a[0], t1);
				fp_hlv(t0, t0);
				/* t1 = (a_0 - sqrt(t0)) / 2 */
				fp_sub(t1, a[0], t1);
				fp_hlv(t1, t1);
				dv_copy_cond(t0, t1, RLC_FP_DIGS, !fp_is_sqr(t0));

				/* Should always be a quadratic residue. */
				fp_srt(t2, t0);
				/* c_0 = sqrt(t0) */
				fp_copy(c[0], t2);
				/* c_1 = a_1 / (2 * sqrt(t0)) */
				fp_dbl(t2, t2);
				fp_inv(t2, t2);
				fp_mul(c[1], a[1], t2);
				r = 1;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
	}
	return r;
}

int fp3_is_sqr(const fp3_t a) {
	fp3_t t, u;
	int r;

	fp3_null(t);
	fp3_null(u);

	RLC_TRY {
		fp3_new(t);
		fp3_new(u);

		fp3_frb(u, a, 1);
		fp3_mul(t, u, a);
		fp3_frb(u, u, 1);
		fp3_mul(t, t, u);
		r = fp_is_sqr(t[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t);
		fp2_free(u);
	}

	return r;
}

int fp3_srt(fp3_t c, const fp3_t a) {
	int f = 0, r = 0;
	fp_t root;
	fp3_t t0, t1, t2, t3;
	bn_t d, e;

	fp_null(root);
	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);
	fp3_null(t3);
	bn_null(d);
	bn_null(e);

	if (fp3_is_zero(a)) {
		fp3_zero(c);
		return 1;
	}

	RLC_TRY {
		fp_new(root);
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);
		fp3_new(t3);
		bn_new(d);
		bn_new(e);

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
					dv_copy_cond(t3[0], t0[0], RLC_FP_DIGS,
							fp3_cmp_dig(t2, 1) != RLC_EQ);
					dv_copy_cond(t3[1], t0[1], RLC_FP_DIGS,
							fp3_cmp_dig(t2, 1) != RLC_EQ);
					dv_copy_cond(t3[2], t0[2], RLC_FP_DIGS,
							fp3_cmp_dig(t2, 1) != RLC_EQ);
					fp_sqr(root, root);
					fp_mul(t0[0], t1[0], root);
					fp_mul(t0[1], t1[1], root);
					fp_mul(t0[2], t1[2], root);
					dv_copy_cond(t1[0], t0[0], RLC_FP_DIGS,
							fp3_cmp_dig(t2, 1) != RLC_EQ);
					dv_copy_cond(t1[1], t0[1], RLC_FP_DIGS,
							fp3_cmp_dig(t2, 1) != RLC_EQ);
					dv_copy_cond(t1[2], t0[2], RLC_FP_DIGS,
							fp3_cmp_dig(t2, 1) != RLC_EQ);
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
		dv_copy_cond(c[0], t3[0], RLC_FP_DIGS, r);
		dv_copy_cond(c[1], t3[1], RLC_FP_DIGS, r);
		dv_copy_cond(c[2], t3[2], RLC_FP_DIGS, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(root);
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
		fp3_free(t3);
		bn_free(d);
		bn_free(e);
	}

	return r;
}

int fp4_is_sqr(const fp4_t a) {
	fp4_t t, u;
	int r;

	fp4_null(t);
	fp4_null(u);

	RLC_TRY {
		fp4_new(t);
		fp4_new(u);

		fp4_frb(u, a, 1);
		fp4_mul(t, u, a);
		for (int i = 2; i < 4; i++) {
			fp4_frb(u, u, 1);
			fp4_mul(t, t, u);
		}
		r = fp_is_sqr(t[0][0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(t);
		fp4_free(u);
	}

	return r;
}

int fp4_srt(fp4_t c, const fp4_t a) {
	int c0, r = 0;
	fp2_t t0, t1, t2;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);

	if (fp4_is_zero(a)) {
		fp4_zero(c);
		return 1;
	}

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);

		if (fp2_is_zero(a[1])) {
			/* special case: either a[0] is square and sqrt is purely 'real'
			 * or a[0] is non-square and sqrt is purely 'imaginary' */
			r = 1;
			if (fp2_is_sqr(a[0])) {
				fp2_srt(c[0], a[0]);
				fp2_zero(c[1]);
			} else {
				/* Compute a[0]/s^2. */
				fp2_set_dig(t0, 1);
				fp2_mul_nor(t0, t0);
				fp2_inv(t0, t0);
				fp2_mul(t0, a[0], t0);
				fp2_zero(c[0]);
				if (!fp2_srt(c[1], t0)) {
					/* should never happen! */
					RLC_THROW(ERR_NO_VALID);
				}
			}
		} else {
			/* t0 = a[0]^2 - s^2 * a[1]^2 */
			fp2_sqr(t0, a[0]);
			fp2_sqr(t1, a[1]);
			fp2_mul_nor(t2, t1);
			fp2_sub(t0, t0, t2);

			if (fp2_is_sqr(t0)) {
				fp2_srt(t1, t0);
				/* t0 = (a_0 + sqrt(t0)) / 2 */
				fp2_add(t0, a[0], t1);
				fp_hlv(t0[0], t0[0]);
				fp_hlv(t0[1], t0[1]);
				c0 = fp2_is_sqr(t0);
				/* t0 = (a_0 - sqrt(t0)) / 2 */
				fp2_sub(t1, a[0], t1);
				fp_hlv(t1[0], t1[0]);
				fp_hlv(t1[1], t1[1]);
				dv_copy_cond(t0[0], t1[0], RLC_FP_DIGS, !c0);
				dv_copy_cond(t0[1], t1[1], RLC_FP_DIGS, !c0);
				/* Should always be a quadratic residue. */
				fp2_srt(t2, t0);
				/* c_0 = sqrt(t0) */
				fp2_copy(c[0], t2);

				/* c_1 = a_1 / (2 * sqrt(t0)) */
				fp2_dbl(t2, t2);
				fp2_inv(t2, t2);
				fp2_mul(c[1], a[1], t2);
				r = 1;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
	}
	return r;
}

int fp8_is_sqr(const fp8_t a) {
	fp8_t t, u;
	int r;

	fp8_null(t);
	fp8_null(u);

	RLC_TRY {
		fp8_new(t);
		fp8_new(u);

		fp8_frb(u, a, 1);
		fp8_mul(t, u, a);
		for (int i = 2; i < 8; i++) {
			fp8_frb(u, u, 1);
			fp8_mul(t, t, u);
		}
		r = fp_is_sqr(t[0][0][0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t);
		fp8_free(u);
	}

	return r;
}

int fp8_srt(fp8_t c, const fp8_t a) {
	int c0, r = 0;
	fp4_t t0, t1, t2;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);

	if (fp8_is_zero(a)) {
		fp8_zero(c);
		return 1;
	}

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);

		if (fp4_is_zero(a[1])) {
			/* special case: either a[0] is square and sqrt is purely 'real'
			 * or a[0] is non-square and sqrt is purely 'imaginary' */
			r = 1;
			if (fp4_is_sqr(a[0])) {
				fp4_srt(c[0], a[0]);
				fp4_zero(c[1]);
			} else {
				/* Compute a[0]/s^2. */
				fp4_set_dig(t0, 1);
				fp4_mul_art(t0, t0);
				fp4_inv(t0, t0);
				fp4_mul(t0, a[0], t0);
				fp4_zero(c[0]);
				if (!fp4_srt(c[1], t0)) {
					/* should never happen! */
					RLC_THROW(ERR_NO_VALID);
				}
			}
		} else {
			/* t0 = a[0]^2 - s^2 * a[1]^2 */
			fp4_sqr(t0, a[0]);
			fp4_sqr(t1, a[1]);
			fp4_mul_art(t2, t1);
			fp4_sub(t0, t0, t2);

			if (fp4_is_sqr(t0)) {
				fp4_srt(t1, t0);
				/* t0 = (a_0 + sqrt(t0)) / 2 */
				fp4_add(t0, a[0], t1);
				fp_hlv(t0[0][0], t0[0][0]);
				fp_hlv(t0[0][1], t0[0][1]);
				fp_hlv(t0[1][0], t0[1][0]);
				fp_hlv(t0[1][1], t0[1][1]);
				c0 = fp4_is_sqr(t0);
				/* t0 = (a_0 - sqrt(t0)) / 2 */
				fp4_sub(t1, a[0], t1);
				fp_hlv(t1[0][0], t1[0][0]);
				fp_hlv(t1[0][1], t1[0][1]);
				fp_hlv(t1[1][0], t1[1][0]);
				fp_hlv(t1[1][1], t1[1][1]);
				dv_copy_cond(t0[0][0], t1[0][0], RLC_FP_DIGS, !c0);
				dv_copy_cond(t0[0][1], t1[0][1], RLC_FP_DIGS, !c0);
				dv_copy_cond(t0[1][0], t1[1][0], RLC_FP_DIGS, !c0);
				dv_copy_cond(t0[1][1], t1[1][1], RLC_FP_DIGS, !c0);
				/* Should always be a quadratic residue. */
				fp4_srt(t2, t0);
				/* c_0 = sqrt(t0) */
				fp4_copy(c[0], t2);

				/* c_1 = a_1 / (2 * sqrt(t0)) */
				fp4_dbl(t2, t2);
				fp4_inv(t2, t2);
				fp4_mul(c[1], a[1], t2);
				r = 1;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
	}
	return r;
}

int fp16_is_sqr(const fp16_t a) {
	fp16_t t, u;
	int r;

	fp16_null(t);
	fp16_null(u);

	RLC_TRY {
		fp16_new(t);
		fp16_new(u);

		fp16_frb(u, a, 1);
		fp16_mul(t, u, a);
		for (int i = 2; i < 16; i++) {
			fp16_frb(u, u, 1);
			fp16_mul(t, t, u);
		}
		r = fp_is_sqr(t[0][0][0][0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp16_free(t);
		fp16_free(u);
	}

	return r;
}

int fp16_srt(fp16_t c, const fp16_t a) {
	int c0, r = 0;
	fp8_t t0, t1, t2;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);

	if (fp16_is_zero(a)) {
		fp16_zero(c);
		return 1;
	}

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);

		if (fp8_is_zero(a[1])) {
			/* special case: either a[0] is square and sqrt is purely 'real'
			 * or a[0] is non-square and sqrt is purely 'imaginary' */
			r = 1;
			if (fp8_is_sqr(a[0])) {
				fp8_srt(c[0], a[0]);
				fp8_zero(c[1]);
			} else {
				/* Compute a[0]/s^2. */
				fp8_set_dig(t0, 1);
				fp8_mul_art(t0, t0);
				fp8_inv(t0, t0);
				fp8_mul(t0, a[0], t0);
				fp8_zero(c[0]);
				if (!fp8_srt(c[1], t0)) {
					/* should never happen! */
					RLC_THROW(ERR_NO_VALID);
				}
			}
		} else {
			/* t0 = a[0]^2 - s^2 * a[1]^2 */
			fp8_sqr(t0, a[0]);
			fp8_sqr(t1, a[1]);
			fp8_mul_art(t2, t1);
			fp8_sub(t0, t0, t2);

			if (fp8_is_sqr(t0)) {
				fp8_srt(t1, t0);
				/* t0 = (a_0 + sqrt(t0)) / 2 */
				fp8_add(t0, a[0], t1);
				fp_hlv(t0[0][0][0], t0[0][0][0]);
				fp_hlv(t0[0][0][1], t0[0][0][1]);
				fp_hlv(t0[0][1][0], t0[0][1][0]);
				fp_hlv(t0[0][1][1], t0[0][1][1]);
				fp_hlv(t0[1][0][0], t0[1][0][0]);
				fp_hlv(t0[1][0][1], t0[1][0][1]);
				fp_hlv(t0[1][1][0], t0[1][1][0]);
				fp_hlv(t0[1][1][1], t0[1][1][1]);
				c0 = fp8_is_sqr(t0);
				/* t0 = (a_0 - sqrt(t0)) / 2 */
				fp8_sub(t1, a[0], t1);
				for (int i = 0; i < 2; i++) {
					for (int j = 0; j < 2; j++) {
						for (int k = 0; k < 2; k++) {
							fp_hlv(t1[i][j][k], t1[i][j][k]);
							dv_copy_cond(t0[i][j][k], t1[i][j][k], RLC_FP_DIGS,
								!c0);
						}
					}
				}
				/* Should always be a quadratic residue. */
				fp8_srt(t2, t0);
				/* c_0 = sqrt(t0) */
				fp8_copy(c[0], t2);

				/* c_1 = a_1 / (2 * sqrt(t0)) */
				fp8_dbl(t2, t2);
				fp8_inv(t2, t2);
				fp8_mul(c[1], a[1], t2);
				r = 1;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
	}
	return r;
}
