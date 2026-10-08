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
 * Implementation of arithmetic in the quadratic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_cyc_tmpl.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp2, fp, 2);

int fp2_size_bin(const fp2_t a, int pack) {
	if (pack) {
		if (fp2_test_cyc(a)) {
			return RLC_FP_BYTES + 1;
		} else {
			return 2 * RLC_FP_BYTES;
		}
	} else {
		return 2 * RLC_FP_BYTES;
	}
}

void fp2_read_bin(fp2_t a, const uint8_t *bin, size_t len) {
	if (len != RLC_FP_BYTES + 1 && len != 2 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == RLC_FP_BYTES + 1) {
		fp_read_bin(a[0], bin, RLC_FP_BYTES);
		fp_zero(a[1]);
		fp_set_bit(a[1], 0, bin[RLC_FP_BYTES]);
		fp2_upk(a, a);
	}
	if (len == 2 * RLC_FP_BYTES) {
		fp_read_bin(a[0], bin, RLC_FP_BYTES);
		fp_read_bin(a[1], bin + RLC_FP_BYTES, RLC_FP_BYTES);
	}
}

void fp2_write_bin(uint8_t *bin, size_t len, const fp2_t a, int pack) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		if (pack && fp2_test_cyc(a)) {
			if (len < RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
				return;
			} else {
				fp2_pck(t, a);
				fp_write_bin(bin, RLC_FP_BYTES, t[0]);
				bin[RLC_FP_BYTES] = fp_get_bit(t[1], 0);
			}
		} else {
			if (len < 2 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
				return;
			} else {
				fp_write_bin(bin, RLC_FP_BYTES, a[0]);
				fp_write_bin(bin + RLC_FP_BYTES, RLC_FP_BYTES, a[1]);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

TMPL_FPX_CMP(fp2, fp, 2);

#if FPX_QDR == BASIC || !defined(STRIP)

void fp2_add_basic(fp2_t c, const fp2_t a, const fp2_t b) {
	fp_add(c[0], a[0], b[0]);
	fp_add(c[1], a[1], b[1]);
}

void fp2_sub_basic(fp2_t c, const fp2_t a, const fp2_t b) {
	fp_sub(c[0], a[0], b[0]);
	fp_sub(c[1], a[1], b[1]);
}

void fp2_dbl_basic(fp2_t c, const fp2_t a) {
	/* 2 * (a_0 + a_1 * u) = 2 * a_0 + 2 * a_1 * u. */
	fp_dbl(c[0], a[0]);
	fp_dbl(c[1], a[1]);
}

#endif

#if FPX_QDR == INTEG || !defined(STRIP)

void fp2_add_integ(fp2_t c, const fp2_t a, const fp2_t b) {
	fp2_addm_low(c, a, b);
}

void fp2_sub_integ(fp2_t c, const fp2_t a, const fp2_t b) {
	fp2_subm_low(c, a, b);
}

void fp2_dbl_integ(fp2_t c, const fp2_t a) {
	fp2_dblm_low(c, a);
}

#endif

void fp2_add_dig(fp2_t c, const fp2_t a, dig_t dig) {
	fp_add_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
}

void fp2_sub_dig(fp2_t c, const fp2_t a, dig_t dig) {
	fp_sub_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
}

void fp2_neg(fp2_t c, const fp2_t a) {
	fp_neg(c[0], a[0]);
	fp_neg(c[1], a[1]);
}

#if FPX_QDR == BASIC || !defined(STRIP)

void fp2_mul_basic(fp2_t c, const fp2_t a, const fp2_t b) {
	dv_t t0, t1, t2, t3, t4;

	dv_null_all(t0, t1, t2, t3, t4);

	RLC_TRY {
		dv_new_all(t0, t1, t2, t3, t4);

		/* Karatsuba algorithm. */

		/* t2 = a_0 + a_1, t1 = b_0 + b_1. */
		fp_add(t2, a[0], a[1]);
		fp_add(t1, b[0], b[1]);

		/* t3 = (a_0 + a_1) * (b_0 + b_1). */
		fp_muln_low(t3, t2, t1);

		/* t0 = a_0 * b_0, t4 = a_1 * b_1. */
		fp_muln_low(t0, a[0], b[0]);
		fp_muln_low(t4, a[1], b[1]);

		/* t2 = (a_0 * b_0) + (a_1 * b_1). */
		fp_addc_low(t2, t0, t4);

		/* t1 = (a_0 * b_0) + i^2 * (a_1 * b_1). */
		fp_subc_low(t1, t0, t4);
		for (int i = -1; i > fp_prime_get_qnr(); i--) {
			fp_subc_low(t1, t1, t4);
		}
		for (int i = 1; i < fp_prime_get_qnr(); i++) {
			fp_addc_low(t1, t1, t4);
		}

		/* c_0 = t1 mod p. */
		fp_rdc(c[0], t1);

		/* t4 = t3 - t2. */
		fp_subc_low(t4, t3, t2);

		/* c_1 = t4 mod p. */
		fp_rdc(c[1], t4);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(t0, t1, t2, t3, t4);
	}
}

void fp2_mul_nor_basic(fp2_t c, const fp2_t a) {
	fp2_t t;
	bn_t b;

	fp2_null(t);
	bn_null(b);

	RLC_TRY {
		fp2_new(t);
		bn_new(b);

#ifdef FP_QNRES
		/* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
		fp_copy(t[0], a[1]);
		fp_add(c[1], a[0], a[1]);
		fp_sub(c[0], a[0], t[0]);
#else
		int qnr = fp2_field_get_qnr();

		switch (fp_prime_get_mod8()) {
			case 1:
			case 5:
				/* If p = 1,5 mod 8, (i) is a QNR/CNR. */
				fp2_mul_art(c, a);
				break;
			case 3:
				if (qnr == 1) {
					/* If p = 3 mod 8, (1 + i) is a QNR/CNR. */
					fp_neg(t[0], a[1]);
					fp_add(c[1], a[0], a[1]);
					fp_add(c[0], t[0], a[0]);
					break;
				}
				/* Fall through - otherwise, try the next one. */
			case 7:
				/* If p = 7 mod 8, we choose (2^k + i) as a QNR/CNR. */
				fp2_mul_art(t, a);
				fp2_copy(c, a);
				while (qnr > 1) {
					fp2_dbl(c, c);
					qnr = qnr >> 1;
				}
				fp2_add(c, c, t);
				break;
			default:
				RLC_THROW(ERR_NO_VALID);
				break;
		}
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
		bn_free(b);
	}
}

#endif

#if FPX_QDR == INTEG || !defined(STRIP)

void fp2_mul_integ(fp2_t c, const fp2_t a, const fp2_t b) {
	fp2_mulm_low(c, a, b);
}

void fp2_mul_nor_integ(fp2_t c, const fp2_t a) {
	fp2_norm_low(c, a);
}

#endif

void fp2_mul_art(fp2_t c, const fp2_t a) {
	fp_t t;

	fp_null(t);

	RLC_TRY {
		fp_new(t);

#ifdef FP_QNRES
		/* (a_0 + a_1 * i) * i = -a_1 + a_0 * i. */
		fp_copy(t, a[0]);
		fp_neg(c[0], a[1]);
		fp_copy(c[1], t);
#else
		/* (a_0 + a_1 * i) * i = (a_1 * i^2) + a_0 * i. */
		fp_copy(t, a[0]);
		fp_neg(c[0], a[1]);
		for (int i = -1; i > fp_prime_get_qnr(); i--) {
			fp_sub(c[0], c[0], a[1]);
		}
		for (int i = 0; i <= fp_prime_get_qnr(); i++) {
			fp_add(c[0], c[0], a[1]);
		}
		fp_copy(c[1], t);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t);
	}
}

void fp2_mul_frb(fp2_t c, const fp2_t a, int i, int j) {
	ctx_t *ctx = core_get();

	fp2_copy(c, a);
#if ALLOC == AUTO
	switch(i) {
		case 1:
			fp2_mul(c, c, ctx->fp2_p1[j - 1]);
			break;
		case 2:
			fp2_mul(c, c, ctx->fp2_p2[j - 1]);
			break;
	}
#else
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		switch(i) {
			case 1:
				fp_copy(t[0], ctx->fp2_p1[j - 1][0]);
				fp_copy(t[1], ctx->fp2_p1[j - 1][1]);
				break;
			case 2:
				fp_copy(t[0], ctx->fp2_p2[j - 1][0]);
				fp_copy(t[1], ctx->fp2_p2[j - 1][1]);
				break;
		}

		fp2_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
#endif
}

void fp2_mul_dig(fp2_t c, const fp2_t a, dig_t b) {
	fp_mul_dig(c[0], a[0], b);
	fp_mul_dig(c[1], a[1], b);
}

#if FPX_QDR == BASIC || !defined(STRIP)

void fp2_sqr_basic(fp2_t c, const fp2_t a) {
	fp_t t0, t1, t2;

	fp_null_all(t0, t1, t2);

	RLC_TRY {
		fp_new_all(t0, t1, t2);

		/* t0 = (a_0 + a_1). */
		fp_add(t0, a[0], a[1]);

		/* t1 = (a_0 - a_1). */
		fp_sub(t1, a[0], a[1]);

		/* t1 = a_0 + u^2 * a_1. */
		for (int i = -1; i > fp_prime_get_qnr(); i--) {
			fp_sub(t1, t1, a[1]);
		}
		for (int i = 1; i < fp_prime_get_qnr(); i++) {
			fp_add(t1, t1, a[1]);
		}
		
		if (fp_prime_get_qnr() == -1) {
			/* t2 = 2 * a_0. */
			fp_dbl(t2, a[0]);
			/* c_1 = 2 * a_0 * a_1. */
			fp_mul(c[1], t2, a[1]);
			/* c_0 = a_0^2 + a_1^2 * u^2. */
			fp_mul(c[0], t0, t1);
		} else {
			/* c_1 = a_0 * a_1. */
			fp_mul(c[1], a[0], a[1]);
			/* c_0 = a_0^2 + a_1^2 * u^2. */
			fp_mul(c[0], t0, t1);
			for (int i = -1; i > fp_prime_get_qnr(); i--) {
				fp_add(c[0], c[0], c[1]);
			}
			for (int i = 1; i < fp_prime_get_qnr(); i++) {
				fp_add(c[0], c[0], c[1]);
			}

			/* c_1 = 2 * a_0 * a_1. */
			fp_dbl(c[1], c[1]);
		}
		/* c = c_0 + c_1 * u. */
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free_all(t0, t1, t2);
	}
}

#endif

#if FPX_QDR == INTEG || !defined(STRIP)

void fp2_sqr_integ(fp2_t c, const fp2_t a) {
	fp2_sqrm_low(c, a);
}

#endif

void fp2_inv(fp2_t c, const fp2_t a) {
	fp_t t0, t1;

	fp_null_all(t0, t1);

	RLC_TRY {
		fp_new_all(t0, t1);

		/* t0 = a_0^2, t1 = a_1^2. */
		fp_sqr(t0, a[0]);
		fp_sqr(t1, a[1]);

		/* t1 = 1/(a_0^2 + a_1^2). */
#ifndef FP_QNRES
		if (fp_prime_get_qnr() != -1) {
			if (fp_prime_get_qnr() == -2) {
				fp_dbl(t1, t1);
				fp_add(t0, t0, t1);
			} else {
				if (fp_prime_get_qnr() < 0) {
					fp_mul_dig(t1, t1, -fp_prime_get_qnr());
					fp_add(t0, t0, t1);
				} else {
					fp_mul_dig(t1, t1, fp_prime_get_qnr());
					fp_sub(t0, t0, t1);
				}
			}
		} else {
			fp_add(t0, t0, t1);
		}
#else
		fp_add(t0, t0, t1);
#endif

		fp_inv(t1, t0);

		/* c_0 = a_0/(a_0^2 + a_1^2). */
		fp_mul(c[0], a[0], t1);
		/* c_1 = - a_1/(a_0^2 + a_1^2). */
		fp_mul(c[1], a[1], t1);
		fp_neg(c[1], c[1]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free_all(t0, t1);
	}
}

void fp2_inv_cyc(fp2_t c, const fp2_t a) {
	fp_copy(c[0], a[0]);
	fp_neg(c[1], a[1]);
}

TMPL_FPX_INV_SIM(fp2);

void fp2_exp(fp2_t c, const fp2_t a, const bn_t b) {
	fp2_t t;

	if (bn_is_zero(b)) {
		fp2_set_dig(c, 1);
		return;
	}

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp2_copy(t, a);
		for (int i = bn_bits(b) - 2; i >= 0; i--) {
			fp2_sqr(t, t);
			if (bn_get_bit(b, i)) {
				fp2_mul(t, t, a);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp2_inv(c, t);
		} else {
			fp2_copy(c, t);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

void fp2_exp_dig(fp2_t c, const fp2_t a, dig_t b) {
	fp2_t t;

	if (b == 0) {
		fp2_set_dig(c, 1);
		return;
	}

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp2_copy(t, a);
		for (int i = util_bits_dig(b) - 2; i >= 0; i--) {
			fp2_sqr(t, t);
			if (b & ((dig_t)1 << i)) {
				fp2_mul(t, t, a);
			}
		}

		fp2_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

void fp2_frb(fp2_t c, const fp2_t a, int i) {
	switch (i % 2) {
		case 0:
			fp2_copy(c, a);
			break;
		case 1:
			/* (a_0 + a_1 * u)^p = a_0 - a_1 * u. */
			fp_copy(c[0], a[0]);
			fp_neg(c[1], a[1]);
			break;
	}
}

TMPL_FPX_CONV_CYC_QUAD(fp2);

TMPL_FPX_TEST_CYC_QUAD(fp2);

TMPL_EXP_CYC_NAF(fp2, fp2_sqr);

TMPL_EXP_CYC_SIM(fp2, fp2_sqr);

void fp2_pck(fp2_t c, const fp2_t a) {
	int b = fp_get_bit(a[1], 0);
	fp2_copy(c, a);
	if (fp2_test_cyc(a)) {
		fp_copy(c[0], a[0]);
		fp_zero(c[1]);
		fp_set_bit(c[1], 0, b);
	}
}

int fp2_upk(fp2_t c, const fp2_t a) {
	if (fp_bits(a[1]) <= 1) {
		int result, b = fp_get_bit(a[1], 0);
		fp_t t, u;

		fp_null_all(t, u);

		RLC_TRY {
			fp_new_all(t, u);

			/* For i^2 = qnr, a_0^2 - qnr * a_1^2 = 1, thus
			 * a_1^2 = (a_0^2 - 1) / qnr. */
			fp_sqr(t, a[0]);
			fp_sub_dig(t, t, 1);
			if (fp_prime_get_qnr() < 0) {
				fp_set_dig(u, -fp_prime_get_qnr());
				fp_neg(u, u);
			} else {
				fp_set_dig(u, fp_prime_get_qnr());
			}
			fp_inv(u, u);
			fp_mul(t, t, u);

			/* a_1 = sqrt((a_0^2 - 1) / qnr). */
			result = fp_srt(t, t);

			if (result) {
				/* Verify if least significant bit of the result matches the
				 * compressed second coordinate. */
				if (fp_get_bit(t, 0) != b) {
					fp_neg(t, t);
				}
				fp_copy(c[0], a[0]);
				fp_copy(c[1], t);
			}
		} RLC_CATCH_ANY {
			result = 0;
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			fp_free_all(t, u);
		}
		return result;
	} else {
		fp2_copy(c, a);
		return 1;
	}
}
