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
 * Implementation of arithmetic in the cubic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp3, fp, 3);

int fp3_size_bin(const fp3_t a, int pack) {
	(void)a;
	(void)pack;
	return 3 * RLC_FP_BYTES;
}

void fp3_read_bin(fp3_t a, const uint8_t *bin, size_t len) {
	if (len != 3 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp_read_bin(a[0], bin, RLC_FP_BYTES);
	fp_read_bin(a[1], bin + RLC_FP_BYTES, RLC_FP_BYTES);
	fp_read_bin(a[2], bin + 2 * RLC_FP_BYTES, RLC_FP_BYTES);
}

void fp3_write_bin(uint8_t *bin, size_t len, const fp3_t a, int pack) {
	(void)pack;
	if (len != 3 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp_write_bin(bin, RLC_FP_BYTES, a[0]);
	fp_write_bin(bin + RLC_FP_BYTES, RLC_FP_BYTES, a[1]);
	fp_write_bin(bin + 2 * RLC_FP_BYTES, RLC_FP_BYTES, a[2]);
}

TMPL_FPX_CMP(fp3, fp, 3);

#if FPX_CBC == BASIC || !defined(STRIP)

void fp3_add_basic(fp3_t c, const fp3_t a, const fp3_t b) {
	fp_add(c[0], a[0], b[0]);
	fp_add(c[1], a[1], b[1]);
	fp_add(c[2], a[2], b[2]);
}

void fp3_sub_basic(fp3_t c, const fp3_t a, const fp3_t b) {
	fp_sub(c[0], a[0], b[0]);
	fp_sub(c[1], a[1], b[1]);
	fp_sub(c[2], a[2], b[2]);
}

void fp3_dbl_basic(fp3_t c, const fp3_t a) {
  /* 2 * (a_0 + a_1 * u) = 2 * a_0 + 2 * a_1 * u. */
	fp_dbl(c[0], a[0]);
	fp_dbl(c[1], a[1]);
	fp_dbl(c[2], a[2]);
}

#endif

void fp3_add_dig(fp3_t c, const fp3_t a, dig_t dig) {
	fp_add_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
	fp_copy(c[2], a[2]);
}

void fp3_sub_dig(fp3_t c, const fp3_t a, dig_t dig) {
	fp_sub_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
	fp_copy(c[2], a[2]);
}

void fp3_neg(fp3_t c, const fp3_t a) {
	fp_neg(c[0], a[0]);
	fp_neg(c[1], a[1]);
	fp_neg(c[2], a[2]);
}

#if FPX_CBC == INTEG || !defined(STRIP)

void fp3_add_integ(fp3_t c, const fp3_t a, const fp3_t b) {
	fp3_addm_low(c, a, b);
}

void fp3_sub_integ(fp3_t c, const fp3_t a, const fp3_t b) {
	fp3_subm_low(c, a, b);
}

void fp3_dbl_integ(fp3_t c, const fp3_t a) {
	fp3_dblm_low(c, a);
}

#endif

#if FPX_CBC == BASIC || !defined(STRIP)

void fp3_mul_basic(fp3_t c, const fp3_t a, const fp3_t b) {
	dv_t t, t0, t1, t2, t3, t4, t5, t6;

	dv_null_all(t, t0, t1, t2, t3, t4, t5, t6);

	RLC_TRY {
		dv_new_all(t, t0, t1, t2, t3, t4, t5, t6);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0, t1 = a_1 * b_1, t2 = a_2 * b_2. */
		fp_muln_low(t0, a[0], b[0]);
		fp_muln_low(t1, a[1], b[1]);
		fp_muln_low(t2, a[2], b[2]);

		/* t3 = (a_1 + a_2) * (b_1 + b_2). */
		fp_add(t3, a[1], a[2]);
		fp_add(t4, b[1], b[2]);
		fp_muln_low(t, t3, t4);
#ifdef RLC_FP_ROOM
		fp_addd_low(t6, t1, t2);
#else
		fp_addc_low(t6, t1, t2);
#endif
		fp_subc_low(t4, t, t6);
		fp_addc_low(t3, t0, t4);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_addc_low(t3, t3, t4);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_subc_low(t3, t3, t4);
		}

		fp_add(t4, a[0], a[1]);
		fp_add(t5, b[0], b[1]);
		fp_muln_low(t, t4, t5);
#ifdef RLC_FP_ROOM
		fp_addd_low(t4, t0, t1);
#else
		fp_addc_low(t4, t0, t1);
#endif
		fp_subc_low(t4, t, t4);
		fp_addc_low(t4, t4, t2);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_addc_low(t4, t4, t2);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_subc_low(t4, t4, t2);
		}

		fp_add(t5, a[0], a[2]);
		fp_add(t6, b[0], b[2]);
		fp_muln_low(t, t5, t6);
#ifdef RLC_FP_ROOM
		fp_addd_low(t6, t0, t2);
#else
		fp_addc_low(t6, t0, t2);
#endif
		fp_addc_low(t6, t0, t2);
		fp_subc_low(t5, t, t6);
		fp_addc_low(t5, t5, t1);

		/* c_0 = t3 mod p. */
		fp_rdc(c[0], t3);

		/* c_1 = t4 mod p. */
		fp_rdc(c[1], t4);

		/* c_2 = t5 mod p. */
		fp_rdc(c[2], t5);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(t, t0, t1, t2, t3, t4, t5, t6);
	}
}

#endif

#if FPX_CBC == INTEG || !defined(STRIP)

void fp3_mul_integ(fp3_t c, const fp3_t a, const fp3_t b) {
	fp3_mulm_low(c, a, b);
}

#endif

void fp3_mul_art(fp3_t c, const fp3_t a) {
	fp_t t;

	fp_null(t);

	RLC_TRY {
		fp_new(t);

		/* (a_0 + a_1 * u + a_2 * u^2) * u = a_0 * u + a_1 * u^2 + a_2 * u^3. */
		fp_copy(t, a[0]);
		fp_copy(c[0], a[2]);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(c[0], c[0], a[2]);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(c[0], c[0], a[2]);
		}
		fp_copy(c[2], a[1]);
		fp_copy(c[1], t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t);
	}
}

void fp3_mul_nor(fp3_t c, const fp3_t a) {
	fp3_t t, u;

	fp3_null_all(t, u);

	RLC_TRY {
		fp3_new_all(t, u);

		fp3_mul_art(t, a);

		int cnr = fp3_field_get_cnr();
		cnr = (cnr < 0 ? -cnr : cnr);
		switch (fp_prime_get_mod18()) {
			case 1:
			case 7:
				if (cnr != 0) {
					fp3_copy(u, a);
					while (cnr > 1) {
						fp3_dbl(u, u);
						if (cnr & 1) {
							fp3_add(u, u, a);
						}
						cnr = cnr >> 1;
					}
					if (fp3_field_get_cnr() > 0) {
						fp3_add(t, t, u);
					} else {
						fp3_sub(t, t, u);
					}
				}
				break;
		}

		fp3_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free_all(t, u);
	}
}

void fp3_mul_frb(fp3_t c, const fp3_t a, int i, int j) {
	ctx_t *ctx = core_get();

	fp3_copy(c, a);
	if (i % 3 == 0) {
		if (j % 3 == 1) {
			fp_mul(c[1], c[1], ctx->fp3_p0[0]);
			fp_mul(c[2], c[2], ctx->fp3_p0[1]);
		}
		if (j % 3 == 2) {
			fp_mul(c[1], c[1], ctx->fp3_p0[1]);
			fp_mul(c[2], c[2], ctx->fp3_p0[0]);
		}
	}

	if (fp3_field_get_cnr() == 0) {
		switch (i % 3) {
			case 1:
				fp_mul(c[0], c[0], ctx->fp3_p1[j - 1][0]);
				fp_mul(c[1], c[1], ctx->fp3_p1[j - 1][0]);
				fp_mul(c[2], c[2], ctx->fp3_p1[j - 1][0]);
				for (int k = 0; k < (j * ctx->frb3[0]) % 3; k++) {
					fp3_mul_nor(c, c);
				}
				break;
			case 2:
				fp_mul(c[0], c[0], ctx->fp3_p2[j - 1][0]);
				fp_mul(c[1], c[1], ctx->fp3_p2[j - 1][0]);
				fp_mul(c[2], c[2], ctx->fp3_p2[j - 1][0]);
				for (int k = 0; k < ctx->frb3[j]; k++) {
					fp3_mul_nor(c, c);
				}
				break;
		}
	} else {
#if ALLOC == AUTO
		switch (i) {
			case 1:
				fp3_mul(c, c, ctx->fp3_p1[j - 1]);
				break;
			case 2:
				fp3_mul(c, c, ctx->fp3_p2[j - 1]);
				break;
		}
#else
		fp3_t t;

		fp3_null(t);

		RLC_TRY {
			fp3_new(t);

			switch (i) {
				case 1:
					fp_copy(t[0], ctx->fp3_p1[j - 1][0]);
					fp_copy(t[1], ctx->fp3_p1[j - 1][1]);
					fp_copy(t[2], ctx->fp3_p1[j - 1][2]);
					fp3_mul(c, c, t);
					break;
				case 2:
					fp_copy(t[0], ctx->fp3_p2[j - 1][0]);
					fp_copy(t[1], ctx->fp3_p2[j - 1][1]);
					fp_copy(t[2], ctx->fp3_p2[j - 1][2]);
					fp3_mul(c, c, t);
					break;
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp3_free(t);
		}
#endif
	}
}

void fp3_mul_dig(fp3_t c, const fp3_t a, dig_t b) {
	fp_mul_dig(c[0], a[0], b);
	fp_mul_dig(c[1], a[1], b);
	fp_mul_dig(c[2], a[2], b);
}

#if FPX_CBC == BASIC || !defined(STRIP)

void fp3_sqr_basic(fp3_t c, const fp3_t a) {
	dv_t t0, t1, t2, t3, t4;

	dv_null_all(t0, t1, t2, t3, t4);

	RLC_TRY {
		dv_new_all(t0, t1, t2, t3, t4);

		/* t0 = a_0^2. */
		fp_sqrn_low(t0, a[0]);

		/* t1 = 2 * a_1 * a_2. */
		fp_dbl(t2, a[1]);
		fp_muln_low(t1, t2, a[2]);

		/* t3 = (a_0 + a_2 + a_1)^2, t4 = (a_0 + a_2 - a_1)^2. */
		fp_add(t3, a[0], a[2]);
		fp_add(t4, t3, a[1]);
		fp_sub(t2, t3, a[1]);
		fp_sqrn_low(t3, t4);
		fp_sqrn_low(t4, t2);

		/* t2 = a_2^2. */
		fp_sqrn_low(t2, a[2]);

		/* t4 = (t4 + t3)/2. */
#ifdef RLC_FP_ROOM
		fp_addd_low(t4, t4, t3);
#else
		fp_addc_low(t4, t4, t3);
#endif
		fp_hlvd_low(t4, t4);

		/* t3 = t3 - t4 - t1. */
		fp_subc_low(t3, t3, t4);
		fp_subc_low(t3, t3, t1);

		/* c_2 = t4 - t0 - t2. */
		fp_subc_low(t4, t4, t0);
		fp_subc_low(t4, t4, t2);
		fp_rdc(c[2], t4);

		/* c_0 = t0 + t1 * B. */
		for (int i = 1; i <= fp_prime_get_cnr(); i++) {
			fp_addc_low(t0, t0, t1);
		}
		for (int i = -1; i >= fp_prime_get_cnr(); i--) {
			fp_subc_low(t0, t0, t1);
		}
		fp_rdc(c[0], t0);

		/* c_1 = t3 + t2 * B. */
		for (int i = 1; i <= fp_prime_get_cnr(); i++) {
			fp_addc_low(t3, t3, t2);
		}
		for (int i = -1; i >= fp_prime_get_cnr(); i--) {
			fp_subc_low(t3, t3, t2);
		}
		fp_rdc(c[1], t3);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(t0, t1, t2, t3, t4);
	}
}

#endif

#if FPX_CBC == INTEG || !defined(STRIP)

void fp3_sqr_integ(fp3_t c, const fp3_t a) {
	fp3_sqrm_low(c, a);
}

#endif

#if PP_CBC == BASIC || !defined(STRIP)

void fp3_rdc_basic(fp3_t c, dv3_t a) {
	fp_rdc(c[0], a[0]);
	fp_rdc(c[1], a[1]);
	fp_rdc(c[2], a[2]);
}

#endif

#if PP_CBC == INTEG || !defined(STRIP)

void fp3_rdc_integ(fp3_t c, dv3_t a) {
	fp3_rdcn_low(c, a);
}

#endif

void fp3_inv(fp3_t c, const fp3_t a) {
	fp_t v0;
	fp_t v1;
	fp_t v2;
	fp_t t0;

	fp_null_all(v0, v1, v2, t0);

	RLC_TRY {
		fp_new_all(v0, v1, v2, t0);

		/* v0 = a_0^2 - B * a_1 * a_2. */
		fp_sqr(t0, a[0]);
		fp_mul(v0, a[1], a[2]);
		fp_copy(v2, v0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(v2, v2, v0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(v2, v2, v0);
		}
		fp_sub(v0, t0, v2);

		/* v1 = B * a_2^2 - a_0 * a_1. */
		fp_sqr(t0, a[2]);
		fp_copy(v2, t0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(v2, v2, t0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(v2, v2, t0);
		}
		fp_mul(v1, a[0], a[1]);
		fp_sub(v1, v2, v1);

		/* v2 = a_1^2 - a_0 * a_2. */
		fp_sqr(t0, a[1]);
		fp_mul(v2, a[0], a[2]);
		fp_sub(v2, t0, v2);

		fp_mul(t0, a[1], v2);
		fp_copy(c[1], t0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(c[1], c[1], t0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(c[1], c[1], t0);
		}

		fp_mul(c[0], a[0], v0);

		fp_mul(t0, a[2], v1);
		fp_copy(c[2], t0);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(c[2], c[2], t0);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(c[2], c[2], t0);
		}

		fp_add(t0, c[0], c[1]);
		fp_add(t0, t0, c[2]);
		fp_inv(t0, t0);

		fp_mul(c[0], v0, t0);
		fp_mul(c[1], v1, t0);
		fp_mul(c[2], v2, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free_all(v0, v1, v2, t0);
	}
}

TMPL_FPX_INV_SIM(fp3);

void fp3_exp(fp3_t c, const fp3_t a, const bn_t b) {
	fp3_t t;

	if (bn_is_zero(b)) {
		fp3_set_dig(c, 1);
		return;
	}

	fp3_null(t);

	RLC_TRY {
		fp3_new(t);

		fp3_copy(t, a);

		for (int i = bn_bits(b) - 2; i >= 0; i--) {
			fp3_sqr(t, t);
			if (bn_get_bit(b, i)) {
				fp3_mul(t, t, a);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp3_inv(c, t);
		} else {
			fp3_copy(c, t);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t);
	}
}

void fp3_frb(fp3_t c, const fp3_t a, int i) {
	fp3_copy(c, a);
	switch (i % 3) {
		case 1:
			fp3_mul_frb(c, c, 0, 1);
			break;
		case 2:
			fp3_mul_frb(c, c, 0, 2);
			break;
	}
}
