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
 * Implementation of exponentiation in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

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

TMPL_FPX_EXP(fp4);

TMPL_FPX_EXP(fp6);

TMPL_FPX_EXP_CYC(fp8);

TMPL_FPX_EXP_DIG(fp8);

TMPL_FPX_EXP(fp9);

TMPL_FPX_EXP_CYC(fp12);

TMPL_FPX_EXP_DIG(fp12);

TMPL_FPX_EXP_CYC(fp16);

TMPL_FPX_EXP_DIG(fp16);

TMPL_FPX_EXP_CYC(fp18);

TMPL_FPX_EXP_DIG(fp18);

TMPL_FPX_EXP_CYC(fp24);

TMPL_FPX_EXP_DIG(fp24);

TMPL_FPX_EXP_CYC(fp48);

TMPL_FPX_EXP_DIG(fp48);

TMPL_FPX_EXP_CYC(fp54);

TMPL_FPX_EXP_DIG(fp54);
