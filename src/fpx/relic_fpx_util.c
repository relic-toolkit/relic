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
 * Implementation of utilities in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"
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

TMPL_FPX_UTIL(fp4, fp2, 2);

TMPL_FPX_BIN(fp4, fp2, 2, 4);

TMPL_FPX_UTIL(fp6, fp2, 3);

TMPL_FPX_BIN(fp6, fp2, 3, 6);

TMPL_FPX_UTIL(fp8, fp4, 2);

TMPL_FPX_BIN_T2(fp8, fp4, 8);

TMPL_FPX_UTIL(fp9, fp3, 3);

TMPL_FPX_BIN(fp9, fp3, 3, 9);

TMPL_FPX_UTIL(fp12, fp6, 2);

TMPL_FPX_BIN_QC(fp12, fp6, fp2, 12);

TMPL_FPX_UTIL(fp16, fp8, 2);

TMPL_FPX_BIN_T2(fp16, fp8, 16);

TMPL_FPX_UTIL(fp18, fp9, 2);

TMPL_FPX_BIN_QC(fp18, fp9, fp3, 18);

TMPL_FPX_UTIL(fp24, fp8, 3);

TMPL_FPX_BIN_CQ(fp24, fp8, fp4, 24);

TMPL_FPX_UTIL(fp48, fp24, 2);

TMPL_FPX_BIN_QC(fp48, fp24, fp8, 48);

TMPL_FPX_UTIL(fp54, fp18, 3);

TMPL_FPX_BIN_CQ(fp54, fp18, fp9, 54);

