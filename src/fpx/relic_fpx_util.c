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

void fp2_copy(fp2_t c, const fp2_t a) {
	fp_copy(c[0], a[0]);
	fp_copy(c[1], a[1]);
}

void fp2_copy_sec(fp2_t c, const fp2_t a, dig_t bit) {
	fp_copy_sec(c[0], a[0], bit);
	fp_copy_sec(c[1], a[1], bit);
}

void fp2_zero(fp2_t a) {
	fp_zero(a[0]);
	fp_zero(a[1]);
}

int fp2_is_zero(const fp2_t a) {
	return fp_is_zero(a[0]) && fp_is_zero(a[1]);
}

void fp2_rand(fp2_t a) {
	fp_rand(a[0]);
	fp_rand(a[1]);
}

void fp2_print(const fp2_t a) {
	fp_print(a[0]);
	fp_print(a[1]);
}

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

void fp2_set_dig(fp2_t a, const dig_t b) {
	fp_set_dig(a[0], b);
	fp_zero(a[1]);
}

void fp3_copy(fp3_t c, const fp3_t a) {
	fp_copy(c[0], a[0]);
	fp_copy(c[1], a[1]);
	fp_copy(c[2], a[2]);
}

void fp3_copy_sec(fp3_t c, const fp3_t a, dig_t bit) {
	fp_copy_sec(c[0], a[0], bit);
	fp_copy_sec(c[1], a[1], bit);
	fp_copy_sec(c[2], a[2], bit);
}

void fp3_zero(fp3_t a) {
	fp_zero(a[0]);
	fp_zero(a[1]);
	fp_zero(a[2]);
}

int fp3_is_zero(const fp3_t a) {
	return fp_is_zero(a[0]) && fp_is_zero(a[1]) && fp_is_zero(a[2]);
}

void fp3_rand(fp3_t a) {
	fp_rand(a[0]);
	fp_rand(a[1]);
	fp_rand(a[2]);
}

void fp3_print(const fp3_t a) {
	fp_print(a[0]);
	fp_print(a[1]);
	fp_print(a[2]);
}

int fp3_size_bin(const fp3_t a) {
	(void)a;
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

void fp3_write_bin(uint8_t *bin, size_t len, const fp3_t a) {
	if (len != 3 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp_write_bin(bin, RLC_FP_BYTES, a[0]);
	fp_write_bin(bin + RLC_FP_BYTES, RLC_FP_BYTES, a[1]);
	fp_write_bin(bin + 2 * RLC_FP_BYTES, RLC_FP_BYTES, a[2]);
}

void fp3_set_dig(fp3_t a, const dig_t b) {
	fp_set_dig(a[0], b);
	fp_zero(a[1]);
	fp_zero(a[2]);
}

TMPL_FPX_UTIL(fp4, fp2, 2);

int fp4_size_bin(const fp4_t a) {
	(void)a;
	return 4 * RLC_FP_BYTES;
}

void fp4_read_bin(fp4_t a, const uint8_t *bin, size_t len) {
	if (len != 4 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_read_bin(a[0], bin, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[1], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
}

void fp4_write_bin(uint8_t *bin, size_t len, const fp4_t a) {
	if (len != 4 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0], 0);
	fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1], 0);
}

TMPL_FPX_UTIL(fp6, fp2, 3);

int fp6_size_bin(const fp6_t a) {
	(void)a;
	return 6 * RLC_FP_BYTES;
}

void fp6_read_bin(fp6_t a, const uint8_t *bin, size_t len) {
	if (len != 6 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_read_bin(a[0], bin, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[1], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
	fp2_read_bin(a[2], bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
}

void fp6_write_bin(uint8_t *bin, size_t len, const fp6_t a) {
	if (len != 6 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0], 0);
	fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1], 0);
	fp2_write_bin(bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[2], 0);
}

TMPL_FPX_UTIL(fp8, fp4, 2);

int fp8_size_bin(const fp8_t a, int pack) {
	if (pack) {
		if (fp8_test_cyc(a)) {
			return 4 * RLC_FP_BYTES;
		} else {
			return 8 * RLC_FP_BYTES;
		}
	} else {
		return 8 * RLC_FP_BYTES;
	}
}

void fp8_read_bin(fp8_t a, const uint8_t *bin, size_t len) {
	if (len != 8 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp4_read_bin(a[0], bin, 4 * RLC_FP_BYTES);
	fp4_read_bin(a[1], bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
}

void fp8_write_bin(uint8_t *bin, size_t len, const fp8_t a, int pack) {
	(void)pack;
	if (len != 8 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp4_write_bin(bin, 4 * RLC_FP_BYTES, a[0]);
	fp4_write_bin(bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[1]);
}

TMPL_FPX_UTIL(fp9, fp3, 3);

int fp9_size_bin(const fp9_t a) {
	(void)a;
	return 9 * RLC_FP_BYTES;
}

void fp9_read_bin(fp9_t a, const uint8_t *bin, size_t len) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_read_bin(a[0], bin, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[1], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
	fp3_read_bin(a[2], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
}

void fp9_write_bin(uint8_t *bin, size_t len, const fp9_t a) {
	if (len != 9 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp3_write_bin(bin, 3 * RLC_FP_BYTES, a[0]);
	fp3_write_bin(bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[1]);
	fp3_write_bin(bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[2]);
}

TMPL_FPX_UTIL(fp12, fp6, 2);

int fp12_size_bin(const fp12_t a, int pack) {
	if (pack) {
		if (fp12_test_cyc(a)) {
			return 8 * RLC_FP_BYTES;
		} else {
			return 12 * RLC_FP_BYTES;
		}
	} else {
		return 12 * RLC_FP_BYTES;
	}
}

void fp12_read_bin(fp12_t a, const uint8_t *bin, size_t len) {
	if (len != 8 * RLC_FP_BYTES && len != 12 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 8 * RLC_FP_BYTES) {
		fp2_zero(a[0][0]);
		fp2_read_bin(a[0][1], bin, 2 * RLC_FP_BYTES);
		fp2_read_bin(a[0][2], bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp2_read_bin(a[1][0], bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp2_zero(a[1][1]);
		fp2_read_bin(a[1][2], bin + 6 * RLC_FP_BYTES, 2 * RLC_FP_BYTES);
		fp12_back_cyc(a, a);
	}
	if (len == 12 * RLC_FP_BYTES) {
		fp6_read_bin(a[0], bin, 6 * RLC_FP_BYTES);
		fp6_read_bin(a[1], bin + 6 * RLC_FP_BYTES, 6 * RLC_FP_BYTES);
	}
}

void fp12_write_bin(uint8_t *bin, size_t len, const fp12_t a, int pack) {
	fp12_t t;

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		if (pack) {
			if (len != 8 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp12_pck(t, a);
			fp2_write_bin(bin, 2 * RLC_FP_BYTES, a[0][1], 0);
			fp2_write_bin(bin + 2 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[0][2], 0);
			fp2_write_bin(bin + 4 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1][0], 0);
			fp2_write_bin(bin + 6 * RLC_FP_BYTES, 2 * RLC_FP_BYTES, a[1][2], 0);
		} else {
			if (len != 12 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp6_write_bin(bin, 6 * RLC_FP_BYTES, a[0]);
			fp6_write_bin(bin + 6 * RLC_FP_BYTES, 6 * RLC_FP_BYTES, a[1]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp12_free(t);
	}
}

TMPL_FPX_UTIL(fp16, fp8, 2);

int fp16_size_bin(const fp16_t a, int pack) {
	if (pack) {
		if (fp16_test_cyc(a)) {
			return 8 * RLC_FP_BYTES;
		} else {
			return 16 * RLC_FP_BYTES;
		}
	} else {
		return 16 * RLC_FP_BYTES;
	}
}

void fp16_read_bin(fp16_t a, const uint8_t *bin, size_t len) {
	if (len != 16 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp8_read_bin(a[0], bin, 8 * RLC_FP_BYTES);
	fp8_read_bin(a[1], bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
}

void fp16_write_bin(uint8_t *bin, size_t len, const fp16_t a, int pack) {
	(void)pack;
	if (len != 16 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	fp8_write_bin(bin, 8 * RLC_FP_BYTES, a[0], 0);
	fp8_write_bin(bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[1], 0);
}

TMPL_FPX_UTIL(fp18, fp9, 2);

int fp18_size_bin(const fp18_t a, int pack) {
	if (pack) {
		if (fp18_test_cyc(a)) {
			return 12 * RLC_FP_BYTES;
		} else {
			return 18 * RLC_FP_BYTES;
		}
	} else {
		return 18 * RLC_FP_BYTES;
	}
}

void fp18_read_bin(fp18_t a, const uint8_t *bin, size_t len) {
	if (len != 12 * RLC_FP_BYTES && len != 18 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 12 * RLC_FP_BYTES) {
		fp3_zero(a[0][0]);
		fp3_read_bin(a[0][1], bin, 3 * RLC_FP_BYTES);
		fp3_read_bin(a[0][2], bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
		fp3_read_bin(a[1][0], bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
		fp3_zero(a[1][1]);
		fp3_read_bin(a[1][2], bin + 9 * RLC_FP_BYTES, 3 * RLC_FP_BYTES);
		fp18_back_cyc(a, a);
	}
	if (len == 18 * RLC_FP_BYTES) {
		fp9_read_bin(a[0], bin, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[1], bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
	}
}

void fp18_write_bin(uint8_t *bin, size_t len, const fp18_t a, int pack) {
	fp18_t t;

	fp18_null(t);

	RLC_TRY {
		fp18_new(t);

		if (pack) {
			if (len != 12 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp18_pck(t, a);
			fp3_write_bin(bin, 3 * RLC_FP_BYTES, a[0][1]);
			fp3_write_bin(bin + 3 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[0][2]);
			fp3_write_bin(bin + 6 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[1][0]);
			fp3_write_bin(bin + 9 * RLC_FP_BYTES, 3 * RLC_FP_BYTES, a[1][2]);
		} else {
			if (len != 18 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp9_write_bin(bin, 9 * RLC_FP_BYTES, a[0]);
			fp9_write_bin(bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[1]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp18_free(t);
	}
}

TMPL_FPX_UTIL(fp24, fp8, 3);

int fp24_size_bin(const fp24_t a, int pack) {
	if (pack) {
		if (fp24_test_cyc(a)) {
			return 16 * RLC_FP_BYTES;
		} else {
			return 24 * RLC_FP_BYTES;
		}
	} else {
		return 24 * RLC_FP_BYTES;
	}
}

void fp24_read_bin(fp24_t a, const uint8_t *bin, size_t len) {
	if (len != 16 * RLC_FP_BYTES && len != 24 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 16 * RLC_FP_BYTES) {
		fp4_zero(a[0][0]);
		fp4_zero(a[0][1]);
		fp4_read_bin(a[1][0], bin, 4 * RLC_FP_BYTES);
		fp4_read_bin(a[1][1], bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
		fp4_read_bin(a[2][0], bin + 8 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
		fp4_read_bin(a[2][1], bin + 12 * RLC_FP_BYTES, 4 * RLC_FP_BYTES);
		fp24_back_cyc(a, a);
	}
	if (len == 24 * RLC_FP_BYTES) {
		fp8_read_bin(a[0], bin, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[1], bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[2], bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
	}
}

void fp24_write_bin(uint8_t *bin, size_t len, const fp24_t a, int pack) {
	fp24_t t;

	fp24_null(t);

	RLC_TRY {
		fp24_new(t);

		if (pack) {
			if (len != 16 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp24_pck(t, a);
			fp4_write_bin(bin, 4 * RLC_FP_BYTES, a[1][0]);
			fp4_write_bin(bin + 4 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[1][1]);
			fp4_write_bin(bin + 8 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[2][0]);
			fp4_write_bin(bin + 12 * RLC_FP_BYTES, 4 * RLC_FP_BYTES, a[2][1]);
		} else {
			if (len != 24 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp8_write_bin(bin, 8 * RLC_FP_BYTES, a[0], 0);
			fp8_write_bin(bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[1], 0);
			fp8_write_bin(bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[2], 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp24_free(t);
	}
}

TMPL_FPX_UTIL(fp48, fp24, 2);

int fp48_size_bin(const fp48_t a, int pack) {
	if (pack) {
		if (fp48_test_cyc(a)) {
			return 32 * RLC_FP_BYTES;
		} else {
			return 48 * RLC_FP_BYTES;
		}
	} else {
		return 48 * RLC_FP_BYTES;
	}
}

void fp48_read_bin(fp48_t a, const uint8_t *bin, size_t len) {
	if (len != 32 * RLC_FP_BYTES && len != 48 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 32 * RLC_FP_BYTES) {
		fp8_zero(a[0][0]);
		fp8_read_bin(a[0][1], bin, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[0][2], bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp8_read_bin(a[1][0], bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp8_zero(a[1][1]);
		fp8_read_bin(a[1][2], bin + 24 * RLC_FP_BYTES, 8 * RLC_FP_BYTES);
		fp48_back_cyc(a, a);
	}
	if (len == 48 * RLC_FP_BYTES) {
		fp24_read_bin(a[0], bin, 24 * RLC_FP_BYTES);
		fp24_read_bin(a[1], bin + 24 * RLC_FP_BYTES, 24 * RLC_FP_BYTES);
	}
}

void fp48_write_bin(uint8_t *bin, size_t len, const fp48_t a, int pack) {
	fp48_t t;

	fp48_null(t);

	RLC_TRY {
		fp48_new(t);

		if (pack) {
			if (len != 32 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp48_pck(t, a);
			fp8_write_bin(bin, 8 * RLC_FP_BYTES, a[0][1], 0);
			fp8_write_bin(bin + 8 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[0][2], 0);
			fp8_write_bin(bin + 16 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[1][0], 0);
			fp8_write_bin(bin + 24 * RLC_FP_BYTES, 8 * RLC_FP_BYTES, a[1][2], 0);
		} else {
			if (len != 48 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp24_write_bin(bin, 24 * RLC_FP_BYTES, a[0], 0);
			fp24_write_bin(bin + 24 * RLC_FP_BYTES, 24 * RLC_FP_BYTES, a[1], 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp48_free(t);
	}
}

TMPL_FPX_UTIL(fp54, fp18, 3);

int fp54_size_bin(const fp54_t a, int pack) {
	if (pack) {
		if (fp54_test_cyc(a)) {
			return 36 * RLC_FP_BYTES;
		} else {
			return 54 * RLC_FP_BYTES;
		}
	} else {
		return 54 * RLC_FP_BYTES;
	}
}

void fp54_read_bin(fp54_t a, const uint8_t *bin, size_t len) {
	if (len != 36 * RLC_FP_BYTES && len != 54 * RLC_FP_BYTES) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}
	if (len == 36 * RLC_FP_BYTES) {
		fp9_zero(a[0][0]);
		fp9_zero(a[0][1]);
		fp9_read_bin(a[1][0], bin, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[1][1], bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[2][0], bin + 18 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
		fp9_read_bin(a[2][1], bin + 27 * RLC_FP_BYTES, 9 * RLC_FP_BYTES);
		fp54_back_cyc(a, a);
	}
	if (len == 54 * RLC_FP_BYTES) {
		fp18_read_bin(a[0], bin, 18 * RLC_FP_BYTES);
		fp18_read_bin(a[1], bin + 18 * RLC_FP_BYTES, 18 * RLC_FP_BYTES);
		fp18_read_bin(a[2], bin + 36 * RLC_FP_BYTES, 18 * RLC_FP_BYTES);
	}
}

void fp54_write_bin(uint8_t *bin, size_t len, const fp54_t a, int pack) {
	fp54_t t;

	fp54_null(t);

	RLC_TRY {
		fp54_new(t);

		if (pack) {
			if (len != 36 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp54_pck(t, a);
			fp9_write_bin(bin, 9 * RLC_FP_BYTES, a[1][0]);
			fp9_write_bin(bin + 9 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[1][1]);
			fp9_write_bin(bin + 18 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[2][0]);
			fp9_write_bin(bin + 27 * RLC_FP_BYTES, 9 * RLC_FP_BYTES, a[2][1]);
		} else {
			if (len != 54 * RLC_FP_BYTES) {
				RLC_THROW(ERR_NO_BUFFER);
			}
			fp18_write_bin(bin, 18 * RLC_FP_BYTES, a[0], 0);
			fp18_write_bin(bin + 18 * RLC_FP_BYTES, 18 * RLC_FP_BYTES, a[1], 0);
			fp18_write_bin(bin + 36 * RLC_FP_BYTES, 18 * RLC_FP_BYTES, a[2], 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp54_free(t);
	}
}

