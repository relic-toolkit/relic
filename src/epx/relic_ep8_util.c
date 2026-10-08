/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of comparison for points on prime elliptic curves over an
 * octic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_UTIL(ep8, fp8);

void ep8_rhs(fp8_t rhs, const fp8_t x) {
	fp8_t t0;

	fp8_null(t0);

	RLC_TRY {
		fp8_new(t0);

		fp8_sqr(t0, x);

		switch (ep8_curve_opt_a()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp_sub_dig(t0[0][0][0], t0[0][0][0], 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0[0][0][0], t0[0][0][0],
					ep8_curve_get_a()[0][0][0][0]);
				break;
#endif
			default:
				fp8_add(t0, t0, ep8_curve_get_a());
				break;
		}

		fp8_mul(t0, t0, x);

		switch (ep8_curve_opt_b()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp_sub_dig(t0[0][0][0], t0[0][0][0], 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0[0][0][0], t0[0][0][0],
					ep8_curve_get_b()[0][0][0][0]);
				break;
#endif
			default:
				fp8_add(t0, t0, ep8_curve_get_b());
				break;
		}

		fp8_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
	}
}

void ep8_tab(ep8_t *t, const ep8_t p, int w) {
	if (w > 2) {
		ep8_dbl(t[0], p);
#if defined(EP_MIXED)
		ep8_norm(t[0], t[0]);
#endif
		ep8_add(t[1], t[0], p);
		for (int i = 2; i < (1 << (w - 2)); i++) {
			ep8_add(t[i], t[i - 1], t[0]);
		}
#if defined(EP_MIXED)
		ep8_norm_sim(t + 1, t + 1, (1 << (w - 2)) - 1);
#endif
	}
#if defined(EP_MIXED)
	ep8_norm(t[0], p);
#else
	ep8_copy(t[0], p);
#endif
}

size_t ep8_size_bin(const ep8_t a, int pack) {
	ep8_t t;
	size_t size = 0;

	ep8_null(t);

	if (ep8_is_infty(a)) {
		return 1;
	}

	RLC_TRY {
		ep8_new(t);

		ep8_norm(t, a);

		size = 1 + 16 * RLC_FP_BYTES;
		//TODO: implement compression properly
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep8_free(t);
	}

	return size;
}

void ep8_read_bin(ep8_t a, const uint8_t *bin, size_t len) {
	if (len == 1) {
		if (bin[0] == 0) {
			ep8_set_infty(a);
			return;
		} else {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		}
	}

	if (len != (16 * RLC_FP_BYTES + 1)) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	a->coord = BASIC;
	fp8_set_dig(a->z, 1);
	fp8_read_bin(a->x, bin + 1, 8 * RLC_FP_BYTES);

	if (len == 16 * RLC_FP_BYTES + 1) {
		if (bin[0] == 4) {
			fp8_read_bin(a->y, bin + 8 * RLC_FP_BYTES + 1, 8 * RLC_FP_BYTES);
		} else {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}

	if (!ep8_on_curve(a)) {
		RLC_THROW(ERR_NO_VALID);
	}
}

void ep8_write_bin(uint8_t *bin, size_t len, const ep8_t a, int pack) {
	ep8_t t;

	ep8_null(t);

	memset(bin, 0, len);

	if (ep8_is_infty(a)) {
		if (len < 1) {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		} else {
			return;
		}
	}

	RLC_TRY {
		ep8_new(t);

		ep8_norm(t, a);

		if (len < 16 * RLC_FP_BYTES + 1) {
			RLC_THROW(ERR_NO_BUFFER);
		} else {
			bin[0] = 4;
			fp8_write_bin(bin + 1, 8 * RLC_FP_BYTES, t->x, 0);
			fp8_write_bin(bin + 8 * RLC_FP_BYTES + 1, 8 * RLC_FP_BYTES, t->y, 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep8_free(t);
	}
}
