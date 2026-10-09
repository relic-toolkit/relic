/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the prime elliptic curve utilities.
 *
 * @version $Id$
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_UTIL(ep, fp);

void ep_rhs(fp_t rhs, const fp_t x) {
	fp_t t0;

	fp_null(t0);

	RLC_TRY {
		fp_new(t0);

		/* t0 = x1^2. */
		fp_sqr(t0, x);

		/* t0 = x1^2 + a */
		switch (ep_curve_opt_a()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp_sub_dig(t0, t0, 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0, t0, 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0, t0, 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0, t0, ep_curve_get_a()[0]);
				break;
#endif
			default:
				fp_add(t0, t0, ep_curve_get_a());
				break;
		}

		/* t0 = x1^3 + a * x */
		fp_mul(t0, t0, x);

		/* t0 = x1^3 + a * x + b */
		switch (ep_curve_opt_b()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp_sub_dig(t0, t0, 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0, t0, 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0, t0, 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0, t0, ep_curve_get_b()[0]);
				break;
#endif
			default:
				fp_add(t0, t0, ep_curve_get_b());
				break;
		}

		fp_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(t0);
	}
}

size_t ep_size_bin(const ep_t a, int pack) {
	size_t size = 0;

	if (ep_is_infty(a)) {
		return 1;
	}

	size = 1 + RLC_FP_BYTES;
	if (!pack) {
		size += RLC_FP_BYTES;
	}

	return size;
}

void ep_read_bin(ep_t a, const uint8_t *bin, size_t len) {
	if (len == 1) {
		if (bin[0] == 0) {
			ep_set_infty(a);
			return;
		} else {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		}
	}

	if (len != (RLC_FP_BYTES + 1) && len != (2 * RLC_FP_BYTES + 1)) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	a->coord = BASIC;
	fp_set_dig(a->z, 1);
	fp_read_bin(a->x, bin + 1, RLC_FP_BYTES);
	if (len == RLC_FP_BYTES + 1) {
		switch(bin[0]) {
			case 2:
				fp_zero(a->y);
				break;
			case 3:
				fp_zero(a->y);
				fp_set_bit(a->y, 0, 1);
				break;
			default:
				RLC_THROW(ERR_NO_VALID);
				break;
		}
		ep_upk(a, a);
	}

	if (len == 2 * RLC_FP_BYTES + 1) {
		if (bin[0] == 4) {
			fp_read_bin(a->y, bin + RLC_FP_BYTES + 1, RLC_FP_BYTES);
		} else {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}

	if (!ep_on_curve(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
}

void ep_write_bin(uint8_t *bin, size_t len, const ep_t a, int pack) {
	ep_t t;

	ep_null(t);

	memset(bin, 0, len);

	if (ep_is_infty(a)) {
		if (len < 1) {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		} else {
			return;
		}
	}

	RLC_TRY {
		ep_new(t);

		ep_norm(t, a);

		if (pack) {
			if (len < RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
			} else {
				ep_pck(t, t);
				bin[0] = 2 | fp_get_bit(t->y, 0);
				fp_write_bin(bin + 1, RLC_FP_BYTES, t->x);
			}
		} else {
			if (len < 2 * RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
			} else {
				bin[0] = 4;
				fp_write_bin(bin + 1, RLC_FP_BYTES, t->x);
				fp_write_bin(bin + RLC_FP_BYTES + 1, RLC_FP_BYTES, t->y);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
	}
}
