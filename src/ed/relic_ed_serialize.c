/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2015 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of serialization of twisted Edwards curve points.
 *
 * @version $Id$
 * @ingroup ed
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
int ed_size_bin(const ed_t a, int pack) {
	int size = 0;

	if (ed_is_infty(a)) {
		return 1;
	}

	size = 1 + FP_BYTES;
	if (!pack) {
		size += FP_BYTES;
	}
	
	return size;
}

/*
* Compress twisted Edwards curve point by compressing the x-coordinate to its sign.
*/
void ed_pck(ed_t r, const ed_t p) {
	fp_copy(r->y, p->y);
	int b = fp_get_bit(p->x, 0);
	fp_zero(r->x);
	fp_set_bit(r->x, 0, b);
	fp_set_dig(r->z, 1);
	r->norm = 1;
}

/*
* Uncompress twisted Edwards curve point.
*/
int ed_upk(ed_t r, const ed_t p) {
	int result = 1;
	fp_t t;

	TRY {
		fp_new(t);

		fp_copy(r->y, p->y);
		ed_recover_x(t, p->y, core_get()->ed_d, core_get()->ed_a);

		if (fp_get_bit(t, 0) != fp_get_bit(p->x, 0)) {
			fp_neg(t, t);
		}
		fp_copy(r->x, t);

#if ED_ADD == EXTND
		fp_mul(r->t, r->x, r->y);
#endif

		fp_set_dig(r->z, 1);
		r->norm = 1;
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp_free(t);
	}
	return result;
}

void ed_write_bin(uint8_t *bin, int len, const ed_t a, int pack) {
	ed_t t;

	ed_null(t);

	if (ed_is_infty(a)) {
		if (len != 1) {
			THROW(ERR_NO_BUFFER);
		} else {
			bin[0] = 0;
			return;
		}
	}

	TRY {
		ed_new(t);

		ed_norm(t, a);

		if (pack) {
			if (len != FP_BYTES + 1) {
				THROW(ERR_NO_BUFFER);
			} else {
				ed_pck(t, t);
				bin[0] = 2 | fp_get_bit(t->x, 0);
				fp_write_bin(bin + 1, FP_BYTES, t->y);
			}
		} else {
			if (len != 2 * FP_BYTES + 1) {
				THROW(ERR_NO_BUFFER);
			} else {
				bin[0] = 4;
				fp_write_bin(bin + 1, FP_BYTES, t->y);
				fp_write_bin(bin + FP_BYTES + 1, FP_BYTES, t->x);
			}
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(t);
	}
}

void ed_read_bin(ed_t a, const uint8_t *bin, int len) {
	if (len == 1) {
		if (bin[0] == 0) {
			ed_set_infty(a);
			return;
		} else {
			THROW(ERR_NO_BUFFER);
			return;
		}
	}

	if (len != (FP_BYTES + 1) && len != (2 * FP_BYTES + 1)) {
		THROW(ERR_NO_BUFFER);
		return;
	}

	a->norm = 1;
	fp_set_dig(a->z, 1);
	fp_read_bin(a->y, bin + 1, FP_BYTES);
	if (len == FP_BYTES + 1) {
		switch(bin[0]) {
			case 2:
				fp_zero(a->x);
				break;
			case 3:
				fp_zero(a->x);
				fp_set_bit(a->x, 0, 1);
				break;
			default:
				THROW(ERR_NO_VALID);
				break;
		}
		ed_upk(a, a);
	}

	if (len == 2 * FP_BYTES + 1) {
		if (bin[0] == 4) {
			fp_read_bin(a->x, bin + FP_BYTES + 1, FP_BYTES);
		} else {
			THROW(ERR_NO_VALID);
		}
	}

#if ED_ADD == EXTND
	ed_projc_to_extnd(a, a->x, a->y, a->z);
#endif
}
