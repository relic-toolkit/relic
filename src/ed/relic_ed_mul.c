/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2014 RELIC Authors
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
 * Implementation of the point multiplication on prime elliptic Edwards curves.
 *
 * @version $Id$
 * @ingroup ed
 */

#include <assert.h>

#include "relic_core.h"

void ed_mul(ed_t r, const ed_t p, const bn_t k) {
	ed_t t[2];

	ed_null(t[0]);
	ed_null(t[1]);

	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

	TRY {
		ed_new(t[0]);
		ed_new(t[1]);

		ed_set_infty(t[0]);
		ed_copy(t[1], p);

		for (int i = bn_bits(k) - 1; i >= 0; i--) {
			int j = bn_get_bit(k, i);
			dv_swap_cond(t[0]->x, t[1]->x, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y, t[1]->y, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z, t[1]->z, FP_DIGS, j ^ 1);
			ed_add(t[0], t[0], t[1]);
			ed_dbl(t[1], t[1]);
			dv_swap_cond(t[0]->x, t[1]->x, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y, t[1]->y, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z, t[1]->z, FP_DIGS, j ^ 1);
		}
		ed_norm(r, t[0]);

	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(t[1]);
		ed_free(t[0]);
	}
}

void ed_mul_gen(ed_t r, const bn_t k) {		
	ed_t g;

	ed_null(g);

	TRY {
		ed_new(g);
		ed_curve_get_gen(g);
		ed_mul(r, g, k);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(g);
	}
}

void ed_mul_dig(ed_t r, const ed_t p, dig_t k) {
	int i, l;
	ed_t t;

	ed_null(t);

	if (k == 0) {
		ed_set_infty(r);
		return;
	}

	TRY {
		ed_new(t);

		l = util_bits_dig(k);

		ed_copy(t, p);

		for (i = l - 2; i >= 0; i--) {
			ed_dbl(t, t);
			if (k & ((dig_t)1 << i)) {
				ed_add(t, t, p);
			}
		}

		ed_norm(r, t);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(t);
	}
}