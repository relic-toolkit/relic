/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Implementation of fixed point multiplication on prime elliptic Edwards curves.
 *
 * @ingroup ed
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ed_mul_pre_basic(ed_t *t, const ed_t p) {
	int i, j, l;
	bn_t n;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		ed_curve_get_ord(n);
		l = RLC_CEIL(bn_bits(n), RLC_DEPTH);

		ed_set_infty(t[0]);

		ed_copy(t[1], p);
		for (j = 1; j < RLC_DEPTH; j++) {
			ed_dbl(t[1 << j], t[1 << (j - 1)]);
			for (i = 1; i < l; i++) {
				ed_dbl(t[1 << j], t[1 << j]);
			}
			for (i = 1; i < (1 << j); i++) {
				ed_add(t[(1 << j) + i], t[i], t[1 << j]);
			}
		}

		ed_norm_sim(t + 2, (const ed_t *)t + 2, RLC_ED_TABLE_BASIC - 2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
	}
}

void ed_mul_fix_basic(ed_t r, const ed_t *t, const bn_t k) {
	int i, j, l, w, n0, p0, p1;
	bn_t n, _k;

	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

	bn_null_all(n, _k);

	RLC_TRY {
		bn_new_all(n, _k);

		ed_curve_get_ord(n);
		l = RLC_CEIL(bn_bits(n), RLC_DEPTH);

		/* Reduce the scalar so that it fits in the table. */
		bn_mod(_k, k, n);
		n0 = bn_bits(_k);

		p0 = (RLC_DEPTH) * l - 1;

		w = 0;
		p1 = p0--;
		for (j = RLC_DEPTH - 1; j >= 0; j--, p1 -= l) {
			w = w << 1;
			if (p1 < n0 && bn_get_bit(_k, p1)) {
				w = w | 1;
			}
		}
		ed_copy(r, t[w]);

		for (i = l - 2; i >= 0; i--) {
			ed_dbl(r, r);

			w = 0;
			p1 = p0--;
			for (j = RLC_DEPTH - 1; j >= 0; j--, p1 -= l) {
				w = w << 1;
				if (p1 < n0 && bn_get_bit(_k, p1)) {
					w = w | 1;
				}
			}
			if (w > 0) {
				ed_add(r, r, t[w]);
			}
		}
		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, _k);
	}
}

void ed_mul_pre_combd(ed_t *t, const ed_t p) {
	int i, j, d, e;
	bn_t n;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		ed_curve_get_ord(n);
		d = RLC_CEIL(bn_bits(n), RLC_DEPTH);
		e = RLC_CEIL(d, 2);

		ed_set_infty(t[0]);
		ed_copy(t[1], p);
		for (j = 1; j < RLC_DEPTH; j++) {
			ed_dbl(t[1 << j], t[1 << (j - 1)]);
			for (i = 1; i < d; i++) {
				ed_dbl(t[1 << j], t[1 << j]);
			}
			for (i = 1; i < (1 << j); i++) {
				ed_add(t[(1 << j) + i], t[i], t[1 << j]);
			}
		}
		ed_set_infty(t[1 << RLC_DEPTH]);
		for (j = 1; j < (1 << RLC_DEPTH); j++) {
			ed_dbl(t[(1 << RLC_DEPTH) + j], t[j]);
			for (i = 1; i < e; i++) {
				ed_dbl(t[(1 << RLC_DEPTH) + j], t[(1 << RLC_DEPTH) + j]);
			}
		}

		ed_norm_sim(t + 2, (const ed_t *)t + 2, (1 << RLC_DEPTH) - 2);
		ed_norm_sim(t + (1 << RLC_DEPTH) + 1,
				(const ed_t *)t + (1 << RLC_DEPTH) + 1, (1 << RLC_DEPTH) - 1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
	}
}

void ed_mul_fix_combd(ed_t r, const ed_t *t, const bn_t k) {
	int i, j, d, e, w0, w1, n0, p0, p1;
	bn_t n, _k;

	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

	bn_null_all(n, _k);

	RLC_TRY {
		bn_new_all(n, _k);

		ed_curve_get_ord(n);
		d = RLC_CEIL(bn_bits(n), RLC_DEPTH);
		e = RLC_CEIL(d, 2);

		/* Reduce the scalar so that it fits in the table. */
		bn_mod(_k, k, n);
		n0 = bn_bits(_k);

		ed_set_infty(r);
		p1 = (e - 1) + (RLC_DEPTH - 1) * d;
		for (i = e - 1; i >= 0; i--) {
			ed_dbl(r, r);

			w0 = 0;
			p0 = p1;
			for (j = RLC_DEPTH - 1; j >= 0; j--, p0 -= d) {
				w0 = w0 << 1;
				if (p0 < n0 && bn_get_bit(_k, p0)) {
					w0 = w0 | 1;
				}
			}

			w1 = 0;
			p0 = p1-- + e;
			for (j = RLC_DEPTH - 1; j >= 0; j--, p0 -= d) {
				w1 = w1 << 1;
				if (i + e < d && p0 < n0 && bn_get_bit(_k, p0)) {
					w1 = w1 | 1;
				}
			}

			ed_add(r, r, t[w0]);
			ed_add(r, r, t[(1 << RLC_DEPTH) + w1]);
		}
		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, _k);
	}
}
