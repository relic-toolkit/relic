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
 * Implementation of simultaneous point multiplication on binary elliptic
 * curves.
 *
 * @ingroup ed
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies and adds two prime elliptic Edwards curve points simultaneously
 * by interleaving their w-NAFs. The integers must be reduced modulo the order.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 */
static void ed_mul_sim_imp(ed_t r, const ed_t p, const bn_t k, const ed_t q,
		const bn_t m) {
	int i, n0, n1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;
	ed_t t0[1 << (RLC_WIDTH - 2)];
	ed_t t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
		ed_null(t0[i]);
		ed_null(t1[i]);
	}

	RLC_TRY {
		/* Compute the precomputation tables. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ed_new(t0[i]);
			ed_new(t1[i]);
		}
		ed_tab(t0, p, RLC_WIDTH);
		ed_tab(t1, q, RLC_WIDTH);

		/* Compute the w-NAF representations of k and m. */
		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, m, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		_k = naf0 + l - 1;
		_m = naf1 + l - 1;
		ed_set_infty(r);
		for (i = l - 1; i >= 0; i--, _k--, _m--) {
			ed_dbl(r, r);

			n0 = *_k;
			n1 = *_m;
			if (n0 > 0) {
				ed_add(r, r, t0[n0 / 2]);
			}
			if (n0 < 0) {
				ed_sub(r, r, t0[-n0 / 2]);
			}
			if (n1 > 0) {
				ed_add(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				ed_sub(r, r, t1[-n1 / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation tables. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ed_free(t0[i]);
			ed_free(t1[i]);
		}
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ed_mul_sim(ed_t r, const ed_t p, const bn_t k, const ed_t q,
		const bn_t m) {
	bn_t n, _k, _m;

	if (bn_is_zero(k) || ed_is_infty(p)) {
		ed_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ed_is_infty(q)) {
		ed_mul(r, p, k);
		return;
	}

	bn_null_all(n, _k, _m);

	RLC_TRY {
		bn_new_all(n, _k, _m);

		/* Reduce the scalars here to simplify the static function. */
		ed_curve_get_ord(n);
		bn_mod(_k, k, n);
		bn_mod(_m, m, n);

		ed_mul_sim_imp(r, p, _k, q, _m);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, _k, _m);
	}
}

void ed_mul_sim_gen(ed_t r, const bn_t k, const ed_t q, const bn_t m) {
	ed_t g;

	if (bn_is_zero(k)) {
		ed_mul(r, q, m);
		return;
	}
	if (bn_is_zero(m) || ed_is_infty(q)) {
		ed_mul_gen(r, k);
		return;
	}

	ed_null(g);

	RLC_TRY {
		ed_new(g);
		ed_curve_get_gen(g);
		ed_mul_sim(r, g, k, q, m);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ed_free(g);
	}
}

void ed_mul_sim_lot(ed_t r, const ed_t p[], const bn_t k[], int n) {
	int i, j;
	int8_t *naf = NULL;
	ed_t *_p;
	size_t l, *_l;

	if (n == 0) {
		ed_set_infty(r);
		return;
	}

	_p = RLC_ALLOCA(ed_t, n);
	_l = RLC_ALLOCA(size_t, n);

	RLC_TRY {
		l = 0;
		for (i = 0; i < n; i++) {
			l = RLC_MAX(l, bn_bits(k[i]) + 1);
		}
		naf = RLC_ALLOCA(int8_t, n * l);
		if (naf == NULL || _p == NULL || _l == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		for (i = 0; i < n; i++) {
			ed_null(_p[i]);
			ed_new(_p[i]);
		}

		for (i = 0; i < n; i++) {
			_l[i] = l;
			ed_norm(_p[i], p[i]);
			bn_rec_naf(&naf[i*l], &_l[i], k[i], 2);
			if (bn_sign(k[i]) == RLC_NEG) {
				ed_neg(_p[i], _p[i]);
			}
		}

		ed_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			ed_dbl(r, r);
			for (j = 0; j < n; j++) {
				if (naf[j*l + i] > 0) {
					ed_add(r, r, _p[j]);
				}
				if (naf[j*l + i] < 0) {
					ed_sub(r, r, _p[j]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (i = 0; i < n; i++) {
			ed_free(_p[i]);
		}
		RLC_FREE(_l);
		RLC_FREE(_p);
		RLC_FREE(naf);
	}
}
