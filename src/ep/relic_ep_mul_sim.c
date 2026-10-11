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
 * Implementation of simultaneous point multiplication on binary elliptic
 * curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies and adds two prime elliptic curve points simultaneously, using
 * the GLV endomorphism.
 *
 * @param[out] r 				- the result.
 * @param[in] p					- the first point to multiply.
 * @param[in] k					- the first integer.
 * @param[in] q					- the second point to multiply.
 * @param[in] m					- the second integer.
 */
static void ep_mul_sim_endom(ep_t r, const ep_t p, const bn_t k, const ep_t q,
		const bn_t m) {
	int i, sk0, sk1, sl0, sl1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *t0, *t1, u;
	int8_t naf2[RLC_FP_BITS + 1], naf3[RLC_FP_BITS + 1], *t2, *t3;
	bn_t n, k0, k1, m0, m1;
	ep_t v;
	ep_t tab0[1 << (RLC_WIDTH - 2)];
	ep_t tab1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1, l2, l3;

	bn_null(n);
	bn_null(k0);
	bn_null(k1);
	bn_null(m0);
	bn_null(m1);
	ep_null(v);

	for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
		ep_null(tab0[i]);
		ep_null(tab1[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(k0);
		bn_new(k1);
		bn_new(m0);
		bn_new(m1);
		ep_new(v);

		ep_curve_get_ord(n);
		bn_rec_glv(k0, k1, k, n, ep_curve_get_v1(), ep_curve_get_v2());
		sk0 = bn_sign(k0);
		sk1 = bn_sign(k1);
		bn_abs(k0, k0);
		bn_abs(k1, k1);

		bn_rec_glv(m0, m1, m, n, ep_curve_get_v1(), ep_curve_get_v2());
		sl0 = bn_sign(m0);
		sl1 = bn_sign(m1);
		bn_abs(m0, m0);
		bn_abs(m1, m1);

		/* Compute the precomputation tables. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_new(tab0[i]);
			ep_new(tab1[i]);
		}
		ep_tab(tab0, p, RLC_WIDTH);
		ep_tab(tab1, q, RLC_WIDTH);

		/* Compute the w-NAF representations of the subscalars. */
		l0 = l1 = l2 = l3 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k0, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, k1, RLC_WIDTH);
		bn_rec_naf(naf2, &l2, m0, RLC_WIDTH);
		bn_rec_naf(naf3, &l3, m1, RLC_WIDTH);

		l = RLC_MAX(RLC_MAX(l0, l1), RLC_MAX(l2, l3));
		t0 = naf0 + l - 1;
		t1 = naf1 + l - 1;
		t2 = naf2 + l - 1;
		t3 = naf3 + l - 1;

		if (bn_sign(k) == RLC_NEG) {
			for (size_t j = 0; j < l0; j++) {
				naf0[j] = -naf0[j];
			}
			for (size_t j = 0; j < l1; j++) {
				naf1[j] = -naf1[j];
			}
		}
		if (bn_sign(m) == RLC_NEG) {
			for (size_t j = 0; j < l2; j++) {
				naf2[j] = -naf2[j];
			}
			for (size_t j = 0; j < l3; j++) {
				naf3[j] = -naf3[j];
			}
		}

		ep_set_infty(r);
		for (i = l - 1; i >= 0; i--, t0--, t1--, t2--, t3--) {
			ep_dbl(r, r);

			u = *t0;
			if (u > 0) {
				if (sk0 == RLC_POS) {
					ep_add(r, r, tab0[u / 2]);
				} else {
					ep_sub(r, r, tab0[u / 2]);
				}
			}
			if (u < 0) {
				if (sk0 == RLC_POS) {
					ep_sub(r, r, tab0[-u / 2]);
				} else {
					ep_add(r, r, tab0[-u / 2]);
				}
			}
			u = *t1;
			if (u > 0) {
				ep_psi(v, tab0[u / 2]);
				if (sk1 == RLC_NEG) {
					ep_neg(v, v);
				}
				ep_add(r, r, v);
			}
			if (u < 0) {
				ep_psi(v, tab0[-u / 2]);
				if (sk1 == RLC_NEG) {
					ep_neg(v, v);
				}
				ep_sub(r, r, v);
			}

			u = *t2;
			if (u > 0) {
				if (sl0 == RLC_POS) {
					ep_add(r, r, tab1[u / 2]);
				} else {
					ep_sub(r, r, tab1[u / 2]);
				}
			}
			if (u < 0) {
				if (sl0 == RLC_POS) {
					ep_sub(r, r, tab1[-u / 2]);
				} else {
					ep_add(r, r, tab1[-u / 2]);
				}
			}
			u = *t3;
			if (u > 0) {
				ep_psi(v, tab1[u / 2]);
				if (sl1 == RLC_NEG) {
					ep_neg(v, v);
				}
				ep_add(r, r, v);
			}
			if (u < 0) {
				ep_psi(v, tab1[-u / 2]);
				if (sl1 == RLC_NEG) {
					ep_neg(v, v);
				}
				ep_sub(r, r, v);
			}
		}
		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(k0);
		bn_free(k1);
		bn_free(m0);
		bn_free(m1);
		ep_free(v);

		/* Free the precomputation tables. */
		for (i = 0; i < 1 << (RLC_WIDTH - 2); i++) {
			ep_free(tab0[i]);
			ep_free(tab1[i]);
		}
	}
}

/**
 * Multiplies and adds multiple elliptic curve points simultaneously.
 * Computes R = \Sum_i=0..n [k_i]P_i.
 *
 * @param[out] r			- the result.
 * @param[out] p			- the elements to multiply.
 * @param[out] k			- the integer scalars.
 * @param[out] n			- the number of elements to multiply.
 */
static void ep_mul_sim_lot_endom(ep_t r, const ep_t p[], const bn_t k[],
		int n) {
	const int len = RLC_FP_BITS + 1;
	int i, j, m, sk;
	bn_t _k[2], q;
	int8_t ptr, *naf = RLC_ALLOCA(int8_t, 2 * n * len);
	size_t l, _l[2];

	bn_null(q);

	if (n <= 10) {
		ep_t *_p = RLC_ALLOCA(ep_t, 2 * n);

		RLC_TRY {
			if (naf == NULL || _p == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			bn_new(q);
			for (j = 0; j < 2; j++) {
				bn_null(_k[j]);
				bn_new(_k[j]);
			}
			for (i = 0; i < 2 * n; i++) {
				ep_null(_p[i]);
				ep_new(_p[i]);
			}

			l = 0;
			ep_curve_get_ord(q);
			for (i = 0; i < n; i++) {
				ep_norm(_p[2*i], p[i]);
				ep_psi(_p[2*i + 1], _p[2*i]);
				bn_mod(_k[0], k[i], q);
				sk = bn_sign(_k[0]);
				bn_rec_glv(_k[0], _k[1], _k[0], q,
						ep_curve_get_v1(), ep_curve_get_v2());
				if (sk == RLC_NEG) {
					bn_neg(_k[0], _k[0]);
					bn_neg(_k[1], _k[1]);
				}
				for (j = 0; j < 2; j++) {
					_l[j] = len;
					bn_rec_naf(&naf[(2*i + j)*len], &_l[j], _k[j], 2);
					if (bn_sign(_k[j]) == RLC_NEG) {
						ep_neg(_p[2*i + j], _p[2*i + j]);
					}
					l = RLC_MAX(l, _l[j]);
				}
			}

			ep_set_infty(r);
			for (i = l - 1; i >= 0; i--) {
				ep_dbl(r, r);
				for (j = 0; j < n; j++) {
					for (m = 0; m < 2; m++) {
						if (naf[(2*j + m)*len + i] > 0) {
							ep_add(r, r, _p[2*j + m]);
						}
						if (naf[(2*j + m)*len + i] < 0) {
							ep_sub(r, r, _p[2*j + m]);
						}
					}
				}
			}
			ep_norm(r, r);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			bn_free(q);
			bn_free(_k[0]);
			bn_free(_k[1]);
			for (i = 0; i < 2 * n; i++) {
				ep_free(_p[i]);
			}
			RLC_FREE(_p);
			RLC_FREE(naf);
		}
	} else {
		const int w = RLC_MAX(2, util_bits_dig(n) - 2), c = (1 << (w - 2));
		ep_t s, t, u, v, *_p = RLC_ALLOCA(ep_t, c);
		ep_t *_q = RLC_ALLOCA(ep_t, 2 * n);

		ep_null(s);
		ep_null(t);
		ep_null(u);
		ep_null(v);

		RLC_TRY {
			if (naf == NULL || _p == NULL || _q == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			bn_new(q);
			ep_new(s);
			ep_new(t);
			ep_new(u);
			ep_new(v);
			for (i = 0; i < 2; i++) {
				bn_null(_k[i]);
				bn_new(_k[i]);
			}
			for (j = 0; j < c; j++) {
				ep_null(_p[j]);
				ep_new(_p[j]);
				ep_set_infty(_p[j]);
			}
			for (i = 0; i < 2 * n; i++) {
				ep_null(_q[i]);
				ep_new(_q[i]);
			}

			l = 0;
			ep_curve_get_ord(q);
			for (i = 0; i < n; i++) {
				ep_norm(_q[2*i], p[i]);
				ep_psi(_q[2*i + 1], _q[2*i]);
				bn_mod(_k[0], k[i], q);
				sk = bn_sign(_k[0]);
				bn_rec_glv(_k[0], _k[1], _k[0], q,
						ep_curve_get_v1(), ep_curve_get_v2());
				if (sk == RLC_NEG) {
					bn_neg(_k[0], _k[0]);
					bn_neg(_k[1], _k[1]);
				}
				for (j = 0; j < 2; j++) {
					_l[j] = len;
					bn_rec_naf(&naf[(2*i + j)*len], &_l[j], _k[j], w);
					if (bn_sign(_k[j]) == RLC_NEG) {
						for (size_t s = 0; s < _l[j]; s++) {
							naf[(2*i + j)*len + s] = -naf[(2*i + j)*len + s];
						}
					}
					l = RLC_MAX(l, _l[j]);
				}
			}

			ep_set_infty(s);
			for (i = l - 1; i >= 0; i--) {
				for (j = 0; j < n; j++) {
					for (m = 0; m < 2; m++) {
						ptr = naf[(2*j + m)*len + i];
						if (ptr != 0) {
							ep_copy(t, _q[2*j + m]);
							if (ptr < 0) {
								ptr = -ptr;
								ep_neg(t, t);
							}
							ptr >>= 1;
							ep_add(_p[ptr], _p[ptr], t);
						}
					}
				}

				ep_set_infty(u);
				ep_set_infty(v);
				for (j = c - 1; j >= 0; j--) {
					ep_add(u, u, _p[j]);
					if (j == 0) {
						ep_dbl(v, v);
					}
					ep_add(v, v, u);
					ep_set_infty(_p[j]);
				}
				ep_dbl(s, s);
				ep_add(s, s, v);
			}

			/* Convert r to affine coordinates. */
			ep_norm(r, s);
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		} RLC_FINALLY {
			bn_free(q);
			ep_free(s);
			ep_free(t);
			ep_free(u);
			ep_free(v);
			for (i = 0; i < 2; i++) {
				bn_free(_k[i]);
			}
			for (j = 0; j < c; j++) {
				ep_free(_p[j]);
			}
			for (i = 0; i < 2 * n; i++) {
				ep_free(_q[i]);
			}
			RLC_FREE(_p);
			RLC_FREE(_q);
			RLC_FREE(naf);
		}
	}
}

TMPL_EP_MUL_SIM_PLAIN(ep);

/**
 * Multiplies and adds multiple elliptic curve points simultaneously.
 * Computes R = \Sum_i=0..n [k_i]P_i.
 *
 * @param[out] r			- the result.
 * @param[out] p			- the elements to multiply.
 * @param[out] k			- the integer scalars.
 * @param[out] n			- the number of elements to multiply.
 */
static void ep_mul_sim_lot_plain(ep_t r, const ep_t p[], const bn_t k[],
		int n) {
	int i, j;
	int8_t *naf = NULL;
	ep_t *_p = RLC_ALLOCA(ep_t, n);
	size_t l, *_l = RLC_ALLOCA(size_t, n);

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
			ep_null(_p[i]);
			ep_new(_p[i]);
		}

		for (i = 0; i < n; i++) {
			_l[i] = l;
			ep_norm(_p[i], p[i]);
			bn_rec_naf(&naf[i*l], &_l[i], k[i], 2);
			if (bn_sign(k[i]) == RLC_NEG) {
				ep_neg(_p[i], _p[i]);
			}
		}

		ep_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			ep_dbl(r, r);
			for (j = 0; j < n; j++) {
				if (naf[j*l + i] > 0) {
					ep_add(r, r, _p[j]);
				}
				if (naf[j*l + i] < 0) {
					ep_sub(r, r, _p[j]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (i = 0; i < n; i++) {
			ep_free(_p[i]);
		}
		RLC_FREE(_l);
		RLC_FREE(_p);
		RLC_FREE(naf);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_SIM(ep);

TMPL_EP_MUL_SIM_GEN(ep);

void ep_mul_sim_dig(ep_t r, const ep_t p[], const dig_t k[], int n) {
	ep_t t;
	int max;

	ep_null(t);

	max = util_bits_dig(k[0]);
	for (int i = 1; i < n; i++) {
		max = RLC_MAX(max, util_bits_dig(k[i]));
	}

	RLC_TRY {
		ep_new(t);

		ep_set_infty(t);
		for (int i = max - 1; i >= 0; i--) {
			ep_dbl(t, t);
			for (int j = 0; j < n; j++) {
				if (k[j] & ((dig_t)1 << i)) {
					ep_add(t, t, p[j]);
				}
			}
		}

		ep_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
	}
}

void ep_mul_sim_lot(ep_t r, const ep_t p[], const bn_t k[], int n) {
	int flag = 0;

	if (n == 0) {
		ep_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep_mul_sim_lot_endom(r, p, k, n);
		flag = 1;
	}

	if (!flag) {
		ep_mul_sim_lot_plain(r, p, k, n);
	}
	(void)flag;
}
