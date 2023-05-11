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
 * Implementation of pairing computation for curves with embedding degree 1.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Compute the Miller loop for pairings of type G_2 x G_1 over the bits of a
 * given parameter.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] p				- the first pairing argument in affine coordinates.
 * @param[in] q				- the second pairing argument in affine coordinates.
 * @param[in] n 			- the number of pairings to evaluate.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k1(fp_t r, ep_t *t, ep_t *p, ep_t *q, int n, bn_t a) {
	fp_t l, m, s;
	int i, j;

	fp_null(l);
	fp_null(m);
	fp_null(s);

	RLC_TRY {
		fp_new(l);
		fp_new(m);
		fp_new(s);
		for (j = 0; j < n; j++) {
			ep_copy(t[j], p[j]);
		}

		fp_set_dig(s, 1);
		for (i = bn_bits(a) - 2; i >= 0; i--) {
			fp_sqr(r, r);
			fp_sqr(s, s);
			for (j = 0; j < n; j++) {
				pp_dbl_k1(l, m, t[j], t[j], q[j]);
				fp_mul(r, r, l);
				fp_mul(s, s, m);
				if (bn_get_bit(a, i)) {
					pp_add_k1(l, m, t[j], p[j], q[j]);
					fp_mul(r, r, l);
					fp_mul(s, s, m);
				}
			}
		}

		if (!fp_is_zero(s)) {
			fp_inv(s, s);
			fp_mul(r, r, s);
		} else {
			fp_set_dig(r, 1);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(l);
		fp_free(m);
		fp_free(s);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if PP_MAP == TATEP || PP_MAP == OATEP || !defined(STRIP)

void pp_map_tatep_k1(fp_t r, const ep_t p, const ep_t q) {
	ep_t _p[1], _q[1], t[1];
	bn_t n;

	ep_null(_p[0]);
	ep_null(_q[0]);
	ep_null(t[0]);
	bn_null(n);

	RLC_TRY {
		ep_new(t[0]);
		bn_new(n);

		ep_norm(_p[0], p);
		ep_norm(_q[0], q);
		ep_curve_get_ord(n);
		fp_set_dig(r, 1);

		if (!ep_is_infty(p) && !ep_is_infty(q)) {
			pp_mil_k1(r, t, _p, _q, 1, n);
			pp_exp_k1(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(_q[0]);
		ep_free(t[0]);
		bn_free(n);
	}
}

void pp_map_sim_tatep_k1(fp_t r, const ep_t *p, const ep_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m),
			*_q = RLC_ALLOCA(ep_t, m), *t = RLC_ALLOCA(ep_t, m);
	bn_t n;
	int i, j;

	bn_null(n);

	RLC_TRY {
		bn_new(n);
		if (_p == NULL || _q == NULL || t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < m; i++) {
			ep_null(_p[i]);
			ep_null(_q[i]);
			ep_null(t[i]);
			ep_new(_p[i]);
			ep_new(_q[i]);
			ep_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep_norm(_q[j++], q[i]);
			}
		}

		ep_curve_get_ord(n);
		fp_set_dig(r, 1);
		if (j > 0) {
			pp_mil_k1(r, t, _p, _q, j, n);
			pp_exp_k1(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep_free(_q[i]);
			ep_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}

#endif

#if PP_MAP == WEILP || !defined(STRIP)

void pp_map_weilp_k1(fp_t r, const ep_t p, const ep_t q) {
	ep_t _p[1], _q[1], t0[1], t1[1];
	fp_t r0, r1;
	bn_t n;

	ep_null(_p[0]);
	ep_null(_q[0]);
	ep_null(t0[0]);
	ep_null(t1[0]);
	fp_null(r0);
	fp_null(r1);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(_q[0]);
		ep_new(t0[0]);
		ep_new(t1[0]);
		fp_new(r0);
		fp_new(r1);
		bn_new(n);

		ep_norm(_p[0], p);
		ep_norm(_q[0], q);
		ep_curve_get_ord(n);
		fp_set_dig(r0, 1);
		fp_set_dig(r1, 1);

		if (!ep_is_infty(_p[0]) && !ep_is_infty(_q[0])) {
			pp_mil_k1(r0, t0, _p, _q, 1, n);
			pp_mil_k1(r1, t1, _q, _p, 1, n);
			if (fp_cmp(r0, r1) != RLC_EQ) {
				fp_neg(r0, r0);
			}
			fp_inv(r1, r1);
		}
		/* Compute r = (-1)^n * r0/r1. */
		fp_mul(r, r0, r1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(_q[0]);
		ep_free(t0[0]);
		ep_free(t1[0]);
		fp_free(r0);
		fp_free(r1);
		bn_free(n);
	}
}

void pp_map_sim_weilp_k1(fp_t r, const ep_t *p, const ep_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m),
			*_q = RLC_ALLOCA(ep_t, m),
			*t0 = RLC_ALLOCA(ep_t, m), *t1 = RLC_ALLOCA(ep_t, m);
	fp_t r0, r1;
	bn_t n;
	int i, j;

	fp_null(r0);
	fp_null(r1);
	bn_null(r);

	RLC_TRY {
		fp_new(r0);
		fp_new(r1);
		bn_new(n);
		if (_p == NULL || _q == NULL || t0 == NULL || t1 == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < m; i++) {
			ep_null(_p[i]);
			ep_null(_q[i]);
			ep_null(t0[i]);
			ep_null(t1[i]);
			ep_new(_p[i]);
			ep_new(_q[i]);
			ep_new(t0[i]);
			ep_new(t1[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep_norm(_q[j++], q[i]);
			}
		}

		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp_set_dig(r0, 1);
		fp_set_dig(r1, 1);

		if (j > 0) {
			pp_mil_k1(r0, t0, _p, _q, j, n);
			pp_mil_k1(r1, t1, _q, _p, j, n);
			fp_inv(r1, r1);
		}
		fp_mul(r, r0, r1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(r0);
		fp_free(r1);
		bn_free(n);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep_free(_q[i]);
			ep_free(t0[i]);
			ep_free(t1[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t0);
		RLC_FREE(t1);
	}
}

#endif
