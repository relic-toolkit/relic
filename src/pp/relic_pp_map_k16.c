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
 * Implementation of pairing computation for curves with embedding degree 16.
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
 * given parameter represented in sparse form.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the vector of first arguments in affine coordinates.
 * @param[in] p				- the vector of second arguments in affine coordinates.
 * @param[in] n 			- the number of pairings to evaluate.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k16(fp16_t r, ep4_t *t, ep4_t *q, ep_t *p, int m, bn_t a) {
	fp16_t l;
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep4_t *_q = RLC_ALLOCA(ep4_t, m);
	int i, j;
	size_t len = bn_bits(a) + 1;
	int8_t s[RLC_FP_BITS + 1];

	if (m == 0) {
		return;
	}

	fp16_null(l);

	RLC_TRY {
		fp16_new(l);
		if (_p == NULL || _q == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		
		for (j = 0; j < m; j++) {
			ep_null(_p[j]);
			ep4_null(_q[j]);
			ep_new(_p[j]);
			ep4_new(_q[j]);
			ep4_copy(t[j], q[j]);
			ep4_neg(_q[j], q[j]);
#if EP_ADD == BASIC
			ep_neg(_p[j], p[j]);
#else
			fp_neg(_p[j]->x, p[j]->x);
			fp_copy(_p[j]->y, p[j]->y);
#endif
		}

		fp16_zero(l);
		bn_rec_naf(s, &len, a, 2);
		pp_dbl_k16(r, t[0], t[0], _p[0]);
		for (j = 1; j < m; j++) {
			pp_dbl_k16(l, t[j], t[j], _p[j]);
			fp16_mul_dxs(r, r, l);
		}
		if (s[len - 2] > 0) {
			for (j = 0; j < m; j++) {
				pp_add_k16(l, t[j], q[j], _p[j]);
				fp16_mul_dxs(r, r, l);
			}
		}
		if (s[len - 2] < 0) {
			for (j = 0; j < m; j++) {
				pp_add_k16(l, t[j], _q[j], _p[j]);
				fp16_mul_dxs(r, r, l);
			}
		}

		for (i = len - 3; i >= 0; i--) {
			fp16_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_k16(l, t[j], t[j], _p[j]);
				fp16_mul_dxs(r, r, l);
				if (s[i] > 0) {
					pp_add_k16(l, t[j], q[j], _p[j]);
					fp16_mul_dxs(r, r, l);
				}
				if (s[i] < 0) {
					pp_add_k16(l, t[j], _q[j], _p[j]);
					fp16_mul_dxs(r, r, l);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(l);
		for (j = 0; j < m; j++) {
			ep_free(_p[j]);
			ep4_free(_q[j]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
	}
}

/**
 * Compute the Miller loop for pairings of type G_1 x G_2 over the bits of a
 * given parameter.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] p				- the first pairing argument in affine coordinates.
 * @param[in] q				- the second pairing argument in affine coordinates.
 * @param[in] n 			- the number of pairings to evaluate.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_lit_k16(fp16_t r, ep_t *t, ep_t *p, ep4_t *q, int m, bn_t a) {
	fp16_t l;
	ep4_t *_q = RLC_ALLOCA(ep4_t, m);
	int j;

	fp16_null(l);

	RLC_TRY {
		if (_q == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		fp16_new(l);

		for (j = 0; j < m; j++) {
			ep4_null(_q[j]);
			ep4_new(_q[j]);
			ep_copy(t[j], p[j]);
			ep4_neg(_q[j], q[j]);
		}

		fp16_zero(l);
		for (int i = bn_bits(a) - 2; i >= 0; i--) {
			fp16_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_lit_k16(l, t[j], t[j], _q[j]);
				fp16_mul(r, r, l);
				if (bn_get_bit(a, i)) {
					pp_add_lit_k16(l, t[j], p[j], q[j]);
					fp16_mul(r, r, l);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(l);
		for (j = 0; j < m; j++) {
			ep4_free(_q[j]);
		}
		RLC_FREE(_q);
	}
}

/**
 * Compute the final lines for optimal ate pairings.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the first point of the pairing, in G_2.
 * @param[in] p				- the second point of the pairing, in G_1.
 * @param[in] a				- the loop parameter.
 */
static void pp_fin_k16_oatep(fp16_t r, ep4_t t, ep4_t q, ep_t p) {
	ep4_t q1, q2;
	fp16_t tmp;

	fp16_null(tmp);
	ep4_null(q1);
	ep4_null(q2);

	RLC_TRY {
		ep4_new(q1);
		ep4_new(q2);
		fp16_new(tmp);
		fp16_zero(tmp);

#if EP_ADD == PROJC || EP_ADD == JACOB
		fp_neg(p->x, p->x);
#endif
		ep4_frb(q1, q, 1);
		pp_add_k16(tmp, t, q1, p);
		fp16_frb(tmp, tmp, 3);
		fp16_mul_dxs(r, r, tmp);

		pp_dbl_k16(tmp, q2, q, p);
		fp16_mul_dxs(r, r, tmp);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp16_free(tmp);
		ep4_free(q1);
		ep4_free(q2);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if PP_MAP == TATEP || !defined(STRIP)

void pp_map_tatep_k16(fp16_t r, const ep_t p, const ep4_t q) {
	ep_t _p[1], t[1];
	ep4_t _q[1];
	bn_t n;

	ep_null(_p[0]);
	ep_null(t[0]);
	ep4_null(_q[0]);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(t[0]);
		ep4_new(_q[0]);
		bn_new(n);

		ep_norm(_p[0], p);
		ep4_norm(_q[0], q);
		ep_curve_get_ord(n);
		fp16_set_dig(r, 1);

		if (!ep_is_infty(p) && !ep4_is_infty(q)) {
			pp_mil_lit_k16(r, t, _p, _q, 1, n);
			pp_exp_k16(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(t[0]);
		ep4_free(_q[0]);
		bn_free(n);
	}
}

void pp_map_sim_tatep_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m), *t = RLC_ALLOCA(ep_t, m);
	ep4_t *_q = RLC_ALLOCA(ep4_t, m);
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
			ep_null(t[i]);
			ep4_null(_q[i]);
			ep_new(_p[i]);
			ep_new(t[i]);
			ep4_new(_q[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep4_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep4_norm(_q[j], q[i]);
				j++;
			}
		}

		ep_curve_get_ord(n);
		fp16_set_dig(r, 1);
		if (j > 0) {
			pp_mil_lit_k16(r, t, _p, _q, j, n);
			pp_exp_k16(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep_free(t[i]);
			ep4_free(_q[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(t);
		RLC_FREE(_q);
	}
}

#endif

#if PP_MAP == WEILP || !defined(STRIP)

void pp_map_weilp_k16(fp16_t r, const ep_t p, const ep4_t q) {
	ep_t _p[1], t0[1];
	ep4_t _q[1], t1[1];
	fp16_t r0, r1;
	bn_t n;

	ep_null(_p[0]);
	ep_null(t0[0]);
	ep4_null(_q[0]);
	ep4_null(t1[0]);
	fp16_null(r0);
	fp16_null(r1);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(t0[0]);
		ep4_new(_q[0]);
		ep4_new(t1[0]);
		fp16_new(r0);
		fp16_new(r1);
		bn_new(n);

		ep_norm(_p[0], p);
		ep4_norm(_q[0], q);

		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp16_set_dig(r0, 1);
		fp16_set_dig(r1, 1);

		if (!ep_is_infty(_p[0]) && !ep4_is_infty(_q[0])) {
			pp_mil_k16(r1, t1, _q, _p, 1, n);
			pp_mil_lit_k16(r0, t0, _p, _q, 1, n);
			fp16_inv(r1, r1);
			fp16_mul(r0, r0, r1);
			fp16_inv(r1, r0);
			fp16_inv_cyc(r0, r0);
		}
		fp16_mul(r, r0, r1);
		fp16_sqr(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(t0[0]);
		ep4_free(_q[0]);
		ep4_free(t1[0]);
		fp16_free(r0);
		fp16_free(r1);
		bn_free(n);
	}
}

void pp_map_sim_weilp_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m), *t0 = RLC_ALLOCA(ep_t, m);
	ep4_t *_q = RLC_ALLOCA(ep4_t, m), *t1 = RLC_ALLOCA(ep4_t, m);
	fp16_t r0, r1;
	bn_t n;
	int i, j;

	fp16_null(r0);
	fp16_null(r1);
	bn_null(n);

	RLC_TRY {
		fp16_new(r0);
		fp16_new(r1);
		bn_new(n);
		if (_p == NULL || _q == NULL || t0 == NULL || t1 == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < m; i++) {
			ep_null(_p[i]);
			ep_null(t0[i]);
			ep4_null(_q[i]);
			ep4_null(t1[i]);
			ep_new(_p[i]);
			ep_new(t0[i]);
			ep4_new(_q[i]);
			ep4_new(t1[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep4_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep4_norm(_q[j++], q[i]);
			}
		}

		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp16_set_dig(r0, 1);
		fp16_set_dig(r1, 1);

		if (j > 0) {
			pp_mil_k16(r1, t1, _q, _p, j, n);
			pp_mil_lit_k16(r0, t0, _p, _q, j, n);
			fp16_inv(r1, r1);
			fp16_mul(r0, r0, r1);
			fp16_inv(r1, r0);
			fp16_inv_cyc(r0, r0);
		}
		fp16_mul(r, r0, r1);
		fp16_sqr(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(r0);
		fp16_free(r1);
		bn_free(n);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep_free(t0[i]);
			ep4_free(_q[i]);
			ep4_free(t1[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t0);
		RLC_FREE(t1);
	}
}

#endif

#if PP_MAP == OATEP || !defined(STRIP)

void pp_map_oatep_k16(fp16_t r, const ep_t p, const ep4_t q) {
	ep_t _p[1];
	ep4_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep4_null(_q[0]);
	ep4_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep4_new(_q[0]);
		ep4_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp16_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep4_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep4_is_infty(_q[0])) {
			switch (ep_curve_is_pairf()) {
				case EP_FM16:
				case EP_N16:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k16(r, t, _q, _p, 1, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp16_inv_cyc(r, r);
						ep4_neg(t[0], t[0]);
					}
					pp_exp_k16(r, r);
					break;
				case EP_K16:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k16(r, t, _q, _p, 1, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp16_inv_cyc(r, r);
						ep4_neg(t[0], t[0]);
					}
					fp16_frb(r, r, 3);
					pp_fin_k16_oatep(r, t[0], _q[0], _p[0]);
					pp_exp_k16(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep4_free(_q[0]);
		ep4_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_oatep_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep4_t *t = RLC_ALLOCA(ep4_t, m), *_q = RLC_ALLOCA(ep4_t, m);
	bn_t a;
	int i, j;

	RLC_TRY {
		bn_null(a);
		bn_new(a);
		if (_p == NULL || _q == NULL || t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < m; i++) {
			ep_null(_p[i]);
			ep4_null(_q[i]);
			ep4_null(t[i]);
			ep_new(_p[i]);
			ep4_new(_q[i]);
			ep4_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep4_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep4_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp16_set_dig(r, 1);

		if (j > 0) {
			switch (ep_curve_is_pairf()) {
				case EP_FM16:
				case EP_N16:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k16(r, t, _q, _p, j, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp16_inv_cyc(r, r);
					}
					pp_exp_k16(r, r);
					break;
				case EP_K16:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k16(r, t, _q, _p, j, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp16_inv_cyc(r, r);
					}
					fp16_frb(r, r, 3);
					for (i = 0; i < j; i++) {
						if (bn_sign(a) == RLC_NEG) {
							ep4_neg(t[i], t[i]);
						}
						pp_fin_k16_oatep(r, t[i], _q[i], _p[i]);
					}
					pp_exp_k16(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep4_free(_q[i]);
			ep4_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}

#endif
