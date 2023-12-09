/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of pairing computation for curves with embedding degree 18.
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
static void pp_mil_k18(fp18_t r, ep3_t *t, ep3_t *q, ep_t *p, int m, bn_t a) {
	fp18_t l;
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep3_t *_q = RLC_ALLOCA(ep3_t, m);
	int i, j;
	size_t len = bn_bits(a) + 1;
	int8_t s[RLC_FP_BITS + 1];

	if (m == 0) {
		return;
	}

	fp18_null(l);

	RLC_TRY {
		fp18_new(l);
		if (_p == NULL || _q == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (j = 0; j < m; j++) {
			ep_null(_p[j]);
			ep3_null(_q[j]);
			ep_new(_p[j]);
			ep3_new(_q[j]);
			ep3_copy(t[j], q[j]);
			ep3_neg(_q[j], q[j]);
#if EP_ADD == BASIC
			ep_neg(_p[j], p[j]);
#else
			fp_add(_p[j]->x, p[j]->x, p[j]->x);
			fp_add(_p[j]->x, _p[j]->x, p[j]->x);
			fp_neg(_p[j]->y, p[j]->y);
#endif
		}

		fp18_zero(l);
		bn_rec_naf(s, &len, a, 2);
		pp_dbl_k18(r, t[0], t[0], _p[0]);
		for (j = 1; j < m; j++) {
			pp_dbl_k18(l, t[j], t[j], _p[j]);
			fp18_mul_dxs(r, r, l);
		}
		if (s[len - 2] > 0) {
			for (j = 0; j < m; j++) {
				pp_add_k18(l, t[j], q[j], p[j]);
				fp18_mul_dxs(r, r, l);
			}
		}
		if (s[len - 2] < 0) {
			for (j = 0; j < m; j++) {
				pp_add_k18(l, t[j], _q[j], p[j]);
				fp18_mul_dxs(r, r, l);
			}
		}

		for (i = len - 3; i >= 0; i--) {
			fp18_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_k18(l, t[j], t[j], _p[j]);
				fp18_mul_dxs(r, r, l);
				if (s[i] > 0) {
					pp_add_k18(l, t[j], q[j], p[j]);
					fp18_mul_dxs(r, r, l);
				}
				if (s[i] < 0) {
					pp_add_k18(l, t[j], _q[j], p[j]);
					fp18_mul_dxs(r, r, l);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free(l);
		for (j = 0; j < m; j++) {
			ep_free(_p[j]);
			ep3_free(_q[j]);
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
static void pp_mil_lit_k18(fp18_t r, ep_t *t, ep_t *p, ep3_t *q, int m, bn_t a) {
	fp18_t l;
	ep3_t *_q = RLC_ALLOCA(ep3_t, m);
	int j;

	fp18_null(l);

	RLC_TRY {
		if (_q == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		fp18_new(l);

		for (j = 0; j < m; j++) {
			ep3_null(_q[j]);
			ep3_new(_q[j]);
			ep_copy(t[j], p[j]);
			ep3_neg(_q[j], q[j]);
		}

		fp18_zero(l);
		for (int i = bn_bits(a) - 2; i >= 0; i--) {
			fp18_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_lit_k18(l, t[j], t[j], _q[j]);
				fp18_mul(r, r, l);
				if (bn_get_bit(a, i)) {
					pp_add_lit_k18(l, t[j], p[j], q[j]);
					fp18_mul(r, r, l);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free(l);
		for (j = 0; j < m; j++) {
			ep3_free(_q[j]);
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
static void pp_fin_k18_oatep(fp18_t r, ep3_t t, ep3_t q, ep_t p, int f) {
    fp18_t u, v;
    ep3_t _q;
    ep_t _p;

    fp18_null(u);
    fp18_null(v);
    ep3_null(_q);
    ep_null(_p);

    RLC_TRY {
        fp18_new(u);
        fp18_new(v);
        ep3_new(_q);
        ep3_null(_p);

		/* Compute additional line function. */
		fp18_zero(u);
		fp18_zero(v);

		switch (ep_curve_is_pairf()) {
			case EP_K18:
#if EP_ADD == BASIC
				ep_neg(_p, p);
#else
				fp_add(_p->x, p->x, p->x);
				fp_add(_p->x, _p->x, p->x);
				fp_neg(_p->y, p->y);
#endif
				/* _q = 3*p*Q. */
		        pp_dbl_k18(u, _q, q, _p);
		        pp_add_k18(v, _q, q, p);
		        pp_norm_k18(_q, _q);
		        fp18_mul_dxs(u, u, v);
		        fp18_frb(u, u, 1);
		        fp18_mul(r, r, u);
		        ep3_frb(_q, _q, 1);
		        pp_add_k18(u, t, _q, p);
		        fp18_mul_dxs(r, r, u);
				break;
			case EP_SG18:
				if (f == 1) {
					fp18_frb(u, r, 3);
					fp18_mul(r, r, u);
				}
				ep3_frb(t, t, 3);
				ep3_frb(_q, q, 2);
				pp_add_k18(v, t, _q, p);
				fp18_mul_dxs(r, r, v);
				break;
		}
    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        fp18_free(u);
        fp18_free(v);
        ep3_free(_q);
        ep_free(_p);
    }
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if PP_MAP == TATEP || !defined(STRIP)

void pp_map_tatep_k18(fp18_t r, const ep_t p, const ep3_t q) {
	ep_t _p[1], t[1];
	ep3_t _q[1];
	bn_t n;

	ep_null(_p[0]);
	ep_null(t[0]);
	ep3_null(_q[0]);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(t[0]);
		ep3_new(_q[0]);
		bn_new(n);

		ep_norm(_p[0], p);
		ep3_norm(_q[0], q);
		fp3_mul(_q[0]->x, _q[0]->x, core_get()->ep3_frb[2]);
		fp3_mul(_q[0]->y, _q[0]->y, core_get()->ep3_frb[2]);
		ep_curve_get_ord(n);
		fp18_set_dig(r, 1);

		if (!ep_is_infty(p) && !ep3_is_infty(q)) {
			pp_mil_lit_k18(r, t, _p, _q, 1, n);
			pp_exp_k18(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(t[0]);
		ep3_free(_q[0]);
		bn_free(n);
	}
}

void pp_map_sim_tatep_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m), *t = RLC_ALLOCA(ep_t, m);
	ep3_t *_q = RLC_ALLOCA(ep3_t, m);
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
			ep3_null(_q[i]);
			ep_new(_p[i]);
			ep_new(t[i]);
			ep3_new(_q[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep3_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep3_norm(_q[j], q[i]);
				fp3_mul(_q[j]->x, _q[j]->x, core_get()->ep3_frb[2]);
				fp3_mul(_q[j]->y, _q[j]->y, core_get()->ep3_frb[2]);
				j++;
			}
		}

		ep_curve_get_ord(n);
		fp18_set_dig(r, 1);
		if (j > 0) {
			pp_mil_lit_k18(r, t, _p, _q, j, n);
			pp_exp_k18(r, r);
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
			ep3_free(_q[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(t);
		RLC_FREE(_q);
	}
}

#endif

#if PP_MAP == WEILP || !defined(STRIP)

void pp_map_weilp_k18(fp18_t r, const ep_t p, const ep3_t q) {
	ep_t _p[1], t0[1];
	ep3_t _q[1], t1[1];
	fp18_t r0, r1;
	bn_t n;

	ep_null(_p[0]);
	ep_null(t0[0]);
	ep3_null(_q[0]);
	ep3_null(t1[0]);
	fp18_null(r0);
	fp18_null(r1);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(t0[0]);
		ep3_new(_q[0]);
		ep3_new(t1[0]);
		fp18_new(r0);
		fp18_new(r1);
		bn_new(n);

		ep_norm(_p[0], p);
		ep3_norm(_q[0], q);

		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp18_set_dig(r0, 1);
		fp18_set_dig(r1, 1);

		if (!ep_is_infty(_p[0]) && !ep3_is_infty(_q[0])) {
			pp_mil_k18(r1, t1, _q, _p, 1, n);
			fp3_mul(_q[0]->x, _q[0]->x, core_get()->ep3_frb[2]);
			fp3_mul(_q[0]->y, _q[0]->y, core_get()->ep3_frb[2]);
			pp_mil_lit_k18(r0, t0, _p, _q, 1, n);
			fp18_inv(r1, r1);
			fp18_mul(r0, r0, r1);
			fp18_inv(r1, r0);
			fp18_inv_cyc(r0, r0);
		}
		fp18_mul(r, r0, r1);
		fp18_sqr(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(t0[0]);
		ep3_free(_q[0]);
		ep3_free(t1[0]);
		fp18_free(r0);
		fp18_free(r1);
		bn_free(n);
	}
}

void pp_map_sim_weilp_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m), *t0 = RLC_ALLOCA(ep_t, m);
	ep3_t *_q = RLC_ALLOCA(ep3_t, m), *t1 = RLC_ALLOCA(ep3_t, m);
	fp18_t r0, r1;
	bn_t n;
	int i, j;

	fp18_null(r0);
	fp18_null(r1);
	bn_null(n);

	RLC_TRY {
		fp18_new(r0);
		fp18_new(r1);
		bn_new(n);
		if (_p == NULL || _q == NULL || t0 == NULL || t1 == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < m; i++) {
			ep_null(_p[i]);
			ep_null(t0[i]);
			ep3_null(_q[i]);
			ep3_null(t1[i]);
			ep_new(_p[i]);
			ep_new(t0[i]);
			ep3_new(_q[i]);
			ep3_new(t1[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep3_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep3_norm(_q[j++], q[i]);
			}
		}

		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp18_set_dig(r0, 1);
		fp18_set_dig(r1, 1);

		if (j > 0) {
			pp_mil_k18(r1, t1, _q, _p, j, n);
			for (i = 0; i < j; i++) {
				fp3_mul(_q[i]->x, _q[i]->x, core_get()->ep3_frb[2]);
				fp3_mul(_q[i]->y, _q[i]->y, core_get()->ep3_frb[2]);
			}
			pp_mil_lit_k18(r0, t0, _p, _q, j, n);
			fp18_inv(r1, r1);
			fp18_mul(r0, r0, r1);
			fp18_inv(r1, r0);
			fp18_inv_cyc(r0, r0);
		}
		fp18_mul(r, r0, r1);
		fp18_sqr(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free(r0);
		fp18_free(r1);
		bn_free(n);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep_free(t0[i]);
			ep3_free(_q[i]);
			ep3_free(t1[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t0);
		RLC_FREE(t1);
	}
}

#endif

#if PP_MAP == OATEP || !defined(STRIP)

void pp_map_oatep_k18(fp18_t r, const ep_t p, const ep3_t q) {
	ep_t _p[1];
	ep3_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep3_null(_q[0]);
	ep3_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep3_new(_q[0]);
		ep3_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp18_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep3_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep3_is_infty(_q[0])) {
			switch (ep_curve_is_pairf()) {
				case EP_K18:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k18(r, t, _q, _p, 1, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp18_inv_cyc(r, r);
						ep3_neg(t[0], t[0]);
					}
					pp_fin_k18_oatep(r, t[0], _q[0], _p[0], 0);
					pp_exp_k18(r, r);
					break;
				case EP_SG18:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k18(r, t, _q, _p, 1, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp18_inv_cyc(r, r);
						ep3_neg(t[0], t[0]);
					}
					pp_fin_k18_oatep(r, t[0], _q[0], _p[0], 1);
					pp_exp_k18(r, r);
					break;
				case EP_FM18:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k18(r, t, _q, _p, 1, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp18_inv_cyc(r, r);
						ep3_neg(t[0], t[0]);
					}
					pp_exp_k18(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep3_free(_q[0]);
		ep3_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_oatep_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep3_t *t = RLC_ALLOCA(ep3_t, m), *_q = RLC_ALLOCA(ep3_t, m);
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
			ep3_null(_q[i]);
			ep3_null(t[i]);
			ep_new(_p[i]);
			ep3_new(_q[i]);
			ep3_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep3_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep3_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp18_set_dig(r, 1);

		if (j > 0) {
			switch (ep_curve_is_pairf()) {
				case EP_K18:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k18(r, t, _q, _p, j, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp18_inv_cyc(r, r);
					}
					for (i = 0; i < j; i++) {
						if (bn_sign(a) == RLC_NEG) {
							ep3_neg(t[i], t[i]);
						}
						pp_fin_k18_oatep(r, t[i], _q[i], _p[i], 0);
					}
					pp_exp_k18(r, r);
					break;
				case EP_SG18:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k18(r, t, _q, _p, j, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp18_inv_cyc(r, r);
					}
					for (i = 0; i < j; i++) {
						if (bn_sign(a) == RLC_NEG) {
							ep3_neg(t[i], t[i]);
						}
						/* Apply Frobenius only once. */
						pp_fin_k18_oatep(r, t[i], _q[i], _p[i], i == 0);
					}
					pp_exp_k18(r, r);
					break;
				case EP_FM18:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k18(r, t, _q, _p, j, a);
					if (bn_sign(a) == RLC_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp18_inv_cyc(r, r);
					}
					pp_exp_k18(r, r);
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
			ep3_free(_q[i]);
			ep3_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}

#endif
