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
 * Implementation of the pairings over prime curves.
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
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k2(fp2_t r, ep_t t, ep_t p, ep_t q, bn_t a) {
	fp2_t l;
	ep_t _q;

	fp2_null(l);
	ep_null(_q);

	TRY {
		fp2_new(l);
		ep_new(_q);

		fp2_zero(l);
		ep_copy(t, p);
		ep_neg(_q, q);

		for (int i = bn_bits(a) - 2; i >= 0; i--) {
			fp2_sqr(r, r);
			pp_dbl_k2(l, t, t, _q);
			fp2_mul(r, r, l);
			if (bn_get_bit(a, i)) {
				pp_add_k2(l, t, p, q);
				fp2_mul(r, r, l);
			}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp2_free(l);
		ep_free(_q);
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
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_lit_k2(fp2_t r, ep_t t, ep_t p, ep_t q, bn_t a) {
	fp2_t l, m;
	ep_t _q;

	fp2_null(l);
	ep_null(_q);

	TRY {
		fp2_new(l);
		fp2_new(m);
		ep_new(_q);

		fp2_zero(l);
		fp2_zero(m);
		ep_copy(t, p);
		ep_neg(_q, q);

		for (int i = bn_bits(a) - 2; i >= 0; i--) {
			fp2_sqr(r, r);
			pp_dbl_k2(l, t, t, _q);
			fp_copy(m[0], l[1]);
			fp_copy(m[1], l[0]);
			fp2_mul(r, r, m);
			if (bn_get_bit(a, i)) {
				pp_add_k2(l, t, p, q);
				fp_copy(m[0], l[1]);
				fp_copy(m[1], l[0]);
				fp2_mul(r, r, m);
			}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp2_free(l);
		fp2_free(m);
		ep_free(_q);
	}
}

/**
 * Compute the Miller loop for pairings of type G_2 x G_1 over the bits of a
 * given parameter.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the first pairing argument in affine coordinates.
 * @param[in] p				- the second pairing argument in affine coordinates.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k12(fp12_t r, ep2_t t, ep2_t q, ep_t p, bn_t a) {
	fp12_t l;
	ep_t _p;

	fp12_null(l);
	ep_null(_p);

	TRY {
		fp12_new(l);
		ep_new(_p);

		fp12_zero(l);
		ep2_copy(t, q);

		/* Precomputing. */
#if EP_ADD == BASIC
		ep_neg(_p, p);
#else
		fp_add(_p->x, p->x, p->x);
		fp_add(_p->x, _p->x, p->x);
		fp_neg(_p->y, p->y);
#endif

		pp_dbl_k12(r, t, t, _p);
		if (bn_get_bit(a, bn_bits(a) - 2)) {
			pp_add_k12(l, t, q, p);
			fp12_mul_dxs(r, r, l);
		}
		for (int i = bn_bits(a) - 3; i >= 0; i--) {
			fp12_sqr(r, r);
			pp_dbl_k12(l, t, t, _p);
			fp12_mul_dxs(r, r, l);
			if (bn_get_bit(a, i)) {
				pp_add_k12(l, t, q, p);
				fp12_mul_dxs(r, r, l);
			}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp12_free(l);
		ep_free(_p);
	}
}

/**
 * Compute the Miller loop for pairings of type G_2 x G_1 over the bits of a
 * given parameter represented in sparse form.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the first pairing argument in affine coordinates.
 * @param[in] p				- the second pairing argument in affine coordinates.
 * @param[in] s				- the loop parameter in sparse form.
 * @paramin] len			- the length of the loop parameter.
 */
static void pp_mil_sps_k12(fp12_t r, ep2_t t, ep2_t q, ep_t p, int *s, int len) {
	fp12_t l;
	ep_t _p;
	ep2_t _q;

	fp12_null(l);
	ep_null(_p);
	ep2_null(_q);

	TRY {
		fp12_new(l);
		ep_new(_p);
		ep2_new(_q);

		fp12_zero(l);
		ep2_copy(t, q);
		ep2_neg(_q, q);

#if EP_ADD == BASIC
		ep_neg(_p, p);
#else
		fp_add(_p->x, p->x, p->x);
		fp_add(_p->x, _p->x, p->x);
		fp_neg(_p->y, p->y);
#endif

		pp_dbl_k12(r, t, t, _p);
		if (s[len - 2] > 0) {
			pp_add_k12(l, t, q, p);
			fp12_mul_dxs(r, r, l);
		}
		if (s[len - 2] < 0) {
			pp_add_k12(l, t, _q, p);
			fp12_mul_dxs(r, r, l);
		}
		for (int i = len - 3; i >= 0; i--) {
			fp12_sqr(r, r);
			pp_dbl_k12(l, t, t, _p);
			fp12_mul_dxs(r, r, l);
			if (s[i] > 0) {
				pp_add_k12(l, t, q, p);
				fp12_mul_dxs(r, r, l);
			}
			if (s[i] < 0) {
				pp_add_k12(l, t, _q, p);
				fp12_mul_dxs(r, r, l);
			}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp12_free(l);
		ep_free(_p);
		ep2_free(_q);
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
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_lit_k12(fp12_t r, ep_t t, ep_t p, ep2_t q, bn_t a) {
	fp12_t l;
	ep2_t _q;

	fp12_null(l);
	ep2_null(_q);

	TRY {
		fp12_new(l);
		ep2_new(_q);

		ep_copy(t, p);
		ep2_neg(_q, q);
		fp12_zero(l);

		for (int i = bn_bits(a) - 2; i >= 0; i--) {
			fp12_sqr(r, r);
			pp_dbl_lit_k12(l, t, t, _q);
			fp12_mul(r, r, l);
			if (bn_get_bit(a, i)) {
				pp_add_lit_k12(l, t, p, q);
				fp12_mul(r, r, l);
			}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp12_free(l);
		ep2_free(_q);
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
static void pp_fin_k12_oatep(fp12_t r, ep2_t t, ep2_t q, ep_t p) {
	ep2_t q1, q2;
	fp12_t tmp;

	fp12_null(tmp);
	ep2_null(q1);
	ep2_null(q2);

	TRY {
		ep2_new(q1);
		ep2_new(q2);
		fp12_new(tmp);
		fp12_zero(tmp);

		fp2_set_dig(q1->z, 1);
		fp2_set_dig(q2->z, 1);

		ep2_frb(q1, q, 1);
		ep2_frb(q2, q, 2);
		ep2_neg(q2, q2);

		pp_add_k12(tmp, t, q1, p);
		fp12_mul_dxs(r, r, tmp);
		pp_add_k12(tmp, t, q2, p);
		fp12_mul_dxs(r, r, tmp);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		fp12_free(tmp);
		ep2_free(q1);
		ep2_free(q2);
	}
}


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_map_init(void) {
	ep2_curve_init();
}

void pp_map_clean(void) {
	ep2_curve_clean();
}

#if PP_MAP == TATEP || PP_MAP == OATEP || !defined(STRIP)

void pp_map_tatep_k2(fp2_t r, ep_t p, ep_t q) {
	ep_t _p, _q, t;
	bn_t n;

	ep_null(_p);
	ep_null(_q);
	ep_null(t);
	bn_null(n);

	TRY {
		ep_new(t);
		bn_new(n);

		ep_norm(_p, p);
		ep_norm(_q, q);
		ep_curve_get_ord(n);
		/* Since p has order n, we do not have to perform last iteration. */
		bn_sub_dig(n, n, 1);
		fp2_set_dig(r, 1);

		if (!ep_is_infty(_p) && !ep_is_infty(_q)) {
			pp_mil_k2(r, t, _p, _q, n);
			pp_exp_k2(r, r);
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep_free(_p);
		ep_free(_q);
		ep_free(t);
		bn_free(n);
	}
}

#endif

#if PP_MAP == TATEP || !defined(STRIP)

void pp_map_tatep_k12(fp12_t r, ep_t p, ep2_t q) {
	ep_t _p, t;
	ep2_t _q;
	bn_t n;

	ep_null(_p);
	ep_null(t);
	ep2_null(_q);
	bn_null(n);

	TRY {
		ep_new(_p);
		ep_new(t);
		ep2_new(_q);
		bn_new(n);

		ep_norm(_p, p);
		ep2_norm(_q, q);
		ep_curve_get_ord(n);
		fp12_set_dig(r, 1);

		if (!ep_is_infty(_p) && !ep2_is_infty(_q)) {
			pp_mil_lit_k12(r, t, _p, _q, n);
			pp_exp_k12(r, r);
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep_free(_p);
		ep_free(t);
		ep2_free(_q);
		bn_free(n);
	}
}

#endif

#if PP_MAP == WEILP || !defined(STRIP)

void pp_map_weilp_k2(fp2_t r, ep_t p, ep_t q) {
	ep_t _p, _q, t0, t1;
	fp2_t r0, r1;
	bn_t n;

	ep_null(_p);
	ep_null(_q);
	ep_null(t0);
	ep_null(t1);
	fp2_null(r0);
	fp2_null(r1);
	bn_null(n);

	TRY {
		ep_new(_p);
		ep_new(_q);
		ep_new(t0);
		ep_new(t1);
		fp2_new(r0);
		fp2_new(r1);
		bn_new(n);

		ep_norm(_p, p);
		ep_norm(_q, q);
		ep_curve_get_ord(n);
		/* Since p has order n, we do not have to perform last iteration. */
		bn_sub_dig(n, n, 1);
		fp2_set_dig(r0, 1);
		fp2_set_dig(r1, 1);

		if (!ep_is_infty(_p) && !ep_is_infty(_q)) {
			pp_mil_lit_k2(r0, t0, _p, _q, n);
			pp_mil_k2(r1, t1, _q, _p, n);
			fp2_inv(r1, r1);
			fp2_mul(r0, r0, r1);
			fp2_inv(r1, r0);
			fp2_inv_uni(r0, r0);
		}
		fp2_mul(r, r0, r1);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep_free(_p);
		ep_free(_q);
		ep_free(t0);
		ep_free(t1);
		fp2_free(r0);
		fp2_free(r1);
		bn_free(n);
	}
}

void pp_map_weilp_k12(fp12_t r, ep_t p, ep2_t q) {
	ep_t _p, t0;
	ep2_t _q, t1;
	fp12_t r0, r1;
	bn_t n;

	ep_null(_p);
	ep_null(t0);
	ep2_null(_q);
	ep2_null(t1);
	fp12_null(r0);
	fp12_null(r1);
	bn_null(n);

	TRY {
		ep_new(_p);
		ep_new(t0);
		ep2_new(_q);
		ep2_new(t1);
		fp12_new(r0);
		fp12_new(r1);
		bn_new(n);

		ep_norm(_p, p);
		ep2_norm(_q, q);
		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp12_set_dig(r0, 1);
		fp12_set_dig(r1, 1);

		if (!ep_is_infty(_p) && !ep2_is_infty(_q)) {
			pp_mil_lit_k12(r0, t0, _p, _q, n);
			pp_mil_k12(r1, t1, _q, _p, n);
			fp12_inv(r1, r1);
			fp12_mul(r0, r0, r1);
			fp12_inv(r1, r0);
			fp12_inv_uni(r0, r0);
		}
		fp12_mul(r, r0, r1);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep_free(_p);
		ep_free(t0);
		ep2_free(_q);
		ep2_free(t1);
		fp12_free(r0);
		fp12_free(r1);
		bn_free(n);
	}
}

#endif


#if PP_MAP == OATEP || !defined(STRIP)

void pp_map_oatep_k12(fp12_t r, ep_t p, ep2_t q) {
	ep_t _p;
	ep2_t t, _q;
	bn_t a;
	int len = FP_BITS, s[FP_BITS];

	ep_null(_p);
	ep2_null(_q);	
	ep2_null(t);
	bn_null(a);

	TRY {
		ep_new(_p);
		ep2_new(_q);
		ep2_new(t);
		bn_new(a);


		ep_norm(_p, p);
		ep2_norm(_q, q);
		fp_param_get_var(a);
		bn_mul_dig(a, a, 6);
		bn_add_dig(a, a, 2);
		fp_param_get_map(s, &len);
		fp12_set_dig(r, 1);

		if (!ep_is_infty(p) && !ep2_is_infty(q)) {
			switch (ep_param_get()) {
				case BN_P158:
				case BN_P254:
				case BN_P256:
				case BN_P638:
					/* r = f_{|a|,Q}(P). */
					pp_mil_sps_k12(r, t, _q, _p, s, len);
					if (bn_sign(a) == BN_NEG) {
						/* f_{-a,Q}(P) = 1/f_{a,Q}(P). */
						fp12_inv_uni(r, r);
						ep2_neg(t, t);
					}
					pp_fin_k12_oatep(r, t, _q, _p);
					pp_exp_k12(r, r);
					break;
				case B12_P638:
					/* r = f_{|a|,Q}(P). */
					pp_mil_sps_k12(r, t, _q, _p, s, len);
					if (bn_sign(a) == BN_NEG) {
						fp12_inv_uni(r, r);
						ep2_neg(t, t);
					}
					pp_exp_k12(r, r);
					break;
			}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep_free(_p);
		ep2_free(_q);
		ep2_free(t);
		bn_free(a);
	}
}

#endif
