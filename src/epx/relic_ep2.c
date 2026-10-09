/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of point arithmetic and utilities on prime elliptic curves
 * over a quadratic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_util_tmpl.h"
#include "relic_ep_add_tmpl.h"
#include "relic_ep_dbl_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

/**
 * Adds two points represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_BASIC_IMP(ep2, fp2);

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || !defined(STRIP)

/**
 * Adds a point represented in homogeneous coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_PROJC_MIX(ep2, fp2);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep2, fp2);

#endif /* EP_ADD == PROJC */

#if EP_ADD == JACOB || !defined(STRIP)

/**
 * Adds a point represented in Jacobian coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_JACOB_MIX(ep2, fp2);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep2, fp2);

#endif /* EP_ADD == JACOB */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

TMPL_ADD_BASIC(ep2, fp2);

#endif

#if EP_ADD == PROJC || !defined(STRIP)

TMPL_ADD(ep2, projc);

#endif

#if EP_ADD == JACOB || !defined(STRIP)

TMPL_ADD(ep2, jacob);

#endif

TMPL_SUB(ep2);

#if EP_ADD == BASIC || !defined(STRIP)

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the point to double.
 */
TMPL_DBL_BASIC_IMP(ep2, fp2);

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || !defined(STRIP)

/**
 * Doubles a point represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_PROJC_IMP(ep2, fp2);

#endif /* EP_ADD == PROJC */

#if EP_ADD == JACOB || !defined(STRIP)

/**
 * Doubles a point represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_JACOB_IMP(ep2, fp2);

#endif /* EP_ADD == JACOB */

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

TMPL_EP_NORM_IMP(ep2, fp2);

#endif /* EP_ADD == PROJC */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_UTIL(ep2, fp2);

void ep2_rhs(fp2_t rhs, const fp2_t x) {
	fp2_t t0;

	fp2_null(t0);

	RLC_TRY {
		fp2_new(t0);

		fp2_sqr(t0, x);                  /* x1^2 */

		switch (ep2_curve_opt_a()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp2_sub_dig(t0, t0, 3);
				break;
			case RLC_ONE:
				fp2_add_dig(t0, t0, 1);
				break;
			case RLC_TWO:
				fp2_add_dig(t0, t0, 2);
				break;
			case RLC_TINY:
				fp2_mul_dig(t0, t0, ep2_curve_get_a()[0][0]);
				break;
#endif
			default:
				fp2_add(t0, t0, ep2_curve_get_a());
				break;
		}

		fp2_mul(t0, t0, x);				/* x1^3 + a * x */

		switch (ep2_curve_opt_b()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp2_sub_dig(t0, t0, 3);
				break;
			case RLC_ONE:
				fp2_add_dig(t0, t0, 1);
				break;
			case RLC_TWO:
				fp2_add_dig(t0, t0, 2);
				break;
			case RLC_TINY:
				fp2_mul_dig(t0, t0, ep2_curve_get_b()[0][0]);
				break;
#endif
			default:
				fp2_add(t0, t0, ep2_curve_get_b());
				break;
		}

		fp2_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t0);
	}
}

size_t ep2_size_bin(const ep2_t a, int pack) {
	ep2_t t;
	size_t size = 0;

	ep2_null(t);

	if (ep2_is_infty(a)) {
		return 1;
	}

	RLC_TRY {
		ep2_new(t);

		ep2_norm(t, a);

		size = 1 + 2 * RLC_FP_BYTES;
		if (!pack) {
			size += 2 * RLC_FP_BYTES;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep2_free(t);
	}

	return size;
}

void ep2_read_bin(ep2_t a, const uint8_t *bin, size_t len) {
	if (len == 1) {
		if (bin[0] == 0) {
			ep2_set_infty(a);
			return;
		} else {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		}
	}

	if (len != (2 * RLC_FP_BYTES + 1) && len != (4 * RLC_FP_BYTES + 1)) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	a->coord = BASIC;
	fp2_set_dig(a->z, 1);
	fp2_read_bin(a->x, bin + 1, 2 * RLC_FP_BYTES);
	if (len == 2 * RLC_FP_BYTES + 1) {
		switch(bin[0]) {
			case 2:
				fp2_zero(a->y);
				break;
			case 3:
				fp2_zero(a->y);
				fp_set_bit(a->y[0], 0, 1);
				fp_zero(a->y[1]);
				break;
			default:
				RLC_THROW(ERR_NO_VALID);
				break;
		}
		ep2_upk(a, a);
	}

	if (len == 4 * RLC_FP_BYTES + 1) {
		if (bin[0] == 4) {
			fp2_read_bin(a->y, bin + 2 * RLC_FP_BYTES + 1, 2 * RLC_FP_BYTES);
		} else {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}

	if (!ep2_on_curve(a)) {
		RLC_THROW(ERR_NO_VALID);
	}
}

void ep2_write_bin(uint8_t *bin, size_t len, const ep2_t a, int pack) {
	ep2_t t;

	ep2_null(t);

	memset(bin, 0, len);

	if (ep2_is_infty(a)) {
		if (len < 1) {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		} else {
			return;
		}
	}

	RLC_TRY {
		ep2_new(t);

		ep2_norm(t, a);

		if (pack) {
			if (len < 2 * RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
			} else {
				ep2_pck(t, t);
				bin[0] = 2 | fp_get_bit(t->y[0], 0);
				fp2_write_bin(bin + 1, 2 * RLC_FP_BYTES, t->x, 0);
			}
		} else {
			if (len < 4 * RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
			} else {
				bin[0] = 4;
				fp2_write_bin(bin + 1, 2 * RLC_FP_BYTES, t->x, 0);
				fp2_write_bin(bin + 2 * RLC_FP_BYTES + 1, 2 * RLC_FP_BYTES, t->y, 0);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep2_free(t);
	}
}

TMPL_EP_CMP(ep2, fp2);

TMPL_EP_NEG(ep2, fp2);

#if EP_ADD == BASIC || !defined(STRIP)

TMPL_DBL_BASIC(ep2, fp2);

#endif

#if EP_ADD == PROJC || !defined(STRIP)

TMPL_DBL(ep2, projc);

#endif

#if EP_ADD == JACOB || !defined(STRIP)

TMPL_DBL(ep2, jacob);

#endif

TMPL_EP_NORM(ep2, fp2);

void ep2_frb(ep2_t r, const ep2_t p, int i) {
	if (ep2_curve_opt_a() == RLC_ZERO) {
		ctx_t *ctx = core_get();

		ep2_copy(r, p);
		for (; i > 0; i--) {
			fp2_frb(r->x, r->x, 1);
			fp2_frb(r->y, r->y, 1);
			fp2_frb(r->z, r->z, 1);
			fp2_mul(r->x, r->x, ctx->ep2_frb[0]);
			fp2_mul(r->y, r->y, ctx->ep2_frb[1]);
		}
	} else {
		bn_t t;

		bn_null(t);

		RLC_TRY {
			bn_new(t);
			
			/* Can we do faster than this? */
			fp_prime_get_par(t);
			for (; i > 0; i--) {
				ep2_mul_basic(r, p, t);
			}
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_NO_MEMORY);
		} RLC_FINALLY {
			bn_free(t);
		}
	}
}

#if defined(EP_ENDOM)

void ep2_psi(ep2_t r, const ep2_t p) {
	ep2_frb(r, p, 1);
}

#endif

void ep2_pck(ep2_t r, const ep2_t p) {
	bn_t halfQ, yValue;

    bn_null(halfQ);
    bn_null(yValue);

	RLC_TRY {
		bn_new(halfQ);
		bn_new(yValue);

        halfQ->used = RLC_FP_DIGS;
        dv_copy(halfQ->dp, fp_prime_get(), RLC_FP_DIGS);
        bn_hlv(halfQ, halfQ);

        fp_prime_back(yValue, p->y[1]);

        int b = bn_cmp(yValue, halfQ) == RLC_GT;

        fp2_copy(r->x, p->x);
        fp2_zero(r->y);
        fp_set_bit(r->y[0], 0, b);
        fp_zero(r->y[1]);
        fp_set_dig(r->z[0], 1);
        fp_zero(r->z[1]);
        r->coord = BASIC;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(yValue);
		bn_free(halfQ);
	}
}

int ep2_upk(ep2_t r, const ep2_t p) {
	fp2_t t;
	bn_t halfQ;
	bn_t yValue;
	int result = 0;

	fp2_null(t);
	bn_null(halfQ);
	bn_null(yValue);

	RLC_TRY {
		fp2_new(t);
		bn_new(halfQ);
		bn_new(yValue);

		ep2_rhs(t, p->x);

		/* t0 = sqrt(x1^3 + a * x1 + b). */
		result = fp2_srt(t, t);

		if (result) {
			/* Verify whether the y coordinate is the larger one, matches the
			 * compressed y-coordinate (IETF pairing friendly spec)
			 * sign_F_p^2(y') := { sign_F_p(y'_0) if y'_1 equals 0, else
			 *          	     { 1 if y'_1 > (p - 1) / 2, else
			 *                   { 0 otherwise.
			 *
			 */
			halfQ->used = RLC_FP_DIGS;
			dv_copy(halfQ->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_hlv(halfQ, halfQ);

			fp_prime_back(yValue, t[1]);

			if (bn_is_zero(yValue)) {
				fp_prime_back(yValue, t[0]);
			}

			int sign_fp2y = bn_cmp(yValue, halfQ) == RLC_GT;

			if (sign_fp2y != fp_get_bit(p->y[0], 0)) {
				fp2_neg(t, t);
			}
			fp2_copy(r->x, p->x);
			fp2_copy(r->y, t);
			fp_set_dig(r->z[0], 1);
			fp_zero(r->z[1]);
			r->coord = BASIC;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
		bn_free(yValue);
		bn_free(halfQ);
	}
	return result;
}
