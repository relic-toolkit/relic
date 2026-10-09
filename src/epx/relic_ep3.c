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
 * Implementation of point arithmetic and utilities on prime elliptic curves
 * over a cubic extension field.
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
TMPL_ADD_BASIC_IMP(ep3, fp3);

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
TMPL_ADD_PROJC_MIX(ep3, fp3);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep3, fp3);

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
TMPL_ADD_JACOB_MIX(ep3, fp3);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep3, fp3);

#endif /* EP_ADD == JACOB */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

TMPL_ADD_BASIC(ep3, fp3);

#endif

#if EP_ADD == PROJC || !defined(STRIP)

TMPL_ADD(ep3, projc);

#endif

#if EP_ADD == JACOB || !defined(STRIP)

TMPL_ADD(ep3, jacob);

#endif

TMPL_SUB(ep3);

#if EP_ADD == BASIC || !defined(STRIP)

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the point to double.
 */
TMPL_DBL_BASIC_IMP(ep3, fp3);

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || !defined(STRIP)

/**
 * Doubles a point represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_PROJC_IMP(ep3, fp3);

#endif /* EP_ADD == PROJC */

#if EP_ADD == JACOB || !defined(STRIP)

/**
 * Doubles a point represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_JACOB_IMP(ep3, fp3);

#endif /* EP_ADD == JACOB */

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

TMPL_EP_NORM_IMP(ep3, fp3);

#endif /* EP_ADD == PROJC */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_UTIL(ep3, fp3);

void ep3_rhs(fp3_t rhs, const fp3_t x) {
	fp3_t t0;

	fp3_null(t0);

	RLC_TRY {
		fp3_new(t0);

		fp3_sqr(t0, x);                  /* x1^2 */

		switch (ep3_curve_opt_a()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp_sub_dig(t0[0], t0[0], 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0[0], t0[0], 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0[0], t0[0], 2);
				break;
			case RLC_TINY:
				fp3_mul_dig(t0, t0, ep3_curve_get_a()[0][0]);
				break;
#endif
			default:
				fp3_add(t0, t0, ep3_curve_get_a());
				break;
		}

		fp3_mul(t0, t0, x);				/* x1^3 + a * x */

		switch (ep3_curve_opt_b()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp3_sub_dig(t0, t0, 3);
				break;
			case RLC_ONE:
				fp3_add_dig(t0, t0, 1);
				break;
			case RLC_TWO:
				fp3_add_dig(t0, t0, 2);
				break;
			case RLC_TINY:
				fp3_mul_dig(t0, t0, ep3_curve_get_b()[0][0]);
				break;
#endif
			default:
				fp3_add(t0, t0, ep3_curve_get_b());
				break;
		}

		fp3_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free(t0);
	}
}

size_t ep3_size_bin(const ep3_t a, int pack) {
	ep3_t t;
	size_t size = 0;

	/* Point compression is not supported in this extension. */
	(void)pack;

	ep3_null(t);

	if (ep3_is_infty(a)) {
		return 1;
	}

	RLC_TRY {
		ep3_new(t);

		ep3_norm(t, a);

		size = 1 + 6 * RLC_FP_BYTES;
		//TODO: Implement compression.
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t);
	}

	return size;
}

void ep3_read_bin(ep3_t a, const uint8_t *bin, size_t len) {
	if (len == 1) {
		if (bin[0] == 0) {
			ep3_set_infty(a);
			return;
		} else {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		}
	}

	if (len != (6 * RLC_FP_BYTES + 1)) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	a->coord = BASIC;
	fp3_set_dig(a->z, 1);
	fp3_read_bin(a->x, bin + 1, 3 * RLC_FP_BYTES);

	if (len == 6 * RLC_FP_BYTES + 1) {
		if (bin[0] == 4) {
			fp3_read_bin(a->y, bin + 3 * RLC_FP_BYTES + 1, 3 * RLC_FP_BYTES);
		} else {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}

	if (!ep3_on_curve(a)) {
		RLC_THROW(ERR_NO_VALID);
	}
}

void ep3_write_bin(uint8_t *bin, size_t len, const ep3_t a, int pack) {
	ep3_t t;

	/* Point compression is not supported in this extension. */
	(void)pack;

	ep3_null(t);

	memset(bin, 0, len);

	if (ep3_is_infty(a)) {
		if (len < 1) {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		} else {
			return;
		}
	}

	RLC_TRY {
		ep3_new(t);

		ep3_norm(t, a);

		if (len < 6 * RLC_FP_BYTES + 1) {
			RLC_THROW(ERR_NO_BUFFER);
		} else {
			bin[0] = 4;
			fp3_write_bin(bin + 1, 3 * RLC_FP_BYTES, t->x, 0);
			fp3_write_bin(bin + 3 * RLC_FP_BYTES + 1, 3 * RLC_FP_BYTES, t->y, 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t);
	}
}

TMPL_EP_CMP(ep3, fp3);

TMPL_EP_NEG(ep3, fp3);

#if EP_ADD == BASIC || !defined(STRIP)

TMPL_DBL_BASIC(ep3, fp3);

#endif

#if EP_ADD == PROJC || !defined(STRIP)

TMPL_DBL(ep3, projc);

#endif

#if EP_ADD == JACOB || !defined(STRIP)

TMPL_DBL(ep3, jacob);

#endif

TMPL_EP_NORM(ep3, fp3);

void ep3_frb(ep3_t r, const ep3_t p, int i) {
	ctx_t *ctx = core_get();

	ep3_copy(r, p);
	for (; i > 0; i--) {
		fp3_frb(r->x, r->x, 1);
		fp3_frb(r->y, r->y, 1);
		fp3_frb(r->z, r->z, 1);
		fp3_mul(r->x, r->x, ctx->ep3_frb[0]);
		fp3_mul(r->y, r->y, ctx->ep3_frb[1]);
	}
}

#if defined(EP_ENDOM)

void ep3_psi(ep3_t r, const ep3_t p) {
	ep3_t q;

	ep3_null(q);

	if (ep3_is_infty(p)) {
		ep3_set_infty(r);
		return;
	}

	RLC_TRY {
		ep3_new(q);

		switch (ep_curve_is_pairf()) {
			case EP_SG18:
				/* -3*u = (2*p^2 - p^5) mod r */
				ep3_frb(q, p, 5);
				ep3_frb(r, p, 2);
				ep3_dbl(r, r);
				ep3_sub(r, r, q);
				break;
			case EP_K18:
				/* For KSS18, we have that u = (p^4 - 3*p) mod r. */
				ep3_dbl(q, p);
				ep3_add(q, q, p);
				ep3_frb(r, p, 3);
				ep3_sub(r, r, q);
				ep3_frb(r, r, 1);
				break;
			case EP_FM18:
				/* For FM18, we have that u = (p^4-p) mod r. */
				ep3_frb(q, p, 3);
				ep3_sub(r, q, p);
				ep3_frb(r, r, 1);
				break;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep3_free(q);
	}
}

#endif
