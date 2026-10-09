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
 * Implementation of point arithmetic and utilities on prime elliptic curves
 * over an octic extension field.
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
TMPL_ADD_BASIC_IMP(ep8, fp8);

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
TMPL_ADD_PROJC_MIX(ep8, fp8);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep8, fp8);

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
TMPL_ADD_JACOB_MIX(ep8, fp8);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep8, fp8);

#endif /* EP_ADD == JACOB */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

TMPL_ADD_BASIC(ep8, fp8);

#endif

#if EP_ADD == PROJC || !defined(STRIP)

TMPL_ADD(ep8, projc);

#endif

#if EP_ADD == JACOB || !defined(STRIP)

TMPL_ADD(ep8, jacob);

#endif

TMPL_SUB(ep8);

#if EP_ADD == BASIC || !defined(STRIP)

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the point to double.
 */
TMPL_DBL_BASIC_IMP(ep8, fp8);

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || !defined(STRIP)

/**
 * Doubles a point represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_PROJC_IMP(ep8, fp8);

#endif /* EP_ADD == PROJC */

#if EP_ADD == JACOB || !defined(STRIP)

/**
 * Doubles a point represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_JACOB_IMP(ep8, fp8);

#endif /* EP_ADD == JACOB */

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

TMPL_EP_NORM_IMP(ep8, fp8);

#endif /* EP_ADD == PROJC */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_UTIL(ep8, fp8);

void ep8_rhs(fp8_t rhs, const fp8_t x) {
	fp8_t t0;

	fp8_null(t0);

	RLC_TRY {
		fp8_new(t0);

		fp8_sqr(t0, x);

		switch (ep8_curve_opt_a()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp_sub_dig(t0[0][0][0], t0[0][0][0], 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0[0][0][0], t0[0][0][0],
					ep8_curve_get_a()[0][0][0][0]);
				break;
#endif
			default:
				fp8_add(t0, t0, ep8_curve_get_a());
				break;
		}

		fp8_mul(t0, t0, x);

		switch (ep8_curve_opt_b()) {
			case RLC_ZERO:
				break;
#if FP_RDC != MONTY
			case RLC_MIN3:
				fp_sub_dig(t0[0][0][0], t0[0][0][0], 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0[0][0][0], t0[0][0][0], 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0[0][0][0], t0[0][0][0],
					ep8_curve_get_b()[0][0][0][0]);
				break;
#endif
			default:
				fp8_add(t0, t0, ep8_curve_get_b());
				break;
		}

		fp8_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
	}
}

size_t ep8_size_bin(const ep8_t a, int pack) {
	ep8_t t;
	size_t size = 0;

	/* Point compression is not supported in this extension. */
	(void)pack;

	ep8_null(t);

	if (ep8_is_infty(a)) {
		return 1;
	}

	RLC_TRY {
		ep8_new(t);

		ep8_norm(t, a);

		size = 1 + 16 * RLC_FP_BYTES;
		//TODO: implement compression properly
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep8_free(t);
	}

	return size;
}

void ep8_read_bin(ep8_t a, const uint8_t *bin, size_t len) {
	if (len == 1) {
		if (bin[0] == 0) {
			ep8_set_infty(a);
			return;
		} else {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		}
	}

	if (len != (16 * RLC_FP_BYTES + 1)) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	a->coord = BASIC;
	fp8_set_dig(a->z, 1);
	fp8_read_bin(a->x, bin + 1, 8 * RLC_FP_BYTES);

	if (len == 16 * RLC_FP_BYTES + 1) {
		if (bin[0] == 4) {
			fp8_read_bin(a->y, bin + 8 * RLC_FP_BYTES + 1, 8 * RLC_FP_BYTES);
		} else {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}

	if (!ep8_on_curve(a)) {
		RLC_THROW(ERR_NO_VALID);
	}
}

void ep8_write_bin(uint8_t *bin, size_t len, const ep8_t a, int pack) {
	ep8_t t;

	/* Point compression is not supported in this extension. */
	(void)pack;

	ep8_null(t);

	memset(bin, 0, len);

	if (ep8_is_infty(a)) {
		if (len < 1) {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		} else {
			return;
		}
	}

	RLC_TRY {
		ep8_new(t);

		ep8_norm(t, a);

		if (len < 16 * RLC_FP_BYTES + 1) {
			RLC_THROW(ERR_NO_BUFFER);
		} else {
			bin[0] = 4;
			fp8_write_bin(bin + 1, 8 * RLC_FP_BYTES, t->x, 0);
			fp8_write_bin(bin + 8 * RLC_FP_BYTES + 1, 8 * RLC_FP_BYTES, t->y, 0);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep8_free(t);
	}
}

TMPL_EP_CMP(ep8, fp8);

TMPL_EP_NEG(ep8, fp8);

#if EP_ADD == BASIC || !defined(STRIP)

TMPL_DBL_BASIC(ep8, fp8);

#endif

#if EP_ADD == PROJC || !defined(STRIP)

TMPL_DBL(ep8, projc);

#endif

#if EP_ADD == JACOB || !defined(STRIP)

TMPL_DBL(ep8, jacob);

#endif

TMPL_EP_NORM(ep8, fp8);

void ep8_frb(ep8_t r, const ep8_t p, int i) {
	ep8_copy(r, p);
	for (; i > 0; i--) {
		fp8_frb(r->x, r->x, 1);
		fp8_frb(r->y, r->y, 1);
		fp8_frb(r->z, r->z, 1);
		fp8_mul_frb(r->x, r->x, 1, 2);
		fp8_mul_frb(r->y, r->y, 1, 3);
	}
}

#if defined(EP_ENDOM)

void ep8_psi(ep8_t r, const ep8_t p) {
	ep8_frb(r, p, 1);
}

#endif
