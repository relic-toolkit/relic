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
 * Implementation of point arithmetic and utilities on prime elliptic curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_util_tmpl.h"
#include "relic_ep_add_tmpl.h"
#include "relic_ep_dbl_tmpl.h"
#include "relic_ep_tpl_tmpl.h"
#include "relic_ep.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_ARITH(ep, fp);

void ep_rhs(fp_t rhs, const fp_t x) {
	fp_t t0;

	fp_null(t0);

	RLC_TRY {
		fp_new(t0);

		/* t0 = x1^2. */
		fp_sqr(t0, x);

		/* t0 = x1^2 + a */
		switch (ep_curve_opt_a()) {
			case RLC_ZERO:
				break;
#if FP_RDC != FP_MONTY
			case RLC_MIN3:
				fp_sub_dig(t0, t0, 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0, t0, 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0, t0, 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0, t0, ep_curve_get_a()[0]);
				break;
#endif
			default:
				fp_add(t0, t0, ep_curve_get_a());
				break;
		}

		/* t0 = x1^3 + a * x */
		fp_mul(t0, t0, x);

		/* t0 = x1^3 + a * x + b */
		switch (ep_curve_opt_b()) {
			case RLC_ZERO:
				break;
#if FP_RDC != FP_MONTY
			case RLC_MIN3:
				fp_sub_dig(t0, t0, 3);
				break;
			case RLC_ONE:
				fp_add_dig(t0, t0, 1);
				break;
			case RLC_TWO:
				fp_add_dig(t0, t0, 2);
				break;
			case RLC_TINY:
				fp_add_dig(t0, t0, ep_curve_get_b()[0]);
				break;
#endif
			default:
				fp_add(t0, t0, ep_curve_get_b());
				break;
		}

		fp_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(t0);
	}
}

size_t ep_size_bin(const ep_t a, int pack) {
	size_t size = 0;

	if (ep_is_infty(a)) {
		return 1;
	}

	size = 1 + RLC_FP_BYTES;
	if (!pack) {
		size += RLC_FP_BYTES;
	}

	return size;
}

int ep_read_bin(ep_t a, const uint8_t *bin, size_t len) {
	if (len == 1) {
		if (bin[0] == 0) {
			ep_set_infty(a);
			return RLC_OK;
		} else {
			RLC_THROW(ERR_NO_BUFFER);
			return RLC_ERR;
		}
	}

	if (len != (RLC_FP_BYTES + 1) && len != (2 * RLC_FP_BYTES + 1)) {
		RLC_THROW(ERR_NO_BUFFER);
		return RLC_ERR;
	}

	a->coord = EC_AFFIN;
	fp_set_dig(a->z, 1);
	if (fp_read_bin(a->x, bin + 1, RLC_FP_BYTES) != RLC_OK) {
		return RLC_ERR;
	}
	if (len == RLC_FP_BYTES + 1) {
		switch(bin[0]) {
			case 2:
				fp_zero(a->y);
				break;
			case 3:
				fp_zero(a->y);
				fp_set_bit(a->y, 0, 1);
				break;
			default:
				RLC_THROW(ERR_NO_VALID);
				return RLC_ERR;
		}
		if (!ep_upk(a, a)) {
			RLC_THROW(ERR_NO_VALID);
			return RLC_ERR;
		}
	}

	if (len == 2 * RLC_FP_BYTES + 1) {
		if (bin[0] == 4) {
			if (fp_read_bin(a->y, bin + RLC_FP_BYTES + 1, RLC_FP_BYTES)
					!= RLC_OK) {
				return RLC_ERR;
			}
		} else {
			RLC_THROW(ERR_NO_VALID);
			return RLC_ERR;
		}
	}

	if (!ep_on_curve(a)) {
		RLC_THROW(ERR_NO_VALID);
		return RLC_ERR;
	}
	return RLC_OK;
}

void ep_write_bin(uint8_t *bin, size_t len, const ep_t a, int pack) {
	ep_t t;

	ep_null(t);

	memset(bin, 0, len);

	if (ep_is_infty(a)) {
		if (len < 1) {
			RLC_THROW(ERR_NO_BUFFER);
			return;
		} else {
			return;
		}
	}

	RLC_TRY {
		ep_new(t);

		ep_norm(t, a);

		if (pack) {
			if (len < RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
			} else {
				ep_pck(t, t);
				bin[0] = 2 | fp_get_bit(t->y, 0);
				fp_write_bin(bin + 1, RLC_FP_BYTES, t->x);
			}
		} else {
			if (len < 2 * RLC_FP_BYTES + 1) {
				RLC_THROW(ERR_NO_BUFFER);
			} else {
				bin[0] = 4;
				fp_write_bin(bin + 1, RLC_FP_BYTES, t->x);
				fp_write_bin(bin + RLC_FP_BYTES + 1, RLC_FP_BYTES, t->y);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
	}
}

TMPL_EP_TPL_BASIC(ep, fp);

TMPL_EP_TPL_PROJC(ep, fp);

TMPL_EP_TPL_JACOB(ep, fp);

void ep_psi(ep_t r, const ep_t p) {
	if (ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	if (r != p) {
		ep_copy(r, p);
	}
	if (ep_curve_opt_a() == RLC_ZERO) {
		fp_mul(r->x, r->x, ep_curve_get_beta());
 	} else {
		fp_neg(r->x, r->x);
	 	fp_mul(r->y, r->y, ep_curve_get_beta());
 	}
}

void ep_pck(ep_t r, const ep_t p) {
	int b;
	bn_t hq, y;

	bn_null_all(hq, y);

	RLC_TRY {
		bn_new_all(hq, y);

		fp_copy(r->x, p->x);

		if (ep_curve_is_pairf()) {
			hq->used = RLC_FP_DIGS;
			dv_copy(hq->dp, fp_prime_get(), RLC_FP_DIGS);
			bn_hlv(hq, hq);

			fp_prime_back(y, p->y);

			b = bn_cmp(y, hq) == RLC_GT;
		} else {
			/* Take the parity of y itself, not of its representation. */
			fp_prime_back(y, p->y);
			b = bn_get_bit(y, 0);
		}

		fp_zero(r->y);
		fp_set_bit(r->y, 0, b);
		fp_set_dig(r->z, 1);

		r->coord = EC_AFFIN;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(hq, y);
	}
}

int ep_upk(ep_t r, const ep_t p) {
	fp_t t;
	bn_t hq, y;
	int result = 0;

	fp_null(t);
	bn_null_all(hq, y);

	RLC_TRY {
		fp_new(t);
		bn_new_all(hq, y);

		ep_rhs(t, p->x);

		/* t0 = sqrt(x1^3 + a * x1 + b). */
		result = fp_srt(t, t);

		if (result) {
			if (ep_curve_is_pairf()) {
				/* Verify whether the y coordinate is the larger one, matches the
				 * compressed y-coordinate, from IETF pairing friendly spec:
					sign_F_p(y) :=  { 1 if y > (p - 1) / 2, else
									{ 0 otherwise.
				*/
				hq->used = RLC_FP_DIGS;
				dv_copy(hq->dp, fp_prime_get(), RLC_FP_DIGS);
				/* hq = (p - 1) / 2, as p is odd. */
				bn_hlv(hq, hq);

				fp_prime_back(y, t);
				int sign_fpy = bn_cmp(y, hq) == RLC_GT;

				if (sign_fpy != fp_get_bit(p->y, 0)) {
					fp_neg(t, t);
				}
			} else {
				/* Verify if least significant bit of the result matches the
				 * compressed y-coordinate. */
				fp_prime_back(y, t);
				if (bn_get_bit(y, 0) != fp_get_bit(p->y, 0)) {
					fp_neg(t, t);
				}
			}
			fp_copy(r->x, p->x);
			fp_copy(r->y, t);
			fp_set_dig(r->z, 1);
			r->coord = EC_AFFIN;
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t);
		bn_free_all(hq, y);
	}
	return result;
}

int ep_is_valid(const ep_t p) {
	bn_t h, n;
	ep_t t;
	int result = 0;

	if (ep_is_infty(p) || !ep_on_curve(p)) {
		return 0;
	}

	bn_null(h);
	bn_null(n);
	ep_null(t);

	RLC_TRY {
		bn_new(h);
		bn_new(n);
		ep_new(t);

		result = 1;
		ep_curve_get_cof(h);
		if (bn_cmp_dig(h, 1) != RLC_EQ) {
			/* With a cofactor, the point must also have prime order n. The
			 * basic method is used because it does not reduce the scalar. */
			ep_curve_get_ord(n);
			ep_mul_basic(t, p, n);
			result = ep_is_infty(t);
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(h);
		bn_free(n);
		ep_free(t);
	}
	return result;
}
