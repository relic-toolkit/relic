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
 * Implementation of comparison for points on prime elliptic curves over
 * quartic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int ep8_is_infty(const ep8_t p) {
	return (fp8_is_zero(p->z) == 1);
}

void ep8_set_infty(ep8_t p) {
	fp8_zero(p->x);
	fp8_zero(p->y);
	fp8_zero(p->z);
	p->coord = BASIC;
}

void ep8_copy(ep8_t r, const ep8_t p) {
	fp8_copy(r->x, p->x);
	fp8_copy(r->y, p->y);
	fp8_copy(r->z, p->z);
	r->coord = p->coord;
}

void ep8_rand(ep8_t p) {
	bn_t n, k;

	bn_null(k);
	bn_null(n);

	RLC_TRY {
		bn_new(k);
		bn_new(n);

		ep8_curve_get_ord(n);
		bn_rand_mod(k, n);

		ep8_mul_gen(p, k);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		bn_free(n);
	}
}

void ep8_blind(ep8_t r, const ep8_t p) {
	fp8_t rand;

	fp8_null(rand);

	RLC_TRY {
		fp8_new(rand);
		fp8_rand(rand);
#if EP_ADD == BASIC
		(void)rand;
		ep8_copy(r, p);
#else
		fp8_mul(r->z, p->z, rand);
		fp8_mul(r->y, p->y, rand);
		fp8_sqr(rand, rand);
		fp8_mul(r->x, r->x, rand);
		fp8_mul(r->y, r->y, rand);
		r->coord = EP_ADD;
#endif
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(rand);
	}
}

void ep8_rhs(fp8_t rhs, const ep8_t p) {
	fp8_t t0, t1;

	fp8_null(t0);
	fp8_null(t1);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);

		fp8_sqr(t0, p->x);                  /* x1^2 */

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
				ep8_curve_get_a(t1);
				fp_mul_dig(t0[0][0][0], t0[0][0][0], t1[0][0][0][0]);
				fp_mul_dig(t0[0][0][1], t0[0][0][1], t1[0][0][0][0]);
				fp_mul_dig(t0[0][1][0], t0[0][1][0], t1[0][0][0][0]);
				fp_mul_dig(t0[0][1][1], t0[0][1][1], t1[0][0][0][0]);
				fp_mul_dig(t0[1][0][0], t0[1][0][0], t1[0][0][0][0]);
				fp_mul_dig(t0[1][0][1], t0[1][0][1], t1[0][0][0][0]);
				fp_mul_dig(t0[1][1][0], t0[1][1][0], t1[0][0][0][0]);
				fp_mul_dig(t0[1][1][1], t0[1][1][1], t1[0][0][0][0]);
				break;
#endif
			default:
				ep8_curve_get_a(t1);
				fp8_add(t0, t0, t1);
				break;
		}

		fp8_mul(t0, t0, p->x);				/* x1^3 + a * x */

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
				ep8_curve_get_b(t1);
				fp_mul_dig(t0[0][0][0], t0[0][0][0], t1[0][0][0][0]);
				fp_mul_dig(t0[0][1][0], t0[0][1][0], t1[0][0][0][0]);
				fp_mul_dig(t0[1][0][0], t0[0][0][0], t1[0][0][0][0]);
				fp_mul_dig(t0[1][1][0], t0[1][1][0], t1[0][0][0][0]);
				break;
#endif
			default:
				ep8_curve_get_b(t1);
				fp8_add(t0, t0, t1);
				break;
		}

		fp8_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
	}
}


int ep8_on_curve(const ep8_t p) {
	ep8_t t;
	int r = 0;

	ep8_null(t);

	RLC_TRY {
		ep8_new(t);

		ep8_norm(t, p);

		ep8_rhs(t->x, t);
		fp8_sqr(t->y, t->y);

		r = (fp8_cmp(t->x, t->y) == RLC_EQ) || ep8_is_infty(p);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep8_free(t);
	}
	return r;
}

void ep8_tab(ep8_t *t, const ep8_t p, int w) {
	if (w > 2) {
		ep8_dbl(t[0], p);
#if defined(EP_MIXED)
		ep8_norm(t[0], t[0]);
#endif
		ep8_add(t[1], t[0], p);
		for (int i = 2; i < (1 << (w - 2)); i++) {
			ep8_add(t[i], t[i - 1], t[0]);
		}
#if defined(EP_MIXED)
		ep8_norm_sim(t + 1, t + 1, (1 << (w - 2)) - 1);
#endif
	}
#if defined(EP_MIXED)
	ep8_norm(t[0], p);
#else
	ep8_copy(t[0], p);
#endif
}

void ep8_print(const ep8_t p) {
	fp8_print(p->x);
	fp8_print(p->y);
	fp8_print(p->z);
}

int ep8_size_bin(const ep8_t a, int pack) {
	ep8_t t;
	int size = 0;

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
			fp8_write_bin(bin + 1, 8 * RLC_FP_BYTES, t->x);
			fp8_write_bin(bin + 8 * RLC_FP_BYTES + 1, 8 * RLC_FP_BYTES, t->y);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep8_free(t);
	}
}
