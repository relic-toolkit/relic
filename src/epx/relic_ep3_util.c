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
 * Implementation of comparison for points on prime elliptic curves over
 * quartic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int ep3_is_infty(const ep3_t p) {
	return (fp3_is_zero(p->z) == 1);
}

void ep3_set_infty(ep3_t p) {
	fp3_zero(p->x);
	fp3_zero(p->y);
	fp3_zero(p->z);
	p->coord = BASIC;
}

void ep3_copy(ep3_t r, const ep3_t p) {
	fp3_copy(r->x, p->x);
	fp3_copy(r->y, p->y);
	fp3_copy(r->z, p->z);
	r->coord = p->coord;
}

void ep3_rand(ep3_t p) {
	bn_t n, k;

	bn_null(k);
	bn_null(n);

	RLC_TRY {
		bn_new(k);
		bn_new(n);

		ep3_curve_get_ord(n);
		bn_rand_mod(k, n);

		ep3_mul_gen(p, k);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		bn_free(n);
	}
}

void ep3_blind(ep3_t r, const ep3_t p) {
	fp3_t rand;

	fp3_null(rand);

	RLC_TRY {
		fp3_new(rand);
		fp3_rand(rand);
#if EP_ADD == BASIC
		(void)rand;
		ep3_copy(r, p);
#else
		fp3_mul(r->z, p->z, rand);
		fp3_mul(r->y, p->y, rand);
		fp3_sqr(rand, rand);
		fp3_mul(r->x, r->x, rand);
		fp3_mul(r->y, r->y, rand);
		r->coord = EP_ADD;
#endif
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free(rand);
	}
}

void ep3_rhs(fp3_t rhs, const ep3_t p) {
	fp3_t t0, t1;

	fp3_null(t0);
	fp3_null(t1);

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);

		fp3_sqr(t0, p->x);                  /* x1^2 */

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
				ep3_curve_get_a(t1);
				fp3_mul_dig(t0, t0, t1[0][0]);
				break;
#endif
			default:
				ep3_curve_get_a(t1);
				fp3_add(t0, t0, t1);
				break;
		}

		fp3_mul(t0, t0, p->x);				/* x1^3 + a * x */

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
				ep3_curve_get_b(t1);
				fp3_mul_dig(t0, t0, t1[0][0]);
				break;
#endif
			default:
				ep3_curve_get_b(t1);
				fp3_add(t0, t0, t1);
				break;
		}

		fp3_copy(rhs, t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp3_free(t0);
		fp3_free(t1);
	}
}


int ep3_on_curve(const ep3_t p) {
	ep3_t t;
	int r = 0;

	ep3_null(t);

	RLC_TRY {
		ep3_new(t);

		ep3_norm(t, p);

		ep3_rhs(t->x, t);
		fp3_sqr(t->y, t->y);

		r = (fp3_cmp(t->x, t->y) == RLC_EQ) || ep3_is_infty(p);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t);
	}
	return r;
}

void ep3_tab(ep3_t *t, const ep3_t p, int w) {
	if (w > 2) {
		ep3_dbl(t[0], p);
#if defined(EP_MIXED)
		ep3_norm(t[0], t[0]);
#endif
		ep3_add(t[1], t[0], p);
		for (int i = 2; i < (1 << (w - 2)); i++) {
			ep3_add(t[i], t[i - 1], t[0]);
		}
#if defined(EP_MIXED)
		ep3_norm_sim(t + 1, t + 1, (1 << (w - 2)) - 1);
#endif
	}
#if defined(EP_MIXED)
	ep3_norm(t[0], p);
#else
	ep3_copy(t[0], p);
#endif
}

void ep3_print(const ep3_t p) {
	fp3_print(p->x);
	fp3_print(p->y);
	fp3_print(p->z);
}

int ep3_size_bin(const ep3_t a, int pack) {
	ep3_t t;
	int size = 0;

	ep3_null(t);

	if (ep3_is_infty(a)) {
		return 1;
	}

	RLC_TRY {
		ep3_new(t);

		ep3_norm(t, a);

		size = 1 + 8 * RLC_FP_BYTES;
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

	if (len != (8 * RLC_FP_BYTES + 1)) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	a->coord = BASIC;
	fp3_set_dig(a->z, 1);
	fp3_read_bin(a->x, bin + 1, 3 * RLC_FP_BYTES);

	if (len == 8 * RLC_FP_BYTES + 1) {
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

		if (len < 8 * RLC_FP_BYTES + 1) {
			RLC_THROW(ERR_NO_BUFFER);
		} else {
			bin[0] = 4;
			fp3_write_bin(bin + 1, 3 * RLC_FP_BYTES, t->x);
			fp3_write_bin(bin + 3 * RLC_FP_BYTES + 1, 3 * RLC_FP_BYTES, t->y);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(t);
	}
}
