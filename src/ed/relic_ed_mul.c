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
 * Implementation of the point multiplication on Twisted Edwards elliptic curves.
 *
 * @version $Id$
 * @ingroup ed
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if ED_MUL == LWNAF || !defined(STRIP)

#if defined(ED_ENDOM)

static void ed_mul_glv_imp(ed_t r, const ed_t p, const bn_t k) {
	int l, l0, l1, i, n0, n1, s0, s1;
	int8_t naf0[FP_BITS + 1], naf1[FP_BITS + 1], *t0, *t1;
	bn_t n, k0, k1, v1[3], v2[3];
	ed_t q, t[1 << (ED_WIDTH - 2)];

	bn_null(n);
	bn_null(k0);
	bn_null(k1);
	ed_null(q);

	TRY {
		bn_new(n);
		bn_new(k0);
		bn_new(k1);
		ed_new(q);
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_null(t[i]);
			ed_new(t[i]);
		}
		for (i = 0; i < 3; i++) {
			bn_null(v1[i]);
			bn_null(v2[i]);
			bn_new(v1[i]);
			bn_new(v2[i]);
		}

		ed_curve_get_ord(n);
		ed_curve_get_v1(v1);
		ed_curve_get_v2(v2);
		bn_rec_glv(k0, k1, k, n, (const bn_t *)v1, (const bn_t *)v2);
		s0 = bn_sign(k0);
		s1 = bn_sign(k1);
		bn_abs(k0, k0);
		bn_abs(k1, k1);

		if (s0 == BN_POS) {
			ed_tab(t, p, ED_WIDTH);
		} else {
			ed_neg(q, p);
			ed_tab(t, q, ED_WIDTH);
		}

		l0 = l1 = FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k0, ED_WIDTH);
		bn_rec_naf(naf1, &l1, k1, ED_WIDTH);

		l = MAX(l0, l1);
		t0 = naf0 + l - 1;
		t1 = naf1 + l - 1;
		for (i = l0; i < l; i++)
			naf0[i] = 0;
		for (i = l1; i < l; i++)
			naf1[i] = 0;

		ed_set_infty(r);
		for (i = l - 1; i >= 0; i--, t0--, t1--) {
			ed_dbl(r, r);

			n0 = *t0;
			n1 = *t1;
			if (n0 > 0) {
				ed_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				ed_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				ed_copy(q, t[n1 / 2]);
				fp_mul(q->x, q->x, ed_curve_get_beta());
				if (s0 != s1) {
					ed_neg(q, q);
				}
				ed_add(r, r, q);
			}
			if (n1 < 0) {
				ed_copy(q, t[-n1 / 2]);
				fp_mul(q->x, q->x, ed_curve_get_beta());
				if (s0 != s1) {
					ed_neg(q, q);
				}
				ed_sub(r, r, q);
			}
		}
		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(n);
		bn_free(k0);
		bn_free(k1);
		bn_free(n)
		ed_free(q);
		for (i = 0; i < 1 << (ED_WIDTH - 2); i++) {
			ed_free(t[i]);
		}
		for (i = 0; i < 3; i++) {
			bn_free(v1[i]);
			bn_free(v2[i]);
		}

	}
}

#endif /* ED_ENDOM */

#if defined(ED_PLAIN) || defined(ED_SUPER)

static void ed_mul_naf_imp(ed_t r, const ed_t p, const bn_t k) {
	int l, i, n;
	int8_t naf[FP_BITS + 1], *_k;
	ed_t t[1 << (ED_WIDTH - 2)];

	for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
		ed_null(t[i]);
	}

	TRY {
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_new(t[i]);
		}
		/* Compute the precomputation table. */
		ed_tab(t, p, ED_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = FP_BITS + 1;
		bn_rec_naf(naf, &l, k, ED_WIDTH);

		_k = naf + l - 1;

		ed_set_infty(r);
		for (i = l - 1; i >= 0; i--, _k--) {
			ed_dbl(r, r);

			n = *_k;
			if (n > 0) {
				ed_add(r, r, t[n / 2]);
			}
			if (n < 0) {
				ed_sub(r, r, t[-n / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_free(t[i]);
		}
	}
}

#endif /* ED_PLAIN || ED_SUPER */
#endif /* ED_MUL == LWNAF */

#if ED_MUL == LWNAF_MIXED || !defined(STRIP)

#if defined(ED_ENDOM)

static void ed_mul_glv_imp(ed_t r, const ed_t p, const bn_t k) {
	int l, l0, l1, i, n0, n1, s0, s1;
	int8_t naf0[FP_BITS + 1], naf1[FP_BITS + 1], *t0, *t1;
	bn_t n, k0, k1, v1[3], v2[3];
	ed_t q, t[1 << (ED_WIDTH - 2)];

	bn_null(n);
	bn_null(k0);
	bn_null(k1);
	ed_null(q);

	TRY {
		bn_new(n);
		bn_new(k0);
		bn_new(k1);
		ed_new(q);
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_null(t[i]);
			ed_new(t[i]);
		}
		for (i = 0; i < 3; i++) {
			bn_null(v1[i]);
			bn_null(v2[i]);
			bn_new(v1[i]);
			bn_new(v2[i]);
		}

		ed_curve_get_ord(n);
		ed_curve_get_v1(v1);
		ed_curve_get_v2(v2);
		bn_rec_glv(k0, k1, k, n, (const bn_t *)v1, (const bn_t *)v2);
		s0 = bn_sign(k0);
		s1 = bn_sign(k1);
		bn_abs(k0, k0);
		bn_abs(k1, k1);

		if (s0 == BN_POS) {
			ed_tab(t, p, ED_WIDTH);
		} else {
			ed_neg(q, p);
			ed_tab(t, q, ED_WIDTH);
		}

		l0 = l1 = FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k0, ED_WIDTH);
		bn_rec_naf(naf1, &l1, k1, ED_WIDTH);

		l = MAX(l0, l1);
		t0 = naf0 + l - 1;
		t1 = naf1 + l - 1;
		for (i = l0; i < l; i++)
			naf0[i] = 0;
		for (i = l1; i < l; i++)
			naf1[i] = 0;

		ed_set_infty(r);
		for (i = l - 1; i >= 0; i--, t0--, t1--) {
			ed_dbl(r, r);

			n0 = *t0;
			n1 = *t1;
			if (n0 > 0) {
				ed_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				ed_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				ed_copy(q, t[n1 / 2]);
				fp_mul(q->x, q->x, ed_curve_get_beta());
				if (s0 != s1) {
					ed_neg(q, q);
				}
				ed_add(r, r, q);
			}
			if (n1 < 0) {
				ed_copy(q, t[-n1 / 2]);
				fp_mul(q->x, q->x, ed_curve_get_beta());
				if (s0 != s1) {
					ed_neg(q, q);
				}
				ed_sub(r, r, q);
			}
		}
		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(n);
		bn_free(k0);
		bn_free(k1);
		bn_free(n)
		ed_free(q);
		for (i = 0; i < 1 << (ED_WIDTH - 2); i++) {
			ed_free(t[i]);
		}
		for (i = 0; i < 3; i++) {
			bn_free(v1[i]);
			bn_free(v2[i]);
		}

	}
}

#endif /* ED_ENDOM */

#if defined(ED_PLAIN) || defined(ED_SUPER)

static void ed_mul_naf_mixed_imp(ed_t r, const ed_t p, const bn_t k) {
	int l, i, n;
	int8_t naf[FP_BITS + 1], *_k;
	ed_t t[1 << (ED_WIDTH - 2)];

	for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
		ed_null(t[i]);
	}

	TRY {
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_new(t[i]);
		}
		/* Compute the precomputation table. */
		ed_tab(t, p, ED_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = FP_BITS + 1;
		bn_rec_naf(naf, &l, k, ED_WIDTH);

		_k = naf + l - 1;
		ed_set_infty(r);
		for (i = l - 1; i >= 0; i--, _k--) {
			n = *_k;
			if (n == 0) {
				/* doubling is followed by another doubling */
				if (i > 0) {
					ed_dbl_short(r, r);
				} else {
					/* use full extended coordinate doubling for last step */
					ed_dbl(r, r);
				}
			} else {
				ed_dbl(r, r);
				if (n > 0) {
					ed_add(r, r, t[n / 2]);
				} else if (n < 0) {
					ed_sub(r, r, t[-n / 2]);
				}
			}
		}
		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_free(t[i]);
		}
	}
}

#endif /* ED_PLAIN || ED_SUPER */
#endif /* ED_MUL == LWNAF_MIXED */

#if ED_MUL == LWREG || !defined(STRIP)

#if defined(ED_PLAIN) || defined(ED_SUPER)

static void ed_mul_reg_imp(ed_t r, const ed_t p, const bn_t k) {
	int l, i, j, n;
	int8_t reg[CEIL(FP_BITS + 1, ED_WIDTH - 1)], *_k;
	ed_t t[1 << (ED_WIDTH - 2)];

	for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
		ed_null(t[i]);
	}

	TRY {
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_new(t[i]);
		}
		/* Compute the precomputation table. */
		ed_tab(t, p, ED_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = CEIL(FP_BITS + 1, ED_WIDTH - 1);
		bn_rec_reg(reg, &l, k, FP_BITS, ED_WIDTH);

		_k = reg + l - 1;

		ed_set_infty(r);
		for (i = l - 1; i >= 0; i--, _k--) {
			for (j = 0; j < ED_WIDTH - 1; j++) {
				ed_dbl(r, r);
			}

			n = *_k;
			if (n > 0) {
				ed_add(r, r, t[n / 2]);
			}
			if (n < 0) {
				ed_sub(r, r, t[-n / 2]);
			}
		}

		/* Convert r to affine coordinates. */
		ed_norm(r, r);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (ED_WIDTH - 2)); i++) {
			ed_free(t[i]);
		}
	}
}

#endif /* ED_PLAIN || ED_SUPER */
#endif /* ED_MUL == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if ED_MUL == BASIC || !defined(STRIP)

void ed_mul_basic(ed_t r, const ed_t p, const bn_t k) {
	int i, l;
	ed_t t;

	ed_null(t);

	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

	TRY {
		ed_new(t);
		l = bn_bits(k);

		ed_copy(t, p);
		for (i = l - 2; i >= 0; i--) {
			ed_dbl(t, t);
			if (bn_get_bit(k, i)) {
				ed_add(t, t, p);
			}
		}

		ed_norm(r, t);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(t);
	}
}

#endif

#if ED_MUL == SLIDE || !defined(STRIP)

void ed_mul_slide(ed_t r, const ed_t p, const bn_t k) {
	ed_t t[1 << (ED_WIDTH - 1)], q;
	int i, j, l;
	uint8_t win[FP_BITS + 1];

	ed_null(q);

	/* Initialize table. */
	for (i = 0; i < (1 << (ED_WIDTH - 1)); i++) {
		ed_null(t[i]);
	}

	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

	TRY {
		for (i = 0; i < (1 << (ED_WIDTH - 1)); i ++) {
			ed_new(t[i]);
		}

		ed_new(q);

		ed_copy(t[0], p);
		ed_dbl(q, p);

#if defined(ED_MIXED)
		ed_norm(q, q);
#endif

		/* Create table. */
		for (i = 1; i < (1 << (ED_WIDTH - 1)); i++) {
			ed_add(t[i], t[i - 1], q);
		}

#if defined(ED_MIXED)
		ed_norm_sim(t + 1, (const ed_t *)t + 1, (1 << (ED_WIDTH - 1)) - 1);
#endif

		ed_set_infty(q);
		l = FP_BITS + 1;
		bn_rec_slw(win, &l, k, ED_WIDTH);
		for (i = 0; i < l; i++) {
			if (win[i] == 0) {
				ed_dbl(q, q);
			} else {
				for (j = 0; j < util_bits_dig(win[i]); j++) {
					ed_dbl(q, q);
				}
				ed_add(q, q, t[win[i] >> 1]);
			}
		}

		ed_norm(r, q);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		for (i = 0; i < (1 << (ED_WIDTH - 1)); i++) {
			ed_free(t[i]);
		}
		ed_free(q);
	}
}

#endif

#if ED_MUL == MONTY || !defined(STRIP)

void ed_mul_monty(ed_t r, const ed_t p, const bn_t k) {
	ed_t t[2];

	ed_null(t[0]);
	ed_null(t[1]);

	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

	TRY {
		ed_new(t[0]);
		ed_new(t[1]);

		ed_set_infty(t[0]);
		ed_copy(t[1], p);

		for (int i = bn_bits(k) - 1; i >= 0; i--) {
			int j = bn_get_bit(k, i);
#if ED_ADD == PROJC
			dv_swap_cond(t[0]->x, t[1]->x, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y, t[1]->y, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z, t[1]->z, FP_DIGS, j ^ 1);
			ed_add(t[0], t[0], t[1]);
			ed_dbl(t[1], t[1]);
			dv_swap_cond(t[0]->x, t[1]->x, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y, t[1]->y, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z, t[1]->z, FP_DIGS, j ^ 1);
#elif ED_ADD == EXTND
			dv_swap_cond(t[0]->x, t[1]->x, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y, t[1]->y, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z, t[1]->z, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->t, t[1]->t, FP_DIGS, j ^ 1);
			ed_add(t[0], t[0], t[1]);
			ed_dbl(t[1], t[1]);
			dv_swap_cond(t[0]->x, t[1]->x, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y, t[1]->y, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z, t[1]->z, FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->t, t[1]->t, FP_DIGS, j ^ 1);
#endif
		}

		ed_norm(r, t[0]);

	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(t[1]);
		ed_free(t[0]);
	}
}

#endif

#if ED_MUL == LWNAF || !defined(STRIP)

void ed_mul_lwnaf(ed_t r, const ed_t p, const bn_t k) {
	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

#if defined(ED_ENDOM)
	if (ed_curve_is_endom()) {
		ed_mul_glv_imp(r, p, k);
		return;
	}
#endif

#if defined(ED_PLAIN) || defined(ED_SUPER)
	ed_mul_naf_imp(r, p, k);
#endif
}

#endif

#if ED_MUL == LWNAF_MIXED || !defined(STRIP)

void ed_mul_lwnaf_mixed(ed_t r, const ed_t p, const bn_t k) {
	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

#if defined(ED_ENDOM)
	if (ed_curve_is_endom()) {
		ed_mul_glv_imp(r, p, k);
		return;
	}
#endif

#if defined(ED_PLAIN) || defined(ED_SUPER)
	ed_mul_naf_mixed_imp(r, p, k);
#endif
}

#endif

#if ED_MUL == LWREG || !defined(STRIP)

void ed_mul_lwreg(ed_t r, const ed_t p, const bn_t k) {
	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

#if defined(ED_ENDOM)
	if (ed_curve_is_endom()) {
		ed_mul_glv_imp(r, p, k);
		return;
	}
#endif

#if defined(ED_PLAIN) || defined(ED_SUPER)
	ed_mul_reg_imp(r, p, k);
#endif
}

#endif

#if ED_MUL == FIXED || !defined(STRIP)
void ed_mul_fixed(ed_t r, const ed_t b, const bn_t k) {
	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

	ed_t pre[4];

	for (int n = 0; n < 4; n++) {
		ed_null(pre[n]);
		ed_new(pre[n]);
	}

	// precomputation
	ed_set_infty(pre[0]);
	ed_copy(pre[1], b);
	ed_dbl(pre[2], b);
	ed_add(pre[3], pre[2], pre[1]);

	int k_bits = bn_bits(k);
	char hightest_bits = bn_get_bit(k, k_bits - 1 + (k_bits % 2)) * 2 + bn_get_bit(k, k_bits - 2 + (k_bits % 2));

	ed_copy(r, pre[hightest_bits]);

	for (int i = ((k_bits - 1) / 2) * 2 ; i > 1 ; i -= 2) {
		int index = (i - 2) / (sizeof(dig_t) * 8);
		int shift = (i - 2) % (sizeof(dig_t) * 8);
		char bits = (k->dp[index] >> shift) & 3;
		ed_dbl_short(r, r);
		ed_dbl(r, r);
		ed_add(r, r, pre[bits]);
	}

	ed_norm(r, r);

	for (int n = 0; n < 4; n++) {
		ed_free(pre[n]);
	}
}

#endif

void ed_mul_gen(ed_t r, const bn_t k) {
	if (bn_is_zero(k)) {
		ed_set_infty(r);
		return;
	}

#ifdef ED_PRECO
	ed_mul_fix(r, ed_curve_get_tab(), k);
#else
	ed_t g;

	ed_null(g);

	TRY {
		ed_new(g);
		ed_curve_get_gen(g);
		ed_mul(r, g, k);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(g);
	}
#endif
}

void ed_mul_dig(ed_t r, const ed_t p, dig_t k) {
	int i, l;
	ed_t t;

	ed_null(t);

	if (k == 0) {
		ed_set_infty(r);
		return;
	}

	TRY {
		ed_new(t);

		l = util_bits_dig(k);

		ed_copy(t, p);

		for (i = l - 2; i >= 0; i--) {
			ed_dbl(t, t);
			if (k & ((dig_t)1 << i)) {
				ed_add(t, t, p);
			}
		}

		ed_norm(r, t);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ed_free(t);
	}
}
