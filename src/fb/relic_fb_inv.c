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
 * Implementation of binary field inversion functions.
 *
 * @ingroup fb
 */

#include "relic_core.h"
#include "relic_fb.h"
#include "relic_fb_low.h"
#include "relic_bn_low.h"
#include "relic_util.h"
#include "relic_rand.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fb_inv_basic(fb_t c, const fb_t a) {
	fb_t t, u, v;
	int i, x;

	fb_null_all(t, u, v);

	if (fb_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		fb_new_all(t, u, v);

#if (FB_POLYN % 2) == 0
		fb_sqr(v, a);
		for (i = 2; i < RLC_FB_BITS; i++) {
			fb_sqr(u, a);
			for (int j = 1; j < i; j++) {
				fb_sqr(u, u);
			}
			fb_mul(v, v, u);
		}
#else
		/* u = a^2, v = 1, x = (m - 1)/2. */
		fb_sqr(u, a);
		fb_set_dig(v, 1);
		x = (RLC_FB_BITS - 1) >> 1;

		while (x != 0) {
			/* u = u * a^{2x}. */
			fb_copy(t, u);
			for (i = 0; i < x; i++) {
				fb_sqr(t, t);
			}
			fb_mul(u, u, t);
			if ((x & 0x01) == 0) {
				x = x >> 1;
			} else {
				/* v = v * u, u = u^2, x = (x - 1)/2. */
				fb_mul(v, v, u);
				fb_sqr(u, u);
				x = (x - 1) >> 1;
			}
		}
#endif
		fb_copy(c, v);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fb_free_all(t, u, v);
	}
}

void fb_inv_binar(fb_t c, const fb_t a) {
	int lu, lv;
	dv_t u, v, g1, g2;

	dv_null_all(u, v, g1, g2);

	if (fb_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		dv_new_all(u, v, g1, g2);

		/* u = a, v = f, g1 = 1, g2 = 0. */
		fb_copy(u, a);
		fb_copy(v, fb_poly_get());
		if (RLC_FB_BITS % RLC_DIG == 0) {
			v[RLC_FB_DIGS] = 1;
		}
		dv_zero(g1, 2 * RLC_FB_DIGS);
		g1[0] = 1;
		dv_zero(g2, 2 * RLC_FB_DIGS);

		lu = RLC_FB_DIGS;
		lv = RLC_FB_DIGS + (RLC_FB_BITS % RLC_DIG == 0);

		/* While (u != 1 && v != 1. */
		while (1) {
			/* While z divides u do. */
			while ((u[0] & 0x01) == 0) {
				/* u = u/z. */
				bn_rsh1_low(u, u, lu);
				/* If z divides g1 then g1 = g1/z; else g1 = (g1 + f)/z. */
				if ((g1[0] & 0x01) == 1) {
					fb_poly_add(g1, g1);
					if (RLC_FB_BITS % RLC_DIG == 0) {
						g1[RLC_FB_DIGS] ^= 1;
					}
				}
				bn_rsh1_low(g1, g1, RLC_FB_DIGS + 1);
			}

			while (u[lu - 1] == 0)
				lu--;
			if (lu == 1 && u[0] == 1)
				break;

			/* While z divides v do. */
			while ((v[0] & 0x01) == 0) {
				/* v = v/z. */
				bn_rsh1_low(v, v, lv);
				/* If z divides g2 then g2 = g2/z; else (g2 = g2 + f)/z. */
				if ((g2[0] & 0x01) == 1) {
					fb_poly_add(g2, g2);
					if (RLC_FB_BITS % RLC_DIG == 0) {
						g2[RLC_FB_DIGS] ^= 1;
					}
				}
				bn_rsh1_low(g2, g2, RLC_FB_DIGS + 1);
			}

			while (v[lv - 1] == 0)
				lv--;
			if (lv == 1 && v[0] == 1)
				break;

			/* If deg(u) > deg(v) then u = u + v, g1 = g1 + g2. */
			if (lu > lv || (lu == lv && u[lu - 1] > v[lv - 1])) {
				fb_addd_low(u, u, v, lv);
				fb_add(g1, g1, g2);
			} else {
				/* Else v = v + u, g2 = g2 + g1. */
				fb_addd_low(v, v, u, lu);
				fb_add(g2, g2, g1);
			}
		}

		/* If u == 1 then return g1; else return g2. */
		if (lu == 1 && u[0] == 1) {
			fb_copy(c, g1);
		} else {
			fb_copy(c, g2);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(u, v, g1, g2);
	}
}

void fb_inv_exgcd(fb_t c, const fb_t a) {
	int j, d, lu, lv, lt, l1, l2, bu, bv;
	dv_t _u, _v, _g1, _g2;
	dig_t *t = NULL, *u = NULL, *v = NULL, *g1 = NULL, *g2 = NULL, carry;

	fb_null_all(_u, _v, _g1, _g2);

	if (fb_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		dv_new_all(_u, _v, _g1, _g2);

		dv_zero(_g1, RLC_FB_DIGS + 1);
		dv_zero(_g2, RLC_FB_DIGS + 1);

		u = _u;
		v = _v;
		g1 = _g1;
		g2 = _g2;

		/* u = a, v = f, g1 = 1, g2 = 0. */
		fb_copy(u, a);
		fb_copy(v, fb_poly_get());
		g1[0] = 1;

		lu = lv = RLC_FB_DIGS;
		l1 = l2 = 1;

		bu = fb_bits(u);
		bv = RLC_FB_BITS + 1;
		j = bu - bv;

		/* While (u != 1). */
		while (1) {
			/* If j < 0 then swap(u, v), swap(g1, g2), j = -j. */
			if (j < 0) {
				t = u;
				u = v;
				v = t;

				lt = lu;
				lu = lv;
				lv = lt;

				t = g1;
				g1 = g2;
				g2 = t;

				lt = l1;
				l1 = l2;
				l2 = lt;

				j = -j;
			}

			RLC_RIP(j, d, j);

			/* u = u + v * z^j. */
			if (j > 0) {
				carry = fb_lsha_low(u + d, v, j, lv);
				u[d + lv] ^= carry;
			} else {
				fb_addd_low(u + d, u + d, v, lv);
			}

			/* g1 = g1 + g2 * z^j. */
			if (j > 0) {
				carry = fb_lsha_low(g1 + d, g2, j, l2);
				l1 = (l2 + d >= l1 ? l2 + d : l1);
				if (carry) {
					g1[d + l2] ^= carry;
					l1 = (l2 + d >= l1 ? l1 + 1 : l1);
				}
			} else {
				fb_addd_low(g1 + d, g1 + d, g2, l2);
				l1 = (l2 + d > l1 ? l2 + d : l1);
			}

			while (u[lu - 1] == 0)
				lu--;
			while (v[lv - 1] == 0)
				lv--;

			if (lu == 1 && u[0] == 1)
				break;

			/* j = deg(u) - deg(v). */
			lt = util_bits_dig(u[lu - 1]) - util_bits_dig(v[lv - 1]);
			if (lv > lu) {
				j = -((lv - lu) << RLC_DIG_LOG) + lt;
			} else {
				j = ((lu - lv) << RLC_DIG_LOG) + lt;
			}
		}
		/* Return g1. */
		fb_copy(c, g1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free_all(_u, _v, _g1, _g2);
	}
}

void fb_inv_itoht(fb_t c, const fb_t a) {
	int i, x, y, len;
	const int *chain = fb_poly_get_chain(&len);
	int *u = NULL;
	fb_t *table = NULL;

	if (fb_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	/* The table needs at least two entries, also for even degrees. */
	if (chain == NULL && (FB_POLYN % 2) != 0) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}
	len = RLC_MAX(len, 1);

	u = RLC_ALLOCA(int, len + 1);
	table = RLC_ALLOCA(fb_t, len + 1);
	if (u == NULL || table == NULL) {
		RLC_FREE(u);
		RLC_FREE(table);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	for (i = 0; i <= len; i++) {
		fb_null(table[i]);
	}

	RLC_TRY {
		for (i = 0; i <= len; i++) {
			fb_new(table[i]);
		}

#if (FB_POLYN % 2) == 0
		fb_sqr(table[0], a);
		for (i = 2; i < RLC_FB_BITS; i++) {
			fb_sqr(table[1], a);
			for (int j = 1; j < i; j++) {
				fb_sqr(table[1], table[1]);
			}
			fb_mul(table[0], table[0], table[1]);
		}
		fb_copy(c, table[0]);
#else
		u[0] = 1;
		u[1] = 2;
		fb_copy(table[0], a);
		fb_sqr(table[1], table[0]);
		fb_mul(table[1], table[1], table[0]);
		for (i = 2; i <= len; i++) {
			x = chain[i - 1] >> 8;
			y = chain[i - 1] - (x << 8);
			if (x == y) {
				u[i] = 2 * u[i - 1];
			} else {
				u[i] = u[x] + u[y];
			}
			if (fb_poly_tab_sqr(y) == NULL) {
				/* The tables are only kept when this method is selected. */
				fb_itr_basic(table[i], table[x], u[y]);
			} else {
				fb_itr(table[i], table[x], u[y], fb_poly_tab_sqr(y));
			}
			fb_mul(table[i], table[i], table[y]);
		}
		fb_sqr(c, table[len]);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i <= len; i++) {
			fb_free(table[i]);
		}
		RLC_FREE(u);
		RLC_FREE(table);
	}
}

void fb_inv_ctaia(fb_t c, const fb_t a) {
	fb_t r, s, t, u, v;
	int i, k, d, r0, d0;

	fb_null_all(r, s, t, u, v);

	if (fb_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	RLC_TRY {
		fb_new_all(r, s, t, u, v);

		fb_copy(r, a);
		fb_copy(t, fb_poly_get());
		fb_copy(s, t);
		fb_set_dig(u, 1);
		fb_zero(v);
		d = -1;

		for (k = 1; k < 2 * RLC_FB_BITS; k++) {
			r0 = r[0] & 1;
			d0 = d >> (8 * sizeof(int) - 1);

			for (i = 0; i < RLC_FB_DIGS; i++) {
				r[i] ^= (s[i] & -r0);
				u[i] ^= (v[i] & -r0);
				s[i] ^= (r[i] & d0);
				v[i] ^= (u[i] & d0);
			}

			d = RLC_SEL(d, -d, r0 & -d0);

			fb_rsh(r, r, 1);

			r0 = u[0] & 1;
			fb_poly_add(t, u);
			for (i = 0; i < RLC_FB_DIGS; i++) {
				u[i] = RLC_SEL(u[i], t[i], r0);
			}
			fb_rsh(u, u, 1);
			d--;
		}

		fb_copy(c, v);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fb_free_all(r, s, t, u, v);
	}
}

#if FB_INV == LOWER

void fb_inv_lower(fb_t c, const fb_t a) {
	if (fb_is_zero(a)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	fb_invn_low(c, a);
}

#endif

void fb_inv_sim(fb_t *c, const fb_t *a, int n) {
	int i;
	fb_t u, *t;

	if (n <= 0) {
		return;
	}

	t = RLC_ALLOCA(fb_t, n);
	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	fb_null(u);

	RLC_TRY {
		for (i = 0; i < n; i++) {
			fb_null(t[i]);
			fb_new(t[i]);
		}
		fb_new(u);

		fb_copy(c[0], a[0]);
		fb_copy(t[0], a[0]);

		for (i = 1; i < n; i++) {
			fb_copy(t[i], a[i]);
			fb_mul(c[i], c[i - 1], a[i]);
		}

		fb_inv(u, c[n - 1]);

		for (i = n - 1; i > 0; i--) {
			fb_mul(c[i], u, c[i - 1]);
			fb_mul(u, u, t[i]);
		}
		fb_copy(c[0], u);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < n; i++) {
			fb_free(t[i]);
		}
		fb_free(u);
		RLC_FREE(t);
	}
}
