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
 * Implementation of point normalization on prime elliptic curves over quadratic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

/**
 * Normalizes a point represented in projective coordinates.
 *
 * @param r			- the result.
 * @param p			- the point to normalize.
 */
static void ep3_norm_imp(ep3_t r, const ep3_t p, int inverted) {
	if (p->coord != BASIC) {
		fp3_t t0, t1;

		fp3_null(t0);
		fp3_null(t1);

		RLC_TRY {

			fp3_new(t0);
			fp3_new(t1);

			if (inverted) {
				fp3_copy(t1, p->z);
			} else {
				fp3_inv(t1, p->z);
			}
			fp3_sqr(t0, t1);
			fp3_mul(r->x, p->x, t0);
			fp3_mul(t0, t0, t1);
			fp3_mul(r->y, p->y, t0);
			fp3_set_dig(r->z, 1);
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp3_free(t0);
			fp3_free(t1);
		}
	}

	r->coord = BASIC;
}

#endif /* EP_ADD == PROJC */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep3_norm(ep3_t r, const ep3_t p) {
	if (ep3_is_infty(p)) {
		ep3_set_infty(r);
		return;
	}

	if (p->coord == BASIC) {
		/* If the point is represented in affine coordinates, we just copy it. */
		ep3_copy(r, p);
	}
#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)
	ep3_norm_imp(r, p, 0);
#endif
}

void ep3_norm_sim(ep3_t *r, const ep3_t *t, int n) {
	int i;
	fp3_t *a = RLC_ALLOCA(fp3_t, n);

	RLC_TRY {
		if (a == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < n; i++) {
			fp3_null(a[i]);
			fp3_new(a[i]);
			fp3_copy(a[i], t[i]->z);
		}

		fp3_inv_sim(a, a, n);

		for (i = 0; i < n; i++) {
			fp3_copy(r[i]->x, t[i]->x);
			fp3_copy(r[i]->y, t[i]->y);
			fp3_copy(r[i]->z, a[i]);
		}
#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)
		for (i = 0; i < n; i++) {
			ep3_norm_imp(r[i], r[i], 1);
		}
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < n; i++) {
			fp3_free(a[i]);
		}
		RLC_FREE(a);
	}
}
