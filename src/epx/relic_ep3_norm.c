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
 * Implementation of point normalization on prime elliptic curves over a cubic
 * extension field.
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
 * @param inv		- the flag to indicate if z is already inverted.
 */
static void ep3_norm_imp(ep3_t r, const ep3_t p, int inv) {
	if (p->coord != BASIC) {
		fp3_t t;

		fp3_null(t);

		RLC_TRY {
			fp3_new(t);

			if (inv) {
				fp3_copy(r->z, p->z);
			} else {
				fp3_inv(r->z, p->z);
			}

			switch (p->coord) {
				case PROJC:
					fp3_mul(r->x, p->x, r->z);
					fp3_mul(r->y, p->y, r->z);
					break;
				case JACOB:
					fp3_sqr(t, r->z);
					fp3_mul(r->x, p->x, t);
					fp3_mul(t, t, r->z);
					fp3_mul(r->y, p->y, t);
					break;
				default:
					ep3_copy(r, p);
					break;
			}
			fp3_set_dig(r->z, 1);
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp3_free(t);
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
		/* If the point is represented in affine coordinates, just copy it. */
		ep3_copy(r, p);
		return;
	}
#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)
	ep3_norm_imp(r, p, 0);
#endif /* EP_ADD == PROJC */
}

void ep3_norm_sim(ep3_t *r, const ep3_t *t, int n) {
	int i;
	fp3_t* a = RLC_ALLOCA(fp3_t, n);

	RLC_TRY {
		if (a == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < n; i++) {
			fp3_null(a[i]);
			fp3_new(a[i]);
			fp3_copy(a[i], t[i]->z);
		}

		fp3_inv_sim(a, (const fp3_t *)a, n);

		for (i = 0; i < n; i++) {
			fp3_copy(r[i]->x, t[i]->x);
			fp3_copy(r[i]->y, t[i]->y);
			if (!ep3_is_infty(t[i])) {
				fp3_copy(r[i]->z, a[i]);
			}
		}
#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)
		for (i = 0; i < n; i++) {
			ep3_norm_imp(r[i], r[i], 1);
		}
#endif /* EP_ADD == PROJC */
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
