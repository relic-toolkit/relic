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
 * Implementation of utilities for prime elliptic curves over quadratic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int ep8_cmp(const ep8_t p, const ep8_t q) {
    ep8_t r, s;
    int result = RLC_NE;

	if (ep8_is_infty(p) && ep8_is_infty(q)) {
		return RLC_EQ;
	}

    ep8_null(r);
    ep8_null(s);

    RLC_TRY {
        ep8_new(r);
        ep8_new(s);

        if ((p->coord != BASIC) && (q->coord != BASIC)) {
            /* If the two points are not normalized, it is faster to compare
             * x1 * z2^2 == x2 * z1^2 and y1 * z2^3 == y2 * z1^3. */
            fp8_sqr(r->z, p->z);
            fp8_sqr(s->z, q->z);
            fp8_mul(r->x, p->x, s->z);
            fp8_mul(s->x, q->x, r->z);
            fp8_mul(r->z, r->z, p->z);
            fp8_mul(s->z, s->z, q->z);
            fp8_mul(r->y, p->y, s->z);
            fp8_mul(s->y, q->y, r->z);
        } else {
			ep8_norm(r, p);
            ep8_norm(s, q);
        }

        if ((fp8_cmp(r->x, s->x) == RLC_EQ) &&
				(fp8_cmp(r->y, s->y) == RLC_EQ)) {
            result = RLC_EQ;
        }
    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        ep8_free(r);
        ep8_free(s);
    }

    return result;
}
