/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of the modular Lagrante interpolation.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_lag(bn_t *c, const bn_t *a, const bn_t b, int n) {
    int i, j;
	bn_t *t = RLC_ALLOCA(bn_t, n + 1);

    if (n == 0) {
        bn_zero(c[0]);
        return;
    }

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i <= n; i++) {
			bn_null(t[i]);
			bn_new(t[i]);
		}

        for (i = 0; i < n; i++) {
            bn_zero(t[0]);
            if (i == 0) {
		        bn_set_dig(t[1], 1);
                bn_neg(c[0], a[i]);
                bn_mod(c[0], c[0], b);
            } else {
                for (j = 0; j <= i; j++) {
                    bn_copy(t[j + 1], c[j]);
                }
                for (j = 0; j <= i; j++) {
                    bn_mul(c[j], c[j], a[i]);
                    bn_mod(c[j], c[j], b);
                    bn_sub(c[j], t[j], c[j]);
                    bn_mod(c[j], c[j], b);
                }
            }
            bn_copy(c[i + 1], t[i + 1]);
        }
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i <= n; i++) {
			bn_free(t[i]);
		}
		RLC_FREE(t);
	}
}

void bn_evl(bn_t c, const bn_t *a, const bn_t x, const bn_t b, int n) {
    bn_zero(c);
    for (int j = n - 1; j >= 0; j--) {
        bn_mul(c, c, x);
        bn_mod(c, c, b);
        bn_add(c, c, a[j]);
        bn_mod(c, c, b);
    }
}
