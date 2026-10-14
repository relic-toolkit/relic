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
 * Implementation of the modular Lagrante interpolation.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_lag(bn_t *c, const bn_t *a, const bn_t b, size_t n) {
    size_t i, j;
	bn_t *t = NULL;

    if (n == 0) {
        /* The empty product is the constant polynomial 1. */
        bn_set_dig(c[0], 1);
        return;
    }

	/* Allocate after the early return, so that it does not leak. */
	t = RLC_ALLOCA(bn_t, n + 1);
	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	for (i = 0; i <= n; i++) {
		bn_null(t[i]);
	}

	RLC_TRY {
		for (i = 0; i <= n; i++) {
			bn_new(t[i]);
		}

        for (i = 0; i < n; i++) {
            bn_zero(t[0]);
            if (i == 0) {
		        bn_set_dig(t[1], 1);
                bn_sub(c[0], b, a[i]);
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

void bn_lag_pre(bn_t *w, const bn_t *a, const bn_t b, size_t n) {
	bn_t t;
	int valid = 1;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		for (size_t j = 0; j < n; j++) {
			bn_set_dig(w[j], 1);
			for (size_t m = 0; m < n; m++) {
				if (m != j) {
					bn_sub(t, a[j], a[m]);
					bn_mod(t, t, b);
					bn_mul(w[j], w[j], t);
					bn_mod(w[j], w[j], b);
				}
			}
			valid &= !bn_is_zero(w[j]);
		}
		if (!valid) {
			RLC_THROW(ERR_NO_VALID);
		} else if (n > 0) {
			bn_mod_inv_sim(w, (const bn_t *)w, b, n);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

void bn_lag_fix(bn_t *c, const bn_t x, const bn_t *a, const bn_t *w,
		const bn_t b, size_t n) {
	bn_t l;
	size_t j, k = n;

	bn_null(l);

	RLC_TRY {
		bn_new(l);

		/* With L(x) = \prod_m (x - a_m), compute c_j = L(x) w_j / (x - a_j). */
		bn_set_dig(l, 1);
		for (j = 0; j < n; j++) {
			bn_sub(c[j], x, a[j]);
			bn_mod(c[j], c[j], b);
			if (bn_is_zero(c[j])) {
				k = j;
			}
			bn_mul(l, l, c[j]);
			bn_mod(l, l, b);
		}
		if (k < n) {
			/* The point x is one of the abscissas. */
			for (j = 0; j < n; j++) {
				bn_set_dig(c[j], j == k);
			}
		} else if (n > 0) {
			bn_mod_inv_sim(c, (const bn_t *)c, b, n);
			for (j = 0; j < n; j++) {
				bn_mul(c[j], c[j], w[j]);
				bn_mod(c[j], c[j], b);
				bn_mul(c[j], c[j], l);
				bn_mod(c[j], c[j], b);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(l);
	}
}

void bn_evl(bn_t c, const bn_t *a, const bn_t x, const bn_t b, size_t n) {
    bn_zero(c);
    for (int j = n - 1; j >= 0; j--) {
        bn_mul(c, c, x);
        bn_mod(c, c, b);
        bn_add(c, c, a[j]);
        bn_mod(c, c, b);
    }
}
