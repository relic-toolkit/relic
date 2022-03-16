/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Implementation of Shamir Secret Sharing.
 *
 * @ingroup mpc
 */

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_mpc.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
int mpc_sss_gen(bn_t *x, bn_t *y, const bn_t secret, const bn_t order,
        size_t k, size_t n) {
    bn_t t, *a = RLC_ALLOCA(bn_t, k);

    if (k < 2 || n < k) {
        return RLC_ERR;
    }

    bn_null(t);

    RLC_TRY {
        if (a == NULL) {
            RLC_THROW(ERR_NO_MEMORY);
        }

        bn_new(t);
        bn_null(a[0]);
        bn_new(a[0]);
        bn_copy(a[0], secret);
        for (int i = 1; i < k; i++) {
            bn_null(a[i]);
            bn_new(a[i]);
            bn_rand_mod(a[i], order);
        }
        for (int i = 0; i < n; i++) {
            bn_set_dig(x[i], i + 1);
            bn_evl(y[i], a, x[i], order, k);
        }
    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        bn_free(t);
        for (int i = 0; i < k; i++) {
            bn_free(a[i]);
        }
        RLC_FREE(a);
    }

    return RLC_OK;
}

int mpc_sss_key(bn_t key, const bn_t *x, const bn_t *y, const bn_t order,
        size_t k) {
    bn_t t;
    bn_t *a = RLC_ALLOCA(bn_t, k);
    bn_t *b = RLC_ALLOCA(bn_t, k);

    if (k < 2) {
        RLC_FREE(a);
        RLC_FREE(b);
        return RLC_ERR;
    }

    bn_null(t);

    RLC_TRY {
        if (a == NULL || b == NULL) {
            RLC_THROW(ERR_NO_MEMORY);
        }

        bn_new(t);
        for (int i = 0; i < k; i++) {
            bn_null(a[i]);
            bn_null(b[i]);
            bn_new(a[i]);
            bn_new(b[i]);
        }

        for (int i = 0; i < k; i++) {
            bn_set_dig(a[i], 1);
            bn_set_dig(b[i], 1);
            for (int m = 0; m < k; m++) {
                if (m != i) {
                    bn_sub(t, x[m], x[i]);
                    bn_mod(t, t, order);
                    bn_mul(a[i], a[i], x[m]);
                    bn_mul(b[i], b[i], t);
                    bn_mod(a[i], a[i], order);
                    bn_mod(b[i], b[i], order);
                }
            }
        }
        bn_mod_inv_sim(b, b, order, k);
        bn_mul(a[0], a[0], b[0]);
        bn_mod(a[0], a[0], order);
        bn_mul(a[0], a[0], y[0]);
        bn_mod(key, a[0], order);
        for (int i = 1; i < k; i++) {
            bn_mul(a[i], a[i], b[i]);
            bn_mod(a[i], a[i], order);
            bn_mul(a[i], a[i], y[i]);
            bn_mod(a[i], a[i], order);
            bn_add(key, key, a[i]);
            bn_mod(key, key, order);
        }
    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        bn_free(t);
        for (int i = 0; i < k; i++) {
            bn_free(a[i]);
            bn_free(b[i]);
        }
        RLC_FREE(a);
        RLC_FREE(b);
    }

    return RLC_OK;
}
