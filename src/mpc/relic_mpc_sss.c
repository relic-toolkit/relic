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
    bn_t t, *a = NULL;
    int result = RLC_OK;

    /* The indices 1, ..., n must be distinct and nonzero modulo the order. */
    if (k < 2 || n < k || bn_cmp_dig(order, n) != RLC_GT) {
        return RLC_ERR;
    }

    /* Allocate after the early return, so that it does not leak. */
    a = RLC_ALLOCA(bn_t, k);
    if (a == NULL) {
        RLC_THROW(ERR_NO_MEMORY);
        return RLC_ERR;
    }

    bn_null(t);
    for (size_t i = 0; i < k; i++) {
        bn_null(a[i]);
    }

    RLC_TRY {
        bn_new(t);
        bn_new(a[0]);
        bn_copy(a[0], secret);
        for (size_t i = 1; i < k; i++) {
            bn_new(a[i]);
            bn_rand_mod(a[i], order);
        }
        for (size_t i = 0; i < n; i++) {
            bn_set_dig(x[i], i + 1);
            bn_evl(y[i], a, x[i], order, k);
        }
    } RLC_CATCH_ANY {
        result = RLC_ERR;
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        bn_free(t);
        for (size_t i = 0; i < k; i++) {
            bn_free(a[i]);
        }
        RLC_FREE(a);
    }

    return result;
}

int mpc_sss_key(bn_t key, const bn_t *x, const bn_t *y, const bn_t order,
        size_t k) {
    bn_t t;
    bn_t *a = RLC_ALLOCA(bn_t, k);
    bn_t *b = RLC_ALLOCA(bn_t, k);
    int result = RLC_OK;

    if (k < 2) {
        RLC_FREE(a);
        RLC_FREE(b);
        return RLC_ERR;
    }

    if (a == NULL || b == NULL) {
        RLC_FREE(a);
        RLC_FREE(b);
        RLC_THROW(ERR_NO_MEMORY);
        return RLC_ERR;
    }

    bn_null(t);
    for (size_t i = 0; i < k; i++) {
        bn_null(a[i]);
        bn_null(b[i]);
    }

    RLC_TRY {
        bn_new(t);
        for (size_t i = 0; i < k; i++) {
            bn_new(a[i]);
            bn_new(b[i]);
        }

        for (size_t i = 0; i < k; i++) {
            bn_set_dig(a[i], 1);
            bn_set_dig(b[i], 1);
            for (size_t m = 0; m < k; m++) {
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
        for (size_t i = 0; i < k; i++) {
            if (bn_is_zero(b[i])) {
                /* Two indices are equal modulo the order. */
                result = RLC_ERR;
                RLC_THROW(ERR_NO_VALID);
            }
        }
        if (result == RLC_ERR) {
            bn_zero(key);
        } else {
            bn_mod_inv_sim(b, b, order, k);
            bn_mul(a[0], a[0], b[0]);
            bn_mod(a[0], a[0], order);
            bn_mul(a[0], a[0], y[0]);
            bn_mod(key, a[0], order);
            for (size_t i = 1; i < k; i++) {
                bn_mul(a[i], a[i], b[i]);
                bn_mod(a[i], a[i], order);
                bn_mul(a[i], a[i], y[i]);
                bn_mod(a[i], a[i], order);
                bn_add(key, key, a[i]);
                bn_mod(key, key, order);
            }
        }
    } RLC_CATCH_ANY {
        result = RLC_ERR;
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        bn_free(t);
        for (size_t i = 0; i < k; i++) {
            bn_free(a[i]);
            bn_free(b[i]);
        }
        RLC_FREE(a);
        RLC_FREE(b);
    }

    return result;
}
