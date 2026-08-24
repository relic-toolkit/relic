/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of the computation of the class number for an imaginary
 * quadratic order.
 *
 * @ingroup qf
 */

#include "relic_core.h"

/** Constant to approximate ceil(2^32 * ln2/\pi). */
#define QF_CLASS_STR "947622687"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void qf_class(bn_t bound, const bn_t dsc) {
    bn_t t, c;
    size_t b;

    bn_null(t);
	bn_null(c);

    RLC_TRY {
        bn_new(t);
		bn_new(c);

        bn_abs(t, dsc);
        b = bn_bits(t);                       /* ln|\Delta| < b * ln2 */
        bn_srt(t, t);                         /* floor(sqrt(|\Delta|)) */
        bn_add_dig(t, t, 1);                  /* strictly > sqrt(|\Delta|) */
        bn_mul_dig(t, t, (dig_t)b);

        bn_read_str(c, QF_CLASS_STR, sizeof(QF_CLASS_STR), 10);
        bn_mul(t, t, c);
        bn_rsh(t, t, 32);
        bn_add_dig(bound, t, 1);                  /* compensate truncation */
    } RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
		bn_free(c);
	}
}