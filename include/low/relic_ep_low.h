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
 * Interface of the low-level prime elliptic curve functions, which a backend
 * may provide for the point operations of scalar multiplication.
 *
 * @ingroup ep
 */

#ifndef RLC_EP_LOW_H
#define RLC_EP_LOW_H

#include "relic_ep.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Doubles a point in projective coordinates on a curve with a = 0, as the
 * template does, for a point not in affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to double, which may alias r.
 */
void ep_dblp_low(ep_t r, const ep_t p);

/**
 * Adds two points in projective coordinates on a curve with a = 0, as the
 * template does, for points not in affine coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point, which may alias r.
 * @param[in] q				- the second point, which may alias r.
 */
void ep_addp_low(ep_t r, const ep_t p, const ep_t q);

/**
 * Adds a point in projective coordinates and a point in affine coordinates on
 * a curve with a = 0, as the template does, for a first point not in affine
 * coordinates.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point, which may alias r.
 * @param[in] q				- the second point, in affine coordinates.
 */
void ep_addm_low(ep_t r, const ep_t p, const ep_t q);

#endif /* !RLC_EP_LOW_H */
