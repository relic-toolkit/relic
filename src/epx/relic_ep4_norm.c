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
 * Implementation of point normalization on prime elliptic curves over a quartic
 * extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_util_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == PROJC || EP_ADD == JACOB || !defined(STRIP)

TMPL_EP_NORM_IMP(ep4, fp4);

#endif /* EP_ADD == PROJC */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_NORM(ep4, fp4);

