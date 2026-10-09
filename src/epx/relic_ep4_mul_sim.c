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
 * Implementation of simultaneous point multiplication on a prime elliptic
 * curve over a quartic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_ENDOM_GLS(ep4, 8);

TMPL_EP_MUL_SIM_PLAIN(ep4);

#endif /* EP_SIM == INTER */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_SIM == BASIC || !defined(STRIP)

TMPL_EP_MUL_SIM_BASIC(ep4);

#endif

#if EP_SIM == TRICK || !defined(STRIP)

TMPL_EP_MUL_SIM_TRICK(ep4);

#endif

#if EP_SIM == INTER || !defined(STRIP)

TMPL_EP_MUL_SIM_INTER(ep4);

#endif

#if EP_SIM == JOINT || !defined(STRIP)

TMPL_EP_MUL_SIM_JOINT(ep4);

#endif

TMPL_EP_MUL_SIM_GEN(ep4);

TMPL_EP_MUL_SIM_DIG(ep4);

TMPL_EP_MUL_SIM_LOT(ep4, 8);
