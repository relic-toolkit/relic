/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of the line functions and pairings for curves with embedding
 * degree 48.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp_tmpl.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

TMPL_PP_MIL(48, ep8);

TMPL_PP_MIL_LIT(48, ep8);

TMPL_PP_LIN(48, fp8);

/**
 * Hooks of the pairing with a fixed argument: the loop runs over the
 * parameter itself, and there are no final lines.
 */
/** @{ */
#define TMPL_PP_PAR_48(A)			/* No change of the parameter. */
#define TMPL_PP_PRE_FIN_48(T, Y, J, L, R, Q, E)	/* No final lines. */
#define TMPL_PP_FIX_FIN_48(R, L, T, J, P, D)		/* No final lines. */
/** @} */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(48, ep8, fp8);

TMPL_PP_ADD_PROJC(48, ep8, fp8);

TMPL_PP_ADD_LAZYR(48, ep8, fp8, dv8);

TMPL_PP_ADD_LIT(48, ep8, fp8);

TMPL_PP_DBL_BASIC(48, ep8, fp8);

TMPL_PP_DBL_PROJC(48, ep8, fp8);

TMPL_PP_DBL_LAZYR(48, ep8, fp8, dv8);

TMPL_PP_DBL_LIT(48, ep8, fp8);

TMPL_PP_NORM(48, ep8, fp8);

TMPL_PP_MAP_TATEP(48, ep8);

TMPL_PP_MAP_SIM_TATEP(48, ep8);

TMPL_PP_MAP_WEILP(48, ep8);

TMPL_PP_MAP_SIM_WEILP(48, ep8);

TMPL_PP_MAP_OATEP(48, ep8, EP_B48);

TMPL_PP_MAP_SIM_OATEP(48, ep8, EP_B48);

TMPL_PP_MAP_PRE(48, ep8, fp8);

TMPL_PP_MAP_FIX(48, fp8);
