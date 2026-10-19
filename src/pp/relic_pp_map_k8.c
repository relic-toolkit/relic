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
 * degree 8.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp_tmpl.h"
#include "relic_pp.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

TMPL_PP_MIL(8, ep2);

TMPL_PP_MIL_LIT(8, ep2);

TMPL_PP_LIN(8, fp2);

/**
 * Hooks of the pairing with a fixed argument: the loop runs over the
 * parameter itself, and there are no final lines.
 */
/** @{ */
#define TMPL_PP_PAR_8(A)			/* No change of the parameter. */
#define TMPL_PP_PRE_FIN_8(T, Y, J, L, R, Q, E)	/* No final lines. */
#define TMPL_PP_FIX_FIN_8(R, L, T, J, P, D, G)	/* No final lines. */
/** @} */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(8, ep2, fp2);

TMPL_PP_ADD_PROJC4(8, ep2, fp2);

TMPL_PP_ADD_LAZYR4(8, ep2, fp2, dv2);

TMPL_PP_ADD_LIT(8, ep2, fp2);

TMPL_PP_DBL_BASIC(8, ep2, fp2);

TMPL_PP_DBL_PROJC4(8, ep2, fp2);

TMPL_PP_DBL_LIT4(8, ep2, fp2);

TMPL_PP_NORM(8, ep2, fp2);

TMPL_PP_MAP_TATEP(8, ep2);

TMPL_PP_MAP_SIM_TATEP(8, ep2);

TMPL_PP_MAP_WEILP(8, ep2);

TMPL_PP_MAP_SIM_WEILP(8, ep2);

TMPL_PP_MAP_OATEP(8, ep2, EP_CP8);

TMPL_PP_MAP_SIM_OATEP(8, ep2, EP_CP8);

TMPL_PP_MAP_PRE(8, ep2, fp2);

TMPL_PP_MAP_FIX(8, fp2);

TMPL_PP_MAP_SIM_FIX(8, ep2, fp2);
