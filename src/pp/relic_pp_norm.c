/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2011 RELIC Authors
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
 * Implementation of point normalization for points used in pairing computation.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_pp_tmpl.h"
#include "relic_pp.h"
#include "relic_conf.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_norm_k1(ep_t r, const ep_t p) {
	ep_norm(r, p);
}

void pp_norm_k2(ep_t r, const ep_t p) {
	ep_norm(r, p);
}

TMPL_PP_NORM(8, ep2, fp2);

TMPL_PP_NORM(12, ep2, fp2);

TMPL_PP_NORM(16, ep4, fp4);

TMPL_PP_NORM(18, ep3, fp3);

TMPL_PP_NORM(24, ep4, fp4);

TMPL_PP_NORM(48, ep8, fp8);

TMPL_PP_NORM(54, ep9, fp9);
