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
 * Implementation of squaring in a 24-degree extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_sqr_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_CUBIC(fp24, fp8, fp8_mul_art, 8);

TMPL_SQR_CYC_CQ(fp24, fp4, fp4_mul_art);

TMPL_SQR_PCK_CQ(fp24, fp4, fp4_mul_art);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_CUBIC(fp24, fp8, dv24, dv8, fp2, dv2, 4, 2,
		fp8_sqr_unr, fp8_mul_unr, 8);

TMPL_FPX_SQR_LAZYR(fp24, dv24, fp2, dv2, 12);

TMPL_SQR_PCK_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr, fp4_mul_art);

TMPL_SQR_CYC_LAZYR_CQ(fp24, fp4, dv4, fp2, dv2, 2, 1, fp4_sqr_unr);

#endif
