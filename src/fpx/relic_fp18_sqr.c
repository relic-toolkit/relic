/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of squaring in a octodecic extension of a prime field.
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

TMPL_FPX_SQR_QUAD(fp18, fp9, fp9_mul_art);

TMPL_SQR_CYC_QC(fp18, fp3, fp3_mul_nor);

TMPL_SQR_PCK_QC(fp18, fp3, fp3_mul_nor);

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

TMPL_FPX_SQR_UNR_QUAD(fp18, fp9, dv18, dv9, fp3, dv3, 3, 1,
		fp9_sqr_unr);

TMPL_FPX_SQR_LAZYR(fp18, dv18, fp3, dv3, 6);

TMPL_SQR_PCK_LAZYR_QC(fp18, fp3, dv3, fp3, dv3, 1, 1, fp3_sqrn_low,
		fp3_mul_nor);

TMPL_SQR_CYC_LAZYR_QC(fp18, fp3, dv3, fp3, dv3, 1, 1, fp3_sqrn_low);

#endif
