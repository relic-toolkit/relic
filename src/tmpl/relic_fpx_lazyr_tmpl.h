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
 * Templates for formulas with lazy reduction over extension fields, which
 * extend those over the prime field.
 *
 * @ingroup tmpl
 */

#ifndef RLC_FPX_LAZYR_TMPL_H
#define RLC_FPX_LAZYR_TMPL_H

#include "relic_core.h"
#include "relic_fpx_low.h"
#include "relic_fp_lazyr_tmpl.h"
#include "relic_fpx_dv_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Operations on unreduced elements of the extension fields, as for the prime
 * field.
 */
/** @{ */
#define TMPL_LAZYR_MULN_fp2(C, A, B)	fp2_muln_low(C, A, B)
#define TMPL_LAZYR_SQRN_fp2(C, A)	fp2_sqrn_low(C, A)
#define TMPL_LAZYR_ADDC_fp2(C, A, B)	fp2_addc_low(C, A, B)
#define TMPL_LAZYR_SUBC_fp2(C, A, B)	fp2_subc_low(C, A, B)
#define TMPL_LAZYR_RDCN_fp2(C, A)	fp2_rdcn_low(C, A)
#define TMPL_LAZYR_RDCV_fp2(C, A, N)	fp2_rdcv_low(C, A, N)

#define TMPL_LAZYR_MULN_fp3(C, A, B)	fp3_muln_low(C, A, B)
#define TMPL_LAZYR_SQRN_fp3(C, A)	fp3_sqrn_low(C, A)
#define TMPL_LAZYR_ADDC_fp3(C, A, B)	fp3_addc_low(C, A, B)
#define TMPL_LAZYR_SUBC_fp3(C, A, B)	fp3_subc_low(C, A, B)
#define TMPL_LAZYR_RDCN_fp3(C, A)	fp3_rdcn_low(C, A)
#define TMPL_LAZYR_RDCV_fp3(C, A, N)	fp3_rdcv_low(C, A, N)

#define TMPL_LAZYR_MULN_fp4(C, A, B)	fp4_mul_unr(C, A, B)
#define TMPL_LAZYR_SQRN_fp4(C, A)	fp4_sqr_unr(C, A)
#define TMPL_LAZYR_ADDC_fp4(C, A, B)	TMPL_DV_ADDC(fp2, dv2, 2, C, A, B)
#define TMPL_LAZYR_SUBC_fp4(C, A, B)	TMPL_DV_SUBC(fp2, dv2, 2, C, A, B)
#define TMPL_LAZYR_RDCN_fp4(C, A)	TMPL_DV_RDCN(fp2, dv2, 2, C, A)
#define TMPL_LAZYR_RDCV_fp4(C, A, N)	TMPL_DV_RDCN(fp2, dv2, 2 * (N), C, A)

#define TMPL_LAZYR_MULN_fp8(C, A, B)	fp8_mul_unr(C, A, B)
#define TMPL_LAZYR_SQRN_fp8(C, A)	fp8_sqr_unr(C, A)
#define TMPL_LAZYR_ADDC_fp8(C, A, B)	TMPL_DV_ADDC(fp2, dv2, 4, C, A, B)
#define TMPL_LAZYR_SUBC_fp8(C, A, B)	TMPL_DV_SUBC(fp2, dv2, 4, C, A, B)
#define TMPL_LAZYR_RDCN_fp8(C, A)	TMPL_DV_RDCN(fp2, dv2, 4, C, A)
#define TMPL_LAZYR_RDCV_fp8(C, A, N)	TMPL_DV_RDCN(fp2, dv2, 4 * (N), C, A)

#define TMPL_LAZYR_MULN_fp9(C, A, B)	fp9_mul_unr(C, A, B)
#define TMPL_LAZYR_SQRN_fp9(C, A)	fp9_sqr_unr(C, A)
#define TMPL_LAZYR_ADDC_fp9(C, A, B)	TMPL_DV_ADDC(fp3, dv3, 3, C, A, B)
#define TMPL_LAZYR_SUBC_fp9(C, A, B)	TMPL_DV_SUBC(fp3, dv3, 3, C, A, B)
#define TMPL_LAZYR_RDCN_fp9(C, A)	TMPL_DV_RDCN(fp3, dv3, 3, C, A)
#define TMPL_LAZYR_RDCV_fp9(C, A, N)	TMPL_DV_RDCN(fp3, dv3, 3 * (N), C, A)
/** @} */

#endif /* !RLC_FPX_LAZYR_TMPL_H */
