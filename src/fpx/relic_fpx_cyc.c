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
 * Implementation of exponentiation in cyclotomic subgroups of extensions
 * defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_cyc_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_CONV_CYC_QUAD(fp2);

TMPL_FPX_TEST_CYC_QUAD(fp2);

TMPL_EXP_CYC_NAF(fp2, fp2_sqr);

TMPL_EXP_CYC_SIM(fp2, fp2_sqr);

TMPL_FPX_CONV_CYC_QUAD(fp8);

TMPL_FPX_TEST_CYC_QUAD(fp8);

TMPL_EXP_CYC_NAF(fp8, fp8_sqr_cyc);

TMPL_EXP_CYC_SIM(fp8, fp8_sqr_cyc);

TMPL_FPX_CONV_CYC(fp12, 2);

TMPL_FPX_TEST_CYC(fp12, 2);

TMPL_FPX_BACK_CYC_QC(fp12, fp2, fp2_mul_nor);

TMPL_FPX_BACK_CYC_SIM_QC(fp12, fp2, fp2_mul_nor);

TMPL_EXP_CYC(fp12);

TMPL_EXP_CYC_SIM(fp12, fp12_sqr_cyc);

TMPL_EXP_CYC_SPS(fp12);

TMPL_FPX_CONV_CYC_QUAD(fp16);

TMPL_FPX_TEST_CYC_QUAD(fp16);

TMPL_EXP_CYC_NAF(fp16, fp16_sqr_cyc);

TMPL_EXP_CYC_SIM(fp16, fp16_sqr_cyc);

TMPL_FPX_CONV_CYC(fp18, 3);

TMPL_FPX_TEST_CYC(fp18, 3);

TMPL_FPX_BACK_CYC_QC(fp18, fp3, fp3_mul_nor);

TMPL_FPX_BACK_CYC_SIM_QC(fp18, fp3, fp3_mul_nor);

TMPL_EXP_CYC(fp18);

TMPL_EXP_CYC_SIM(fp18, fp18_sqr_cyc);

TMPL_EXP_CYC_SPS(fp18);

TMPL_FPX_CONV_CYC(fp24, 4);

TMPL_FPX_TEST_CYC(fp24, 4);

TMPL_FPX_BACK_CYC_CQ(fp24, fp4, fp4_mul_art);

TMPL_FPX_BACK_CYC_SIM_CQ(fp24, fp4, fp4_mul_art);

TMPL_EXP_CYC(fp24);

TMPL_EXP_CYC_SIM(fp24, fp24_sqr_cyc);

TMPL_EXP_CYC_SPS(fp24);

TMPL_FPX_CONV_CYC(fp48, 8);

TMPL_FPX_TEST_CYC(fp48, 8);

TMPL_FPX_BACK_CYC_QC(fp48, fp8, fp8_mul_art);

TMPL_FPX_BACK_CYC_SIM_QC(fp48, fp8, fp8_mul_art);

TMPL_EXP_CYC(fp48);

TMPL_EXP_CYC_SIM(fp48, fp48_sqr_cyc);

TMPL_EXP_CYC_SPS(fp48);

TMPL_FPX_CONV_CYC(fp54, 9);

TMPL_FPX_TEST_CYC(fp54, 9);

TMPL_FPX_BACK_CYC_CQ(fp54, fp9, fp9_mul_art);

TMPL_FPX_BACK_CYC_SIM_CQ(fp54, fp9, fp9_mul_art);

TMPL_EXP_CYC(fp54);

TMPL_EXP_CYC_SPS(fp54);
