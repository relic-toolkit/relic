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
 * Implementation of the low-level inversion functions.
 *
 * @ingroup fp
 */

#include <gmp.h>

#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

void _fp_sqrm_low(dig_t *tmp, const dig_t *f1, dig_t *out);
void _fp_mulm_low(dig_t *tmp, const dig_t *f1, dig_t *out, const dig_t *f2);

static void fsquare_times(dig_t *o, const dig_t *inp, dig_t *tmp, uint32_t n)
{
  _fp_sqrm_low(tmp, inp, o);
  for (uint32_t i = (uint32_t)0U; i < n - (uint32_t)1U; i++) {
    _fp_sqrm_low(tmp, o, o);
  }
}

static void _fp_invm_low(uint64_t *o, const uint64_t *i, uint64_t *tmp) {
  uint64_t t1[16U] = { 0U };
  uint64_t *a1 = t1;
  uint64_t *b1 = t1 + (uint32_t)4U;
  uint64_t *t010 = t1 + (uint32_t)12U;
  uint64_t *tmp10 = tmp;
  fsquare_times(a1, i, tmp10, (uint32_t)1U);
  fsquare_times(t010, a1, tmp10, (uint32_t)2U);
  _fp_mulm_low(tmp, t010, b1, i);
  _fp_mulm_low(tmp, b1, a1, a1);
  fsquare_times(t010, a1, tmp10, (uint32_t)1U);
  _fp_mulm_low(tmp, t010, b1, b1);
  fsquare_times(t010, b1, tmp10, (uint32_t)5U);
  _fp_mulm_low(tmp, t010, b1, b1);
  uint64_t *b10 = t1 + (uint32_t)4U;
  uint64_t *c10 = t1 + (uint32_t)8U;
  uint64_t *t011 = t1 + (uint32_t)12U;
  uint64_t *tmp11 = tmp;
  fsquare_times(t011, b10, tmp11, (uint32_t)10U);
  _fp_mulm_low(tmp, t011, c10, b10);
  fsquare_times(t011, c10, tmp11, (uint32_t)20U);
  _fp_mulm_low(tmp, t011, t011, c10);
  fsquare_times(t011, t011, tmp11, (uint32_t)10U);
  _fp_mulm_low(tmp, t011, b10, b10);
  fsquare_times(t011, b10, tmp11, (uint32_t)50U);
  _fp_mulm_low(tmp, t011, c10, b10);
  uint64_t *b11 = t1 + (uint32_t)4U;
  uint64_t *c1 = t1 + (uint32_t)8U;
  uint64_t *t01 = t1 + (uint32_t)12U;
  uint64_t *tmp1 = tmp;
  fsquare_times(t01, c1, tmp1, (uint32_t)100U);
  _fp_mulm_low(tmp, t01, t01, c1);
  fsquare_times(t01, t01, tmp1, (uint32_t)50U);
  _fp_mulm_low(tmp, t01, t01, b11);
  fsquare_times(t01, t01, tmp1, (uint32_t)5U);
  uint64_t *a = t1;
  uint64_t *t0 = t1 + (uint32_t)12U;
  _fp_mulm_low(tmp, t0, o, a);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_invm_low(dig_t *c, const dig_t *a) {
	rlc_align dig_t t[2 * RLC_FP_DIGS];
	_fp_invm_low(c, a, t);
}
