/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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

#include "relic_fp_low.h"

#define CMP_LT	-1
#define CMP_EQ	0
#define CMP_GT	1

.arch armv7-a

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

.text

.global fp_cmpn_low

/******************************************* FP_CMPN_LOW ********************************************************/

/*
int fp_cmpn_low(dig_t *a, dig_t *b) {
	int i, r;

	a += (FP_DIGS - 1);
	b += (FP_DIGS - 1);

	r = CMP_EQ;
	for (i = 0; i < FP_DIGS; i++, --a, --b) {
		if (*a != *b && r == CMP_EQ) {
			r = (*a > *b ? CMP_GT : CMP_LT);
		}
	}
	return r;
}
*/


fp_cmpn_low:

CMPN_STEP:
	/**** Primeira iteracao ****/
	LDR r2, [r0, #28]	/* r2 = *a */
	LDR r3, [r1, #28]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

	/**** Segunda iteracao ****/
	LDR r2, [r0, #24]	/* r2 = *a */
	LDR r3, [r1, #24]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

	/**** Terceira iteracao ****/
	LDR r2, [r0, #20]	/* r2 = *a */
	LDR r3, [r1, #20]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

	/**** Quarta iteracao ****/
	LDR r2, [r0, #16]	/* r2 = *a */
	LDR r3, [r1, #16]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

	/**** Quinta iteracao ****/
	LDR r2, [r0, #12]	/* r2 = *a */
	LDR r3, [r1, #12]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

	/**** Sexta iteracao ****/
	LDR r2, [r0, #8]	/* r2 = *a */
	LDR r3, [r1, #8]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

	/**** Setima iteracao ****/
	LDR r2, [r0, #4]	/* r2 = *a */
	LDR r3, [r1, #4]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

	/**** Oitava iteracao ****/
	LDR r2, [r0, #0]	/* r2 = *a */
	LDR r3, [r1, #0]	/* r3 = *b */
	CMP r2, r3		/* set condition "HI" if (r2 > r3),*/
				/*            or "LO" if (r2 < r3)*/
	BHI GREATER_THAN
	BLO LESS_THAN

EQUAL:
	MOV r0, #CMP_EQ
	MOV pc, lr

GREATER_THAN:
/*Subtracao*/
	MOV r0, #CMP_GT
	MOV pc, lr		/* return r*/

LESS_THAN:
	MOV r0, #CMP_LT
	MOV pc, lr		/* return r*/
