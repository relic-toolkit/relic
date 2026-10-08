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
 * Templates for arithmetic in double precision with elements of extension
 * fields, seen as vectors of components in a base field.
 *
 * @ingroup tmpl
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Adds two double-precision elements made of N components in a base field.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[out] C		- the result.
 * @param[in] A			- the first element.
 * @param[in] E			- the second element.
 */
#define TMPL_DV_ADDC(B, BD, N, C, A, E)										\
	for (int _i = 0; _i < (N); _i++) {										\
		B##_addc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],				\
				((BD##_t *)(E))[_i]);										\
	}

/**
 * Subtracts two double-precision elements made of N components in a base
 * field.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[out] C		- the result.
 * @param[in] A			- the first element.
 * @param[in] E			- the second element.
 */
#define TMPL_DV_SUBC(B, BD, N, C, A, E)										\
	for (int _i = 0; _i < (N); _i++) {										\
		B##_subc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],				\
				((BD##_t *)(E))[_i]);										\
	}

/**
 * Reduces a double-precision element made of N components in a base field.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[out] C		- the result.
 * @param[in] A			- the element to reduce.
 */
#define TMPL_DV_RDCN(B, BD, N, C, A)										\
	for (int _i = 0; _i < (N); _i++) {										\
		B##_rdcn_low(((B##_t *)(C))[_i], ((BD##_t *)(A))[_i]);				\
	}

/**
 * Computes C = A + E * v for double-precision elements made of N components
 * in a base field, where v generates the extension. Multiplying by v moves
 * each component one power of v up, and the top one wraps around times the
 * non-residue. Component p in powers of v is stored at index
 * (p mod Q) * (N / Q) + p / Q, where Q is the number of outer components.
 *
 * @param[in] B			- the base field prefix.
 * @param[in] BD		- the double-precision base field prefix.
 * @param[in] N			- the number of components.
 * @param[in] Q			- the number of outer components.
 * @param[out] C		- the result.
 * @param[in] A			- the first element.
 * @param[in] E			- the second element.
 */
#define TMPL_DV_NADD(B, BD, N, Q, C, A, E)									\
	for (int _p = 0; _p < (N); _p++) {										\
		int _i = (_p % (Q)) * ((N) / (Q)) + _p / (Q);						\
		int _j = (((_p + (N) - 1) % (N)) % (Q)) * ((N) / (Q)) +				\
				((_p + (N) - 1) % (N)) / (Q);								\
		if (_p == 0) {														\
			B##_nord_low(((BD##_t *)(C))[_i], ((BD##_t *)(E))[_j]);			\
			B##_addc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],			\
					((BD##_t *)(C))[_i]);									\
		} else {															\
			B##_addc_low(((BD##_t *)(C))[_i], ((BD##_t *)(A))[_i],			\
					((BD##_t *)(E))[_j]);									\
		}																	\
	}
