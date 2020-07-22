/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2020 RELIC Authors
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
 * Implementation of AMD64-dependent routines.
 *
 * @ingroup arch
 */

#include <stdio.h>

#include "relic_types.h"
#include "relic_arch.h"

#include "lzcnt.inc"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Function pointer to underlying lznct implementation.
 */
static unsigned int (*lzcnt_ptr)(ull_t);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void arch_init(void) {
	lzcnt_ptr = (has_lzcnt_hard() ? lzcnt64_hard : lzcnt64_soft);
}

void arch_clean(void) {
	lzcnt_ptr = NULL;
}

unsigned int arch_lzcnt(dig_t x) {
	return lzcnt_ptr((ull_t)x) - (8 * sizeof(ull_t) - WSIZE);
}
