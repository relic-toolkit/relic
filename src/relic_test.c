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

/**
 * @file
 *
 * Implementation of useful test routines.
 *
 * @ingroup relic
 */

#include "relic_test.h"
#include "relic_util.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Color of the string printed when the test fails (red).
 */
#define FAIL_COLOR		31

/**
 * Color of the string printed when the test passes (green).
 */
#define PASS_COLOR		32

/**
 * Command to set terminal colors.
 */
#define CMD_SET			27

/**
 * Command to reset terminal colors.
 */
#define CMD_RESET		0

/**
 * Print with bright attribute.
 */
#define CMD_ATTR		1

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void test_fail(void) {
#ifdef COLOR
	util_print("[%c[%d;%dm", CMD_SET, CMD_ATTR, FAIL_COLOR);
	util_print("FAIL");
	util_print("%c[%dm]\n", CMD_SET, CMD_RESET);
#else
	util_print("[FAIL]\n");
#endif
}

void test_pass(void) {
#ifdef COLOR
	util_print("[%c[%d;%dm", CMD_SET, CMD_ATTR, PASS_COLOR);
	util_print("PASS");
	util_print("%c[%dm]\n", CMD_SET, CMD_RESET);
#else
	util_print("[PASS]\n");
#endif
}
