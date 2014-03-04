/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007, 2008, 2009 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of useful test routines.
 *
 * @version $Id$
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
 * String to print when the test fails.
 */
#define FAIL_STRING	"FAIL"

/**
 * Color of the string printed when the test passes (green).
 */
#define PASS_COLOR		32

/**
 * String to print when the test passes.
 */
#define PASS_STRING	"PASS"

/**
 * Command to set terminal colors.
 */
#define CMD_SET		27

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
	util_print("%s", FAIL_STRING);
	util_print("%c[%dm]\n", CMD_SET, CMD_RESET);
#else
	util_print("[%s]\n", FAIL_STRING);
#endif
}

void test_pass(void) {
#ifdef COLOR
	util_print("[%c[%d;%dm", CMD_SET, CMD_ATTR, PASS_COLOR);
	util_print("%s", PASS_STRING);
	util_print("%c[%dm]\n", CMD_SET, CMD_RESET);
#else
	util_print("[%s]\n", PASS_STRING);
#endif
}