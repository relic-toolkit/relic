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

#ifdef _MSC_VER
#undef DOUBLE
#include <Windows.h>
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Color of the string printed when the test fails (red).
 */
#define FAIL_COLOR		31
#define FAIL_COLOR_WIN  12

/**
 * Color of the string printed when the test passes (green).
 */
#define PASS_COLOR		32
#define PASS_COLOR_WIN	10

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


int default_color;
void cache_default_color(void)
{
#ifdef _MSC_VER
    CONSOLE_SCREEN_BUFFER_INFO   csbi;
    HANDLE m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo(m_hConsole, &csbi);
    default_color = (csbi.wAttributes & 255);
#endif
}

void fail_font(void)
{
#ifdef COLOR
#ifdef _MSC_VER
    cache_default_color();
    HANDLE m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(m_hConsole, FAIL_COLOR_WIN);
#else
    util_print("[%c[%d;%dm", CMD_SET, CMD_ATTR, FAIL_COLOR);
#endif
#endif
}

void pass_font(void)
{
#ifdef COLOR
#ifdef _MSC_VER
    cache_default_color();
    HANDLE m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(m_hConsole, PASS_COLOR_WIN);
#else
    util_print("[%c[%d;%dm", CMD_SET, CMD_ATTR, PASS_COLOR);
#endif
#endif
}

void reset_font(void)
{
#ifdef COLOR
#ifdef _MSC_VER
    HANDLE m_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(m_hConsole, default_color);
#else
    util_print("%c[%dm]\n", CMD_SET, CMD_RESET);
#endif
#endif
}



void test_fail(void) {
    
    fail_font();
    util_print("[FAIL]\n");
    reset_font();
}

void test_pass(void) {
    pass_font();
	util_print("[PASS]\n");
    reset_font();
}
