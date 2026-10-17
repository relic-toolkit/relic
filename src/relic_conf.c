/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of useful configuration routines.
 *
 * @ingroup relic
 */

#include <stdio.h>

#include "relic_core.h"
#include "relic_conf.h"
#include "relic_bn.h"
#include "relic_fp.h"
#include "relic_fb.h"
#include "relic_ep.h"
#include "relic_eb.h"
#include "relic_ed.h"
#include "relic_ec.h"
#include "relic_pc.h"
#include "relic_bench.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Inserts quotation marks in the macro argument.
 */
/** @{ */
#define QUOTE(A)			_QUOTE(A)
#define _QUOTE(A)			#A
/** @} */

/**
 * Names the state of the switches.
 */
/** @{ */
#ifdef RLC_CHECK
#define CONF_CHECK			"on"
#else
#define CONF_CHECK			"off"
#endif
#ifdef RLC_STRIP
#define CONF_STRIP			"on"
#else
#define CONF_STRIP			"off"
#endif
/** @} */

/**
 * Names the chosen architecture.
 */
#if RLC_ARCH == RLC_AVR
#define CONF_ARCH			"AVR"
#elif RLC_ARCH == RLC_MSP
#define CONF_ARCH			"MSP"
#elif RLC_ARCH == RLC_ARM
#define CONF_ARCH			"ARM"
#elif RLC_ARCH == RLC_A64
#define CONF_ARCH			"A64"
#elif RLC_ARCH == RLC_X86
#define CONF_ARCH			"X86"
#elif RLC_ARCH == RLC_X64
#define CONF_ARCH			"X64"
#else
#define CONF_ARCH			"none"
#endif

/**
 * Names the chosen random generator.
 */
#if RLC_RAND == RLC_HASHD
#define CONF_RAND			"HASHD"
#elif RLC_RAND == RLC_UDEV
#define CONF_RAND			"UDEV"
#elif RLC_RAND == RLC_CALL
#define CONF_RAND			"CALL"
#else
#define CONF_RAND			"none"
#endif

/**
 * Names the chosen seeder of the generator.
 */
#if RLC_SEED == RLC_NONE
#define CONF_SEED			"NONE"
#elif RLC_SEED == RLC_RDRND
#define CONF_SEED			"RDRND"
#elif RLC_SEED == RLC_UDEV
#define CONF_SEED			"UDEV"
#elif RLC_SEED == RLC_WCGR
#define CONF_SEED			"WCGR"
#else
#define CONF_SEED			"none"
#endif

/**
 * Names the chosen multithreading API.
 */
#if RLC_MULTI == RLC_OPENMP
#define CONF_MULTI			"OPENMP"
#elif RLC_MULTI == RLC_PTHREAD
#define CONF_MULTI			"PTHREAD"
#else
#define CONF_MULTI			"none"
#endif

/**
 * Names the chosen timer.
 */
#if RLC_TIMER == RLC_HREAL
#define CONF_TIMER			"HREAL"
#elif RLC_TIMER == RLC_HPROC
#define CONF_TIMER			"HPROC"
#elif RLC_TIMER == RLC_HTHRD
#define CONF_TIMER			"HTHRD"
#elif RLC_TIMER == RLC_ANSI
#define CONF_TIMER			"ANSI"
#elif RLC_TIMER == RLC_CYCLE
#define CONF_TIMER			"CYCLE"
#elif RLC_TIMER == RLC_PERF
#define CONF_TIMER			"PERF"
#else
#define CONF_TIMER			"none"
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void conf_print(void) {
#ifndef RLC_QUIET
	util_print("-- RELIC " RLC_VERSION " configuration:\n\n");
	util_print("** Compiler: " RLC_CC "\n");
	util_print("   Flags: " RLC_FLAGS "\n\n");
	util_print("** Architecture: " CONF_ARCH ", %d-bit words\n\n", (int)RLC_WSIZE);
	util_print("** Switches: CHECK " CONF_CHECK ", STRIP " CONF_STRIP
			", multithreading " CONF_MULTI "\n\n");
	util_print("** Random number generator: " CONF_RAND ", seeded by "
			CONF_SEED "\n\n");
	util_print("** Timer: " CONF_TIMER "\n\n");
#if RLC_ALLOC == RLC_DYNAMIC
	util_print("** Allocation mode: DYNAMIC\n\n");
#elif RLC_ALLOC == RLC_AUTO
	util_print("** Allocation mode: AUTO\n\n");
#endif

#if RLC_ARITH == RLC_EASY
	util_print("** Arithmetic backend: easy\n\n");
#elif RLC_ARITH == RLC_GMP
	util_print("** Arithmetic backend: gmp\n\n");
#elif RLC_ARITH == RLC_GMP_SEC
	util_print("** Arithmetic backend: gmp-sec\n\n");
#else
	/* Skip the prefix of the backend name. */
	util_print("** Arithmetic backend: %s\n\n", QUOTE(RLC_ARITH) + 4);
#endif

#ifdef RLC_LABEL
	util_print("** Configured label: " QUOTE(RLC_LABEL) "\n\n");
#endif

#if RLC_BENCH > 1
	util_print("** Benchmarking options:\n");
	util_print("   Number of times: %d\n", (int)(RLC_BENCH * RLC_BENCH));
	util_print("\n");
#endif

#ifdef WITH_BN
	util_print("** Multiple precision module options:\n");
	util_print("   Precision: %d bits, %d words\n", (int)RLC_BN_BITS,
			(int)RLC_BN_DIGS);
	util_print("   Arithmetic method: " BN_METHD "\n\n");
#endif

#ifdef WITH_FP
	util_print("** Prime field module options:\n");
	util_print("   Prime size: %d bits, %d words\n", (int)RLC_FP_BITS,
			(int)RLC_FP_DIGS);
	util_print("   Arithmetic method: " FP_METHD "\n\n");
#endif

#ifdef WITH_FPX
	util_print("** Prime field extension module options:\n");
	util_print("   Arithmetic method: " FPX_METHD "\n\n");
#endif

#ifdef WITH_EP
	util_print("** Prime elliptic curve module options:\n");
	util_print("   Arithmetic method: " EP_METHD "\n\n");
#endif

#ifdef WITH_PP
	util_print("** Bilinear pairing module options:\n");
	util_print("   Arithmetic method: " PP_METHD "\n\n");
#endif

#ifdef WITH_FB
	util_print("** Binary field module options:\n");
	util_print("   Polynomial size: %d bits, %d words\n", (int)RLC_FB_BITS,
			(int)RLC_FB_DIGS);
	util_print("   Arithmetic method: " FB_METHD "\n\n");
#endif

#ifdef WITH_EB
	util_print("** Binary elliptic curve module options:\n");
	util_print("   Arithmetic method: " EB_METHD "\n\n");
#endif

#ifdef WITH_EC
	util_print("** Elliptic Curve Cryptography module options:\n");
	util_print("   Arithmetic method: " EC_METHD "\n\n");
#endif

#ifdef WITH_ED
	util_print("** Edwards Curve Cryptography module options:\n");
	util_print("   Arithmetic method: " ED_METHD "\n\n");
#endif

#ifdef WITH_MD
	util_print("** Hash function module options:\n");
	util_print("   Chosen method: " MD_METHD "\n\n");
#endif

#endif
}
