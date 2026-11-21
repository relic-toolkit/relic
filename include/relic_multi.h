/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * @defgroup relic Core functions
 */

/**
 * @file
 *
 * Multithreading support.
 *
 * @ingroup relic
 */

#ifndef RLC_MULTI_H
#define RLC_MULTI_H

#if defined(RLC_MULTI)
#include <math.h>
#if RLC_MULTI == RLC_OPENMP
#include <omp.h>
#elif RLC_MULTI == RLC_PTHREAD
#include <pthread.h>
#endif /* RLC_OPENMP */
#endif /* RLC_MULTI */

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

#if defined(RLC_MULTI)

/**
 * If multi-threading is enabled, assigns each thread a local copy of the data,
 * with the same storage for OpenMP and POSIX threads.
 */
#if defined(_MSC_VER)
#define rlc_thread 	__declspec(thread)
#else
#define rlc_thread 	__thread
#endif

/**
 * Pointer to the active library context of the thread, declared here so that
 * core_get() can be inlined.
 */
extern rlc_thread ctx_t *core_ctx;

#endif /* RLC_MULTI */

#endif /* !RLC_MULTI_H */
