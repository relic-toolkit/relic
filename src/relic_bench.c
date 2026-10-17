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
 * Implementation of useful benchmark routines.
 *
 * @ingroup relic
 */

#include "relic_conf.h"

#if RLC_TIMER == RLC_PERF
#define _GNU_SOURCE
#include <sys/syscall.h>      /* Definition of SYS_* constants */
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>

#include "relic_core.h"

#if RLC_OPSYS == RLC_DUINO && RLC_TIMER == RLC_HREAL
/*
 * Prototype for Arduino timing function.
 *
 * @return The time in microseconds since the program began running.
 */
uint32_t micros();
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Shared parameter for these timer.
 */
#if RLC_TIMER == RLC_HREAL
#define CLOCK			CLOCK_MONOTONIC
#elif RLC_TIMER == RLC_HPROC
#define CLOCK			CLOCK_PROCESS_CPUTIME_ID
#elif RLC_TIMER == RLC_HTHRD
#define CLOCK			CLOCK_THREAD_CPUTIME_ID
#else
#define CLOCK			NULL
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bench_init(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
#if RLC_TIMER == RLC_PERF
		static struct perf_event_attr attr;
		attr.type = PERF_TYPE_HARDWARE;
		attr.config = PERF_COUNT_HW_CPU_CYCLES;
		attr.exclude_kernel = 1;

		ctx->perf_buf = NULL;
		ctx->perf_fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
		if (ctx->perf_fd != -1) {
			ctx->perf_buf = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ, MAP_SHARED,
				ctx->perf_fd, 0);
		} else {
			RLC_THROW(ERR_NO_FILE);
		}
#endif
	}
}

void bench_reset(void) {
#ifdef RLC_TIMER
	core_get()->total = 0;
#endif
}

void bench_before(void) {
#if RLC_OPSYS == RLC_DUINO && RLC_TIMER == RLC_HREAL
	core_get()->before = micros();
#elif RLC_TIMER == RLC_HREAL || RLC_TIMER == RLC_HPROC || RLC_TIMER == RLC_HTHRD
	clock_gettime(CLOCK, &(core_get()->before));
#elif RLC_TIMER == RLC_ANSI
	core_get()->before = clock();
#elif RLC_TIMER == RLC_CYCLE || RLC_TIMER == RLC_PERF
	core_get()->before = arch_cycles();
#endif
}

void bench_after(void) {
	ctx_t *ctx = core_get();
	long long result;

#if RLC_OPSYS == RLC_DUINO && RLC_TIMER == RLC_HREAL
	core_get()->after = micros();
	result = (ctx->after - ctx->before);
#elif RLC_TIMER == RLC_HREAL || RLC_TIMER == RLC_HPROC || RLC_TIMER == RLC_HTHRD
	clock_gettime(CLOCK, &(ctx->after));
	result = ((long long)ctx->after.tv_sec - ctx->before.tv_sec) * 1000000000;
	result += (ctx->after.tv_nsec - ctx->before.tv_nsec);
#elif RLC_TIMER == RLC_ANSI
	ctx->after = clock();
	result = (long long)(ctx->after - ctx->before) * 1000000 / CLOCKS_PER_SEC;
#elif RLC_TIMER == RLC_CYCLE || RLC_TIMER == RLC_PERF
	ctx->after = arch_cycles();
  	result = (ctx->after - ctx->before);
#endif

#ifdef RLC_TIMER
	ctx->total += result;
#else
	(void)result;
	(void)ctx;
#endif
}

void bench_compute(int benches) {
	ctx_t *ctx = core_get();
#ifdef RLC_TIMER
	ctx->total = ctx->total / benches;
#else
	(void)benches;
	(void)ctx;
#endif /* RLC_TIMER */
}

void bench_print(void) {
	ctx_t *ctx = core_get();

#if RLC_TIMER == RLC_ANSI || (RLC_OPSYS == RLC_DUINO && RLC_TIMER == RLC_HREAL)
	util_print("%lld microsec", ctx->total);
#elif RLC_TIMER == RLC_CYCLE || RLC_TIMER == RLC_PERF
	util_print("%lld cycles", ctx->total);
#else
	util_print("%lld nanosec", ctx->total);
#endif
	if ((long long)ctx->total < 0) {
		util_print(" (overflow)\n");
	} else {
		util_print("\n");
	}
}

ull_t bench_total(void) {
	return core_get()->total;
}

void bench_clean(void) {
#if RLC_TIMER == RLC_PERF
	ctx_t *ctx = core_get();
	if (ctx != NULL && ctx->perf_fd != -1) {
		close(ctx->perf_fd);
		munmap(ctx->perf_buf, sysconf(_SC_PAGESIZE));
		ctx->perf_fd = -1;
		ctx->perf_buf = NULL;
	}
#endif
}
