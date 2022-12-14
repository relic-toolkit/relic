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
 * Implementation of architecture-dependent routines.
 *
 * @ingroup arch
 */

#include <stdio.h>

#include "relic_types.h"
#include "relic_arch.h"
#include "relic_core.h"

#include "lzcnt.inc"

/**
 * Renames the inline assembly macro to a prettier name.
 */
#define asm					__asm__ volatile

#if TIMER == CYCLE
#if OPSYS == MACOSX
/*
 * Adapted from work by D. Lemire, Duc Tri Nguyen (CERG GMU), Dougall Johnson
 * https://gist.github.com/dougallj/5bafb113492047c865c0c8cfbc930155
 */
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>

#define KPERF_LIST															\
	/*  ret, name, params */												\
	F(int, kpc_get_counting, void)											\
	F(int, kpc_force_all_ctrs_set, int)										\
	F(int, kpc_set_counting, uint32_t)										\
	F(int, kpc_set_thread_counting, uint32_t)								\
	F(int, kpc_set_config, uint32_t, void *)								\
	F(int, kpc_get_config, uint32_t, void *)								\
	F(int, kpc_set_period, uint32_t, void *)								\
	F(int, kpc_get_period, uint32_t, void *)								\
	F(uint32_t, kpc_get_counter_count, uint32_t)							\
	F(uint32_t, kpc_get_config_count, uint32_t)								\
	F(int, kperf_sample_get, int *)											\
	F(int, kpc_get_thread_counters, int, unsigned int, void *)				\

#define F(ret, name, ...)													\
	typedef ret name##proc(__VA_ARGS__);									\
	static name##proc *name;												\

	KPERF_LIST
#undef F

#define CFGWORD_EL0A32EN_MASK (0x10000)
#define CFGWORD_EL0A64EN_MASK (0x20000)
#define CFGWORD_EL1EN_MASK (0x40000)
#define CFGWORD_EL3EN_MASK (0x80000)
#define CFGWORD_ALLMODES_MASK (0xf0000)

#define CPMU_NONE 0
#define CPMU_CORE_CYCLE 0x02
#define CPMU_INST_A64 0x8c
#define CPMU_INST_BRANCH 0x8d
#define CPMU_SYNC_DC_LOAD_MISS 0xbf
#define CPMU_SYNC_DC_STORE_MISS 0xc0
#define CPMU_SYNC_DTLB_MISS 0xc1
#define CPMU_SYNC_ST_HIT_YNGR_LD 0xc4
#define CPMU_SYNC_BR_ANY_MISP 0xcb
#define CPMU_FED_IC_MISS_DEM 0xd3
#define CPMU_FED_ITLB_MISS 0xd4

#define KPC_CLASS_FIXED (0)
#define KPC_CLASS_CONFIGURABLE (1)
#define KPC_CLASS_POWER (2)
#define KPC_CLASS_RAWPMU (3)
#define KPC_CLASS_FIXED_MASK (1u << KPC_CLASS_FIXED)
#define KPC_CLASS_CONFIGURABLE_MASK (1u << KPC_CLASS_CONFIGURABLE)
#define KPC_CLASS_POWER_MASK (1u << KPC_CLASS_POWER)
#define KPC_CLASS_RAWPMU_MASK (1u << KPC_CLASS_RAWPMU)

#define COUNTERS_COUNT 10
#define CONFIG_COUNT 8
#define KPC_MASK (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_FIXED_MASK)
static uint64_t g_counters[COUNTERS_COUNT];
static uint64_t g_config[COUNTERS_COUNT];

static void configure_rdtsc() {
	if (kpc_set_config(KPC_MASK, g_config)) {
		printf("kpc_set_config failed\n");
		return;
	}

	if (kpc_force_all_ctrs_set(1)) {
		printf("kpc_force_all_ctrs_set failed\n");
		return;
	}

	if (kpc_set_counting(KPC_MASK)) {
		printf("kpc_set_counting failed\n");
		return;
	}

	if (kpc_set_thread_counting(KPC_MASK)) {
		printf("kpc_set_thread_counting failed\n");
		return;
	}
}

static void init_rdtsc() {
	void *kperf = dlopen(
		"/System/Library/PrivateFrameworks/kperf.framework/Versions/A/kperf",
		RTLD_LAZY);
	if (!kperf) {
		printf("kperf = %p\n", kperf);
		return;
	}

#define F(ret, name, ...)													\
	name = (name##proc *)(dlsym(kperf, #name));								\
	if (!name) {															\
		printf("%s = %p\n", #name, (void *)name);							\
		return;																\
	}																		\

	KPERF_LIST
#undef F

	if (kpc_get_counter_count(KPC_MASK) != COUNTERS_COUNT) {
		printf("wrong fixed counters count\n");
		return;
	}

	if (kpc_get_config_count(KPC_MASK) != CONFIG_COUNT) {
		printf("wrong fixed config count\n");
		return;
	}
	g_config[0] = CPMU_CORE_CYCLE | CFGWORD_EL0A64EN_MASK;
	g_config[3] = CPMU_INST_BRANCH | CFGWORD_EL0A64EN_MASK;
	g_config[4] = CPMU_SYNC_BR_ANY_MISP | CFGWORD_EL0A64EN_MASK;
	g_config[5] = CPMU_INST_A64 | CFGWORD_EL0A64EN_MASK;

	configure_rdtsc();
}

#endif
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void arch_init(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
		core_get()->lzcnt_ptr =
			(has_lzcnt_hard() ? lzcnt64_hard : lzcnt64_soft);
	}

#if TIMER == CYCLE

#if OPSYS == MACOSX
	int test_high_perf_cores = 1;
	if (test_high_perf_cores) {
		pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
	} else {
		pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
	}
	init_rdtsc();
	configure_rdtsc();
#endif

#endif /* TIMER = CYCLE */
}

void arch_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
		core_get()->lzcnt_ptr = NULL;
	}
}


ull_t arch_cycles(void) {
	uint_t value = 0;

#if TIMER == CYCLE

#if OPSYS == MACOSX
	static bool warned = false;
	if (kpc_get_thread_counters(0, COUNTERS_COUNT, g_counters)) {
		if (!warned) {
			printf("kpc_get_thread_counters failed, run as sudo?\n");
			warned = true;
		}
		return 1;
	}
	// g_counters[3 + 2] gives you the number of instructions 'decoded'
	// whereas g_counters[1] might give you the number of instructions 'retired'.
	// return performance_counters{g_counters[0 + 2], g_counters[3 + 2],
    //                          g_counters[4 + 2], g_counters[5 + 2]};

	value = g_counters[0 + 2];

#endif

#endif /* TIMER = CYCLE */

	return value;
}

uint_t arch_lzcnt(dig_t x) {
	return core_get()->lzcnt_ptr((ull_t)x) - (8 * sizeof(ull_t) - WSIZE);
}
