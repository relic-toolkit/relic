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
 * Timing-leakage test of the constant-time functions of the pairing-based
 * cryptography API with dudect, which compares the running times of a fixed
 * secret and of random secrets with Welch's t-test. Inputs are prepared
 * outside the measurements, which only receive an index into them. Each
 * binary measures one target, chosen with -DTARGET=n:
 *   1 g1_mul_sec, secret scalar         2 g2_mul_sec, secret scalar
 *   3 gt_exp_sec, secret exponent       4 g1_map, secret message
 *   5 g2_map, secret message            6 pc_map, secret element of G_1
 *   7 g1_mul, which is variable time, as a positive control
 *
 * Run it as: dudect [mode] [seconds], where mode is "rand" (a fixed random
 * secret, the default), "small" (a fixed short secret: 2^64 + 1, the zero
 * message or the generator), or "null" (both classes use the
 * same fixed random secret, a control for false positives), and seconds
 * bounds the run (600 by default). It exits with 1 if it finds leakage.
 *
 * The test needs dudect.h from https://github.com/oreparaz/dudect, which is
 * in the public domain, at the commit it was checked with, and patched with
 * tools/relic-dudect.patch to count core cycles with rdpmc when compiled with
 * -DDUDECT_RDPMC. Core cycles, unlike rdtsc, do not count frequency changes as
 * time differences; rdpmc needs perf_event_paranoid at most 2. For example:
 *   curl -O https://raw.githubusercontent.com/oreparaz/dudect/dc269651fb2567e46755cfb2a13d3875592968b5/src/dudect.h
 *   patch dudect.h tools/relic-dudect.patch
 *   cmake -B build -DARITH=x64-asm-6l -DFP_PRIME=381 -DFP_QNRES=on \
 *     -DTESTS=0 -DBENCH=0 -DSHLIB=off && cmake --build build -t relic_s
 *   gcc -O2 -DTARGET=3 -DDUDECT_RDPMC -I. -Iinclude -Ibuild/include \
 *     tools/relic-dudect.c build/lib/librelic_s.a -lgmp -lm -o dudect
 *   taskset -c 2 ./dudect small 1200
 * Pin the run to an idle core whose sibling is also idle. Use an assembly
 * backend, as the portable one (ARITH=easy) is not constant time and makes
 * every target that multiplies in the field leak.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "relic.h"

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#ifndef TARGET
#define TARGET 1
#endif

/** Number of inputs per batch of measurements. */
#define NMEAS 1000

/** Length of the secret messages. */
#define MLEN 32


#ifdef DUDECT_RDPMC

#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/** Page of the self-monitoring perf event. */
static struct perf_event_mmap_page *pmc_page = NULL;

/**
 * Opens a core-cycle counter that user space can read with rdpmc.
 *
 * @return 0 if it succeeded, a negative value otherwise.
 */
static int pmc_init(void) {
	struct perf_event_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.exclude_kernel = 1;
	attr.exclude_hv = 1;
	fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	if (fd < 0) {
		return -1;
	}
	pmc_page = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ, MAP_SHARED, fd, 0);
	if (pmc_page == MAP_FAILED || !pmc_page->cap_user_rdpmc ||
			pmc_page->index == 0) {
		return -2;
	}
	return 0;
}

/**
 * Reads the core-cycle counter, called by the patched dudect.h.
 *
 * @return the number of core cycles.
 */
int64_t dut_cycles(void) {
	uint32_t lo, hi;

	__asm__ volatile("lfence\n\trdpmc" : "=a"(lo), "=d"(hi)
			: "c"(pmc_page->index - 1));
	return (int64_t)(((uint64_t)hi << 32) | lo);
}

#endif

/** Fixed and per-input secrets. */
static bn_t fixed, ks[NMEAS], n;
static uint8_t mfix[MLEN], msg[NMEAS][MLEN];
static g1_t pfix, ps[NMEAS];

/** Public inputs and outputs. */
static g1_t p1, r1;
static g2_t p2, r2;
static gt_t pt, rt;

/** Flag to give both classes the same secret. */
static int null = 0;

/**
 * Returns the name of the target.
 *
 * @return the name.
 */
static const char *name(void) {
	switch (TARGET) {
		case 1: return "g1_mul_sec";
		case 2: return "g2_mul_sec";
		case 3: return "gt_exp_sec";
		case 4: return "g1_map";
		case 5: return "g2_map";
		case 6: return "pc_map, secret P";
		default: return "g1_mul (positive control)";
	}
}

uint8_t do_one_computation(uint8_t *data) {
	uint32_t i;

	memcpy(&i, data, sizeof(i));
#if TARGET == 1
	g1_mul_sec(r1, p1, ks[i]);
	return ((uint8_t *)r1->x)[0];
#elif TARGET == 2
	g2_mul_sec(r2, p2, ks[i]);
	return ((uint8_t *)r2->x)[0];
#elif TARGET == 3
	gt_exp_sec(rt, pt, ks[i]);
	return ((uint8_t *)rt)[0];
#elif TARGET == 4
	g1_map(r1, msg[i], MLEN);
	return ((uint8_t *)r1->x)[0];
#elif TARGET == 5
	g2_map(r2, msg[i], MLEN);
	return ((uint8_t *)r2->x)[0];
#elif TARGET == 6
	pc_map(rt, ps[i], p2);
	return ((uint8_t *)rt)[0];
#else
	g1_mul(r1, p1, ks[i]);
	return ((uint8_t *)r1->x)[0];
#endif
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
	for (uint32_t i = 0; i < c->number_measurements; i++) {
		classes[i] = randombit();
		/* Both classes draw a random secret, so that the preparation does not
		 * leave a cache state that depends on the class. */
		bn_rand_mod(ks[i], n);
		rand_bytes(msg[i], MLEN);
		if (classes[i] == 0 || null) {
			bn_copy(ks[i], fixed);
			memcpy(msg[i], mfix, MLEN);
		}
#if TARGET == 6
		g1_rand(ps[i]);
		g1_norm(ps[i], ps[i]);
		if (classes[i] == 0 || null) {
			g1_copy(ps[i], pfix);
		}
#endif
		memcpy(input_data + (size_t)i * c->chunk_size, &i, sizeof(i));
	}
}

int main(int argc, char *argv[]) {
	const char *mode = (argc > 1 ? argv[1] : "rand");
	double limit = (argc > 2 ? atof(argv[2]) : 600);
	dudect_config_t config = { .chunk_size = sizeof(uint32_t),
		.number_measurements = NMEAS };
	dudect_ctx_t ctx;
	dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
	time_t start = time(NULL);

	if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK) {
		core_clean();
		return 2;
	}
#ifdef DUDECT_RDPMC
	if (pmc_init() != 0) {
		printf("rdpmc is not available\n");
		core_clean();
		return 2;
	}
#endif

	bn_null_all(fixed, n);
	g1_null_all(p1, r1, pfix);
	g2_null_all(p2, r2);
	gt_null_all(pt, rt);

	bn_new_all(fixed, n);
	g1_new_all(p1, r1, pfix);
	g2_new_all(p2, r2);
	gt_new_all(pt, rt);
	for (int j = 0; j < NMEAS; j++) {
		bn_null(ks[j]);
		bn_new(ks[j]);
		g1_null(ps[j]);
		g1_new(ps[j]);
	}

	pc_get_ord(n);
	g1_rand(p1);
	g2_rand(p2);
	gt_rand(pt);
	g1_norm(p1, p1);
	g2_norm(p2, p2);

	null = (strcmp(mode, "null") == 0);
	if (strcmp(mode, "small") == 0) {
		bn_set_2b(fixed, 64);
		bn_add_dig(fixed, fixed, 1);
		memset(mfix, 0, MLEN);
		g1_get_gen(pfix);
	} else {
		bn_rand_mod(fixed, n);
		rand_bytes(mfix, MLEN);
		g1_rand(pfix);
	}
	g1_norm(pfix, pfix);

	printf("%s, fixed %s secret, %d-bit prime, %s\n", name(), mode, FP_PRIME,
#ifdef DUDECT_RDPMC
			"core cycles (rdpmc)"
#else
			"reference cycles (rdtsc)"
#endif
			);
	fflush(stdout);

	/* Only some inputs and outputs are used by each target. */
	(void)ps;
	(void)r1;
	(void)r2;
	(void)rt;

	dudect_init(&ctx, &config);
	while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET &&
			difftime(time(NULL), start) < limit) {
		state = dudect_main(&ctx);
		fflush(stdout);
	}
	dudect_free(&ctx);

	core_clean();
	return (state == DUDECT_LEAKAGE_FOUND);
}
