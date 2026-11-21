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
 * Implementation of the library basic functions.
 *
 * @ingroup relic
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "relic_core.h"
#include "relic_bench.h"
#include "relic_multi.h"
#include "relic_rand.h"
#include "relic_types.h"
#include "relic_err.h"
#include "relic_arch.h"
#include "relic_fp.h"
#include "relic_fb.h"
#include "relic_ep.h"
#include "relic_eb.h"
#include "relic_cp.h"
#include "relic_pp.h"

#if defined(RLC_MULTI) && !defined(_WIN32)
#include <pthread.h>
#endif

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if defined(RLC_MULTI)
/**
 * Context allocated by core_init() for the thread, freed by core_clean(), as
 * a context in thread-local storage would take room in every thread.
 */
static rlc_thread ctx_t *core_own = NULL;

/**
 * Context of the thread for parallel sections, allocated on first use.
 */
static rlc_thread ctx_t *core_par_ctx = NULL;

#if !defined(_WIN32)
/**
 * Flag to clean up the contexts of POSIX threads that exit.
 */
#define CORE_EXIT

/**
 * Key whose destructor runs when a thread with contexts exits.
 */
static pthread_key_t core_key;

/**
 * Flag to create the key once.
 */
static pthread_once_t core_once = PTHREAD_ONCE_INIT;

/**
 * Frees the contexts of a thread that exits without calling core_clean().
 *
 * @param[in] arg			- the value of the key, unused.
 */
static void core_exit(void *arg) {
	(void)arg;
	if (core_own != NULL) {
		core_ctx = core_own;
		core_clean();
	}
	free(core_par_ctx);
	core_par_ctx = NULL;
}

/**
 * Creates the key whose destructor frees the contexts of exiting threads.
 */
static void core_key_new(void) {
	pthread_key_create(&core_key, core_exit);
}

/**
 * Marks the calling thread as having contexts to free when it exits.
 */
static void core_key_set(void) {
	pthread_once(&core_once, core_key_new);
	pthread_setspecific(core_key, (void *)1);
}
#endif

/*
 * Initializer function to call for every thread's context
 */
void (*core_thread_initializer)(void* init_ptr) = NULL;
void* core_init_ptr = NULL;

rlc_thread ctx_t *core_ctx = NULL;
#else
/**
 * Default library context.
 */
static ctx_t first_ctx;

ctx_t *core_ctx = NULL;
#endif

int core_init(void) {
	if (core_ctx == NULL) {
#if defined(RLC_MULTI)
		core_own = (ctx_t *)calloc(1, sizeof(ctx_t));
		if (core_own == NULL) {
			return RLC_ERR;
		}
		core_ctx = core_own;
#ifdef CORE_EXIT
		core_key_set();
#endif
#else
		core_ctx = &(first_ctx);
#endif
	}

	core_ctx->code = RLC_OK;
	core_ctx->number = 0;
	core_ctx->quiet = 0;
	core_ctx->depth = 0;
	core_ctx->pending = 0;

	RLC_TRY {
		arch_init();
		rand_init();

#if RLC_BENCH > 0
		bench_init();
#endif

#ifdef WITH_FP
		fp_prime_init();
#endif
#ifdef WITH_FB
		fb_poly_init();
#endif
#ifdef WITH_EP
		ep_curve_init();
#endif
#ifdef WITH_EB
		eb_curve_init();
#endif
#ifdef WITH_ED
		ed_curve_init();
#endif
#ifdef WITH_PP
		pp_map_init();
#endif
#ifdef WITH_PC
		pc_core_init();
#endif
	} RLC_CATCH_ANY {
		return RLC_ERR;
	}

	/* Failures inside the initialization are recorded in the code. */
	return core_ctx->code;
}

int core_clean(void) {
#ifdef WITH_FP
	fp_prime_clean();
#endif
#ifdef WITH_FB
	fb_poly_clean();
#endif
#ifdef WITH_EP
	ep_curve_clean();
#endif
#ifdef WITH_EB
	eb_curve_clean();
#endif
#ifdef WITH_ED
	ed_curve_clean();
#endif
#ifdef WITH_PP
	pp_map_clean();
#endif
#ifdef WITH_PC
	pc_core_clean();
#endif

#if RLC_BENCH > 0
		bench_clean();
#endif

	arch_clean();
	rand_clean();

	if (core_ctx != NULL) {
		int result = core_ctx->code;
#if defined(RLC_MULTI)
		/* Only free the context allocated by core_init(), not one set. */
		if (core_ctx == core_own) {
			free(core_own);
			core_own = NULL;
		}
#endif
		core_ctx = NULL;
		return result;
	}
	return RLC_OK;
}

#if defined(RLC_MULTI)
ctx_t *core_get_init(void) {
	if (core_thread_initializer != NULL) {
		core_thread_initializer(core_init_ptr);
	}
	return core_ctx;
}
#endif

void core_set(ctx_t *ctx) {
	core_ctx = ctx;
}

#if defined(RLC_MULTI)
void core_set_thread_initializer(void(*init)(void *init_ptr), void* init_ptr) {
    core_thread_initializer = init;
    core_init_ptr = init_ptr;
}
#endif

#if defined(RLC_MULTI)
ctx_t *core_par_enter(const ctx_t *ctx) {
	ctx_t *prev = core_ctx;

	if (core_par_ctx == NULL) {
		core_par_ctx = (ctx_t *)calloc(1, sizeof(ctx_t));
		if (core_par_ctx == NULL) {
			err_fatal(RLC_FILE, __LINE__, ERR_NO_MEMORY);
		}
#ifdef CORE_EXIT
		core_key_set();
#endif
	}
	/* The section context belongs to this thread, so only reset it. */
	core_par_ctx->code = RLC_OK;
	core_par_ctx->number = 0;
	core_par_ctx->depth = 0;
	core_par_ctx->pending = 0;
	core_par_ctx->quiet = ctx->quiet;
#if RLC_ARCH == RLC_X86 || RLC_ARCH == RLC_X64 || RLC_ARCH == RLC_A64
	core_par_ctx->lzcnt_ptr = ctx->lzcnt_ptr;
	core_par_ctx->tzcnt_ptr = ctx->tzcnt_ptr;
#endif
	core_ctx = core_par_ctx;
	return prev;
}

err_t core_par_leave(ctx_t *prev) {
	err_t e = 0;

	if (core_par_ctx->code != RLC_OK) {
		/* A rethrown error keeps its number, but report one in any case. */
		e = (core_par_ctx->number != 0 ? core_par_ctx->number : ERR_CAUGHT);
	}
	core_ctx = prev;
	return e;
}
#endif
