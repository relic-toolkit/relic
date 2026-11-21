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

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/**
 * Default library context.
 */
#if RLC_MULTI
static rlc_thread ctx_t first_ctx;
#else
static ctx_t first_ctx;
#endif

#if defined(RLC_MULTI)
/*
 * Initializer function to call for every thread's context
 */
void (*core_thread_initializer)(void* init_ptr) = NULL;
void* core_init_ptr = NULL;
#endif

#if RLC_MULTI
rlc_thread ctx_t *core_ctx = NULL;
#else
ctx_t *core_ctx = NULL;
#endif

int core_init(void) {
	if (core_ctx == NULL) {
		core_ctx = &(first_ctx);
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
void core_par_enter(core_par_t *s, const ctx_t *ctx) {
	ctx_t *own = &first_ctx;

	s->ctx = core_ctx;
	s->code = own->code;
	s->number = own->number;
	s->depth = own->depth;
	s->pending = own->pending;
	s->quiet = own->quiet;
	own->code = RLC_OK;
	own->number = 0;
	own->depth = 0;
	own->pending = 0;
	/* Other threads read the given context, so only write it when this
	 * thread has a context of its own. */
	if (own != ctx) {
		own->quiet = ctx->quiet;
#if RLC_ARCH == RLC_X86 || RLC_ARCH == RLC_X64 || RLC_ARCH == RLC_A64
		own->lzcnt_ptr = ctx->lzcnt_ptr;
		own->tzcnt_ptr = ctx->tzcnt_ptr;
#endif
	}
	core_ctx = own;
}

err_t core_par_leave(const core_par_t *s) {
	ctx_t *own = &first_ctx;
	err_t e = (own->code == RLC_OK ? 0 : own->number);

	/* An error can be recorded without a number, so report it anyway. */
	if (own->code != RLC_OK && e == 0) {
		e = ERR_CAUGHT;
	}
	own->code = s->code;
	own->number = s->number;
	own->depth = s->depth;
	own->pending = s->pending;
	own->quiet = s->quiet;
	core_ctx = s->ctx;
	return e;
}
#endif
