/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2013 RELIC Authors
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
 * Implementation of error-handling routines.
 *
 * @ingroup relic
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "relic_core.h"
#include "relic_conf.h"
#include "relic_err.h"

#if defined(RLC_VERBS) && RLC_OPSYS == RLC_LINUX && HAVE_EXECINFO_H
#include <execinfo.h>
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#ifdef RLC_CHECK

void err_simple_msg(int error) {
	if (error != ERR_CAUGHT && !core_get()->quiet) {
		fprintf(stderr, "\nERROR: %s.\n", core_get()->reason[error]);
	}
}

#ifdef RLC_VERBS

void err_full_msg(const char *function, const char *file, int line,
		int error) {
	ctx_t *ctx = core_get();

	if (ctx->quiet) {
		return;
	}

	if (error == ERR_CAUGHT) {
		fprintf(stderr, "\tCAUGHT in %s() at %s,%d.\n", function, file, line);
	} else {
		fprintf(stderr, "\nERROR in %s() at %s,%d: %s.\n", function, file, line,
				ctx->reason[error]);

#if RLC_OPSYS == RLC_LINUX && HAVE_BACKTRACE && HAVE_BACKTRACE_SYMBOLS 
		void *trace[100];
		char **symbols;
		int n;

		/* Print the stack trace. */
		fprintf(stderr, "\tCall stack:\n");
		n = backtrace(trace, 100);
		symbols = backtrace_symbols(trace, n);
		/*
		 * Skip the first entry (err_complete_error) and the two last (this
		 * binary and a libc entry.
		 */
		for (int i = 1; i < n - 2; i++) {
			fprintf(stderr, "\t\t#%d %s\n", i - 1, symbols[i]);
		}
		free(symbols);
#endif
	}
}

#endif /* RLC_VERBS */

void err_get_msg(err_t *e, char **msg) {
	ctx_t *ctx = core_get();
	if (ctx->last == NULL || ctx->last->error == NULL) {
		/* No error was thrown outside of a try-catch block. */
		*e = 0;
		*msg = NULL;
		return;
	}
	*e = *(ctx->last->error);
	*msg = ctx->reason[*e];
	ctx->last = NULL;
}

#endif /* RLC_CHECK */

void err_throw(const char *file, int line) {
	core_get()->code = RLC_ERR;
	if (core_get()->quiet) {
		return;
	}
#if RLC_ARCH == RLC_AVR
	/* The file name is stored in program memory. */
	util_print("ERROR THROWN in %S:%d\n", file, line);
#else
	util_print("ERROR THROWN in %s:%d\n", file, line);
#endif
}

int err_get_code(void) {
	ctx_t *ctx = core_get();
	int r = ctx->code;
	ctx->code = RLC_OK;
#ifdef RLC_CHECK
	/* Forget an error thrown outside of a try-catch block, so that the next
	 * one is reported. */
	if (ctx->last == &(ctx->error)) {
		ctx->last = NULL;
	}
#else
	ctx->pending = 0;
#endif
	return r;
}

void err_set_quiet(int quiet) {
	core_get()->quiet = quiet;
}
