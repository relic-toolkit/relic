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

void err_simple_msg(const char *file, int line, int error) {
	if (error == ERR_CAUGHT || core_get()->quiet) {
		return;
	}
#if RLC_ARCH == RLC_AVR
	/* The file name is stored in program memory. */
	util_print("\nERROR in %S:%d: %s.\n", file, line,
			core_get()->reason[error]);
#else
	util_print("\nERROR in %s:%d: %s.\n", file, line,
			core_get()->reason[error]);
#endif
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
	if (ctx->number == 0) {
		/* No error was thrown since the last read. */
		*e = 0;
		*msg = NULL;
		return;
	}
	*e = ctx->number;
	*msg = ctx->reason[*e];
	ctx->number = 0;
}

/* RLC_ALLOCA names the error by its value, as it cannot see the list. */
typedef char err_alloc_fatal[(RLC_ALLOC_FATAL == ERR_NO_MEMORY) ? 1 : -1];

void err_fatal(const char *file, int line, int error) {
	/* Printed even when quiet, as the program stops. */
#if RLC_ARCH == RLC_AVR
	util_print("\nFATAL ERROR in %S:%d: %s.\n", file, line,
			core_get()->reason[error]);
#else
	/* Without the directory, as RLC_FILE, for RLC_ALLOCA, which passes the full
	 * name of the file. */
	const char *base = strrchr(file, '/');
	fprintf(stderr, "\nFATAL ERROR in %s:%d: %s.\n",
			(base ? base + 1 : file), line, core_get()->reason[error]);
#endif
	abort();
}

int err_get_code(void) {
	ctx_t *ctx = core_get();
	int r = ctx->code;
	ctx->code = RLC_OK;
	/* Forget the last error, so that the next one is reported. */
	ctx->number = 0;
	ctx->pending = 0;
	return r;
}

void err_set_quiet(int quiet) {
	core_get()->quiet = quiet;
}
