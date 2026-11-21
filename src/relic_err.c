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
/* Private definitions                                                        */
/*============================================================================*/

#if RLC_ARCH == RLC_AVR
#include <avr/pgmspace.h>
/** Keeps the messages in program memory, as AVR has little RAM. */
#define ERR_MEM		PROGMEM
#else
/** Keeps the messages with the other constants. */
#define ERR_MEM
#endif

/** Message of an unknown error. */
static const char msg_unknown[] ERR_MEM = "unknown error";
/** Message of ERR_NO_MEMORY. */
static const char msg_no_memory[] ERR_MEM = "not enough memory";
/** Message of ERR_NO_PRECI. */
static const char msg_no_preci[] ERR_MEM = "insufficient precision";
/** Message of ERR_NO_FILE. */
static const char msg_no_file[] ERR_MEM = "file not found";
/** Message of ERR_NO_READ. */
static const char msg_no_read[] ERR_MEM = "can't read bytes from file";
/** Message of ERR_NO_VALID. */
static const char msg_no_valid[] ERR_MEM = "invalid value passed as input";
/** Message of ERR_NO_BUFFER. */
static const char msg_no_buffer[] ERR_MEM = "insufficient buffer capacity";
/** Message of ERR_NO_FIELD. */
static const char msg_no_field[] ERR_MEM =
		"no finite field supported at this security level";
/** Message of ERR_NO_CURVE. */
static const char msg_no_curve[] ERR_MEM =
		"no curve supported at this security level";
/** Message of ERR_NO_CONFIG. */
static const char msg_no_config[] ERR_MEM = "invalid library configuration";
/** Message of ERR_NO_RAND. */
static const char msg_no_rand[] ERR_MEM =
		"faulty pseudo-random number generator";

/** Messages of the errors, kept out of the context so that they are shared. */
static const char *const err_msgs[ERR_MAX] ERR_MEM = {
	[0] = msg_unknown,
	[ERR_CAUGHT] = msg_unknown,
	[ERR_NO_MEMORY] = msg_no_memory,
	[ERR_NO_PRECI] = msg_no_preci,
	[ERR_NO_FILE] = msg_no_file,
	[ERR_NO_READ] = msg_no_read,
	[ERR_NO_VALID] = msg_no_valid,
	[ERR_NO_BUFFER] = msg_no_buffer,
	[ERR_NO_FIELD] = msg_no_field,
	[ERR_NO_CURVE] = msg_no_curve,
	[ERR_NO_CONFIG] = msg_no_config,
	[ERR_NO_RAND] = msg_no_rand
};

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

const char *err_reason(int error) {
	if (error < 0 || error >= ERR_MAX) {
		error = 0;
	}
#if RLC_ARCH == RLC_AVR
	return (const char *)pgm_read_word(&err_msgs[error]);
#else
	return err_msgs[error];
#endif
}

void err_simple_msg(const char *file, int line, int error) {
	if (error == ERR_CAUGHT || core_get()->quiet) {
		return;
	}
#if RLC_ARCH == RLC_AVR
	/* The file name and the message are stored in program memory. */
	util_print("\nERROR in %S:%d: %S.\n", file, line, err_reason(error));
#else
	fprintf(stderr, "\nERROR in %s:%d: %s.\n", file, line, err_reason(error));
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
				err_reason(error));

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
	*msg = (char *)err_reason(*e);
	ctx->number = 0;
}

/* RLC_ALLOCA names the error by its value, as it cannot see the list. */
typedef char err_alloc_fatal[(RLC_ALLOC_FATAL == ERR_NO_MEMORY) ? 1 : -1];

void err_fatal(const char *file, int line, int error) {
	/* Printed even when quiet, as the program stops, and without the context,
	 * which may be missing. */
#if RLC_ARCH == RLC_AVR
	util_print("\nFATAL ERROR in %S:%d: %S.\n", file, line, err_reason(error));
#else
	/* Without the directory, as RLC_FILE, for RLC_ALLOCA, which passes the full
	 * name of the file. */
	const char *base = strrchr(file, '/');
	fprintf(stderr, "\nFATAL ERROR in %s:%d: %s.\n",
			(base ? base + 1 : file), line, err_reason(error));
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
