/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2018 RELIC Authors
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
 * Implementation of the auxiliary memory allocation functions.
 *
 * @ingroup utils
 */

#ifndef RLC_ALLOC_H
#define RLC_ALLOC_H

#include "relic_conf.h"

/**
 * The value of ERR_NO_MEMORY, which this file cannot see, as relic_err.h
 * includes it indirectly; relic_err.c checks that they agree.
 */
#define RLC_ALLOC_FATAL		2

#if RLC_ALLOC == RLC_DYNAMIC

#include <stdlib.h>
#include "relic_label.h"

/* Declared here as well, as relic_err.h includes this file indirectly. */
void err_fatal(const char *file, int line, int error);

/**
 * Allocates n objects of the given size for RLC_ALLOCA with dynamic allocation,
 * and stops with err_fatal() if there is no memory: execution continues past a
 * throw without error checking, and callers would use the missing memory, so
 * running out of memory is fatal.
 *
 * @param[in] n					- the number of objects.
 * @param[in] size				- the size of each object.
 * @param[in] file				- the source file of the allocation.
 * @param[in] line				- the line of the allocation in the file.
 * @return the allocated memory.
 */
static inline void *rlc_alloca_dyn(size_t n, size_t size, const char *file,
		int line) {
	void *p = malloc(n * size);

	if (p == NULL && n * size != 0) {
		err_fatal(file, line, RLC_ALLOC_FATAL);
	}
	return p;
}

#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)

#include <malloc.h>

/*
 * Dynamically allocates an array of "Type" with the specified size on the
 * stack. This memory will be automatically deallocated from the stack when the
 * function frame is returned from.
 * Note: This is the Windows specific implementation.
 *
 * @param[in] T                 - the type of each object.
 * @param[in] S                 - the number of objects to allocate.
 */
#if RLC_ALLOC == RLC_DYNAMIC
#define RLC_ALLOCA(T, S)													\
	(T*) rlc_alloca_dyn((S), sizeof(T), __FILE__, __LINE__)
#else
#define RLC_ALLOCA(T, S)		(T*) _alloca((S) * sizeof(T))
#endif

#else /* _MSC_VER */

#if RLC_ALLOC == RLC_DYNAMIC
#include <stdlib.h>
#else
#include <alloca.h>
#endif

/*
 * Dynamically allocates an array of "Type" with the specified size on the
 * stack. This memory will be automatically deallocated from the stack when the
 * function frame is returned from.
 * Note: This is the POSIX specific implementation.
 *
 * @param[in] T                 - the type of each object.
 * @param[in] S                 - the number of objects to allocate.
 */
#if RLC_ALLOC == RLC_DYNAMIC
#define RLC_ALLOCA(T, S)													\
	(T*) rlc_alloca_dyn((S), sizeof(T), __FILE__, __LINE__)
#elif defined(__GNUC__)
/* The builtin does not depend on the C library providing alloca(), and keeps
 * the alignment of the type, which may exceed that of alloca() with ALIGN. */
#define RLC_ALLOCA(T, S)													\
	(T*) __builtin_alloca_with_align((S) * sizeof(T), 8 * __alignof__(T))
#else
#define RLC_ALLOCA(T, S)		(T*) alloca((S) * sizeof(T))
#endif

#endif

/*
 * Free memory allocated with RLC_ALLOCA.
 *
 * @param[in] A					- the variable to free.
 */
#if RLC_ALLOC == RLC_DYNAMIC
#define RLC_FREE(A)															\
	if (A != NULL) {														\
		free((void *)A);													\
		A = NULL;															\
	}
#else
#define RLC_FREE(A)         	(void)A;
#endif

#endif /* !RLC_ALLOC_H */
