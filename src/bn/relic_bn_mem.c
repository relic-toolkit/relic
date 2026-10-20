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
 * Implementation of the multiple precision integer memory management routines.
 *
 * @ingroup bn
 */

#include <errno.h>

#if RLC_ALLOC != RLC_AUTO && RLC_OPSYS == RLC_WINDOWS
#include <malloc.h>
#endif

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_make(bn_t a, size_t digits) {
	/* Allocate at least one digit. */
	digits = RLC_MAX(digits, 1);

#if RLC_ALLOC == RLC_DYNAMIC
	if (digits % RLC_BN_SIZE != 0) {
		/* Pad the number of digits to a multiple of the block. */
		digits += (RLC_BN_SIZE - digits % RLC_BN_SIZE);
	}

	if (a == NULL) {
		return;
	}

	a->dp = NULL;
#if RLC_ALIGN == 1
	a->dp = (dig_t *)malloc(digits * sizeof(dig_t));
#elif RLC_OPSYS == RLC_WINDOWS
	a->dp = _aligned_malloc(digits * sizeof(dig_t), RLC_ALIGN);
#else
	int r = posix_memalign((void **)&a->dp, RLC_ALIGN, digits * sizeof(dig_t));
	if (r != 0) {
		/* The pointer is left undefined when the allocation fails. */
		a->dp = NULL;
		if (r == EINVAL) {
			RLC_THROW(ERR_NO_VALID);
			return;
		}
	}
#endif /* RLC_ALIGN */

	if (a->dp == NULL) {
		/* The caller still owns a, and bn_free() handles the null digits. */
		a->alloc = 0;
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
#else
	/* Verify if the number of digits is sane. */
	if (digits > RLC_BN_SIZE) {
		RLC_THROW(ERR_NO_PRECI);
		return;
	} else {
		digits = RLC_BN_SIZE;
	}
#endif
	if (a != NULL) {
		a->used = 1;
		a->dp[0] = 0;
		a->alloc = digits;
		a->sign = RLC_POS;
	}
}

void bn_clean(bn_t a) {
#if RLC_ALLOC == RLC_DYNAMIC
	if (a != NULL) {
		if (a->dp != NULL) {
#if RLC_OPSYS == RLC_WINDOWS && RLC_ALIGN > 1
			_aligned_free(a->dp);
#else
			free(a->dp);
#endif
			a->dp = NULL;
		}
		a->alloc = 0;
	}
#endif
	if (a != NULL) {
		a->used = 0;
		a->sign = RLC_POS;
	}
}

void bn_grow(bn_t a, size_t digits) {
#if RLC_ALLOC == RLC_DYNAMIC
	dig_t *t = NULL;

	if (a->alloc < digits) {
		size_t pad = (RLC_BN_SIZE * 2) - (digits % RLC_BN_SIZE);
		/* Check overflow. */
        if (digits > SIZE_MAX - pad) {
			RLC_THROW(ERR_NO_MEMORY);
			return;
        }
		/* At least add RLC_BN_SIZE more digits. */
		digits += pad;
#if RLC_ALIGN == 1
		t = (dig_t *)realloc(a->dp, (RLC_DIG / 8) * digits);
#else
		/* The realloc() function does not keep the alignment of the memory
		 * allocated in bn_make(), so allocate, copy and free instead. */
#if RLC_OPSYS == RLC_WINDOWS
		t = _aligned_malloc(digits * sizeof(dig_t), RLC_ALIGN);
#else
		if (posix_memalign((void **)&t, RLC_ALIGN, digits * sizeof(dig_t)) != 0) {
			t = NULL;
		}
#endif
		if (t != NULL && a->dp != NULL) {
			dv_copy(t, a->dp, a->alloc);
#if RLC_OPSYS == RLC_WINDOWS
			_aligned_free(a->dp);
#else
			free(a->dp);
#endif
		}
#endif
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
			return;
		}
		a->dp = t;
		a->alloc = digits;
	}
#elif RLC_ALLOC == RLC_AUTO
	if (digits > RLC_BN_SIZE) {
		RLC_THROW(ERR_NO_PRECI);
		return;
	}
	(void)a;
#endif
}

void bn_trim(bn_t a) {
	while (a->used > 0 && a->dp[a->used - 1] == 0) {
		--(a->used);
	}
	/* Zero can't be negative. */
	if (a->used == 0) {
		a->used = 1;
		a->dp[0] = 0;
		a->sign = RLC_POS;
	}
}
