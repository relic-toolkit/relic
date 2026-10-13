/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of the low-level prime field shifting functions.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

.text
.global cdecl(fp_rsh1_low)
.global cdecl(fp_lsh1_low)

/*
 * Both functions stream over the limbs with two registers, reading each limb
 * of a before the limb of c at the same position is written, so c may alias a.
 */
cdecl(fp_rsh1_low):
	movq	0(%rsi), %r8
	movq	%r8, %rax
	andq	$1, %rax
	movq	8(%rsi), %r9
	shrdq	$1, %r9, %r8
	movq	%r8, 0(%rdi)
	movq	16(%rsi), %r8
	shrdq	$1, %r8, %r9
	movq	%r9, 8(%rdi)
	movq	24(%rsi), %r9
	shrdq	$1, %r9, %r8
	movq	%r8, 16(%rdi)
	movq	32(%rsi), %r8
	shrdq	$1, %r8, %r9
	movq	%r9, 24(%rdi)
	movq	40(%rsi), %r9
	shrdq	$1, %r9, %r8
	movq	%r8, 32(%rdi)
	movq	48(%rsi), %r8
	shrdq	$1, %r8, %r9
	movq	%r9, 40(%rdi)
	movq	56(%rsi), %r9
	shrdq	$1, %r9, %r8
	movq	%r8, 48(%rdi)
	movq	64(%rsi), %r8
	shrdq	$1, %r8, %r9
	movq	%r9, 56(%rdi)
	shrq	$1, %r8
	movq	%r8, 64(%rdi)
	ret

cdecl(fp_lsh1_low):
	movq	64(%rsi), %r8
	movq	%r8, %rax
	shrq	$63, %rax
	movq	56(%rsi), %r9
	shldq	$1, %r9, %r8
	movq	%r8, 64(%rdi)
	movq	48(%rsi), %r8
	shldq	$1, %r8, %r9
	movq	%r9, 56(%rdi)
	movq	40(%rsi), %r9
	shldq	$1, %r9, %r8
	movq	%r8, 48(%rdi)
	movq	32(%rsi), %r8
	shldq	$1, %r8, %r9
	movq	%r9, 40(%rdi)
	movq	24(%rsi), %r9
	shldq	$1, %r9, %r8
	movq	%r8, 32(%rdi)
	movq	16(%rsi), %r8
	shldq	$1, %r8, %r9
	movq	%r9, 24(%rdi)
	movq	8(%rsi), %r9
	shldq	$1, %r9, %r8
	movq	%r8, 16(%rdi)
	movq	0(%rsi), %r8
	shldq	$1, %r8, %r9
	movq	%r9, 8(%rdi)
	shlq	$1, %r8
	movq	%r8, 0(%rdi)
	ret
