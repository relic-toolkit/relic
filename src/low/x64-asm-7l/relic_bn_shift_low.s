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
 * Implementation of the ASM multiple precision bit shifting functions.
 *
 * @ingroup bn
 */

#include "relic_bn_low.h"
#include "macro.s"

.text
.global cdecl(bn_srsh_low)
.text
.global cdecl(bn_srsh_low)

/*
 * Function: bn_srsh_low
 * Inputs: rdi = c, rsi = a, rdx = size = RLC_FP_DIGS + 1, rcx = 0 < bits < 64
 * Output: c = a >> bits (arithmetic), returns the bits shifted out of a[0]
 * in the most significant bits of the digit.
 */
cdecl(bn_srsh_low):
	movq	0(%rsi), %r8
	xorq	%rax, %rax
	shrd	%cl, %r8, %rax
	movq	8(%rsi), %r9
	shrd	%cl, %r9, %r8
	movq	%r8, 0(%rdi)
	movq	16(%rsi), %r10
	shrd	%cl, %r10, %r9
	movq	%r9, 8(%rdi)
	movq	24(%rsi), %r11
	shrd	%cl, %r11, %r10
	movq	%r10, 16(%rdi)
	movq	32(%rsi), %r8
	shrd	%cl, %r8, %r11
	movq	%r11, 24(%rdi)
	movq	40(%rsi), %r9
	shrd	%cl, %r9, %r8
	movq	%r8, 32(%rdi)
	movq	48(%rsi), %r10
	shrd	%cl, %r10, %r9
	movq	%r9, 40(%rdi)
	movq	56(%rsi), %r11
	shrd	%cl, %r11, %r10
	movq	%r10, 48(%rdi)
	sar		%cl, %r11
	movq	%r11, 56(%rdi)
	ret
