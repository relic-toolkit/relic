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
 * Implementation of the low-level prime field multiplication functions.
 *
 * @version $Id: relic_fp_mul_low.c 683 2011-03-10 23:51:23Z dfaranha $
 * @ingroup bn
 */

#include "macro.s"

.text

.global fp_muln_low
.global fp_mulm_low

fp_muln_low:
	push	%r12
	push	%r13
	push	%r14
	push 	%rbx

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MULM_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 0

    popq	%rbx
    popq	%r14
    popq	%r13
    popq	%r12
    ret

fp_mulm_low:
	push	%r12
	push	%r13
	push	%r14
	push 	%rbx
	push 	%rbp

	movq	%rdx, %rbp

	MULM	0(%rsi), 0(%rbp), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MULM_LOW	0(%rsi), 0(%rbp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 1

	popq	%rbp
    popq	%rbx
    popq	%r14
    popq	%r13
    popq	%r12
    ret