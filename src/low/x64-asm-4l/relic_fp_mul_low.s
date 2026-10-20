/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

.text

.global cdecl(fp_mul1_low)
.global cdecl(fp_muln_low)
.global cdecl(fp_mulm_low)

cdecl(fp_mul1_low):
	push	%r12
	push	%r13
	subq	$8, %rsp

	movq	%rdi, 0(%rsp)
	mulxq	0(%rsi), %r8, %rax
	mulxq	8(%rsi), %r9, %rdi
	addq	%rax, %r9
	mulxq	16(%rsi), %r10, %rax
	adcq	%rdi, %r10
	mulxq	24(%rsi), %r11, %rcx
	adcq	%rax, %r11
	adcq	$0, %rcx

	movq	%r11, %rax
	shrdq	$BARS, %rcx, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	mulxq	p0(%rip), %rax, %rdi
	subq	%rax, %r8
	mulxq	p1(%rip), %rax, %rsi
	sbbq	%rax, %r9
	mulxq	p2(%rip), %rax, %r12
	sbbq	%rax, %r10
	mulxq	p3(%rip), %rax, %r13
	sbbq	%rax, %r11
	sbbq	$0, %rcx

	subq	%rdi, %r9
	sbbq	%rsi, %r10
	sbbq	%r12, %r11
	sbbq	%r13, %rcx

	.rept 2
	movq	%r8, %r12
	subq	p0(%rip), %r12
	movq	%r9, %rdi
	sbbq	p1(%rip), %rdi
	movq	%r10, %rsi
	sbbq	p2(%rip), %rsi
	movq	%r11, %rdx
	sbbq	p3(%rip), %rdx
	movq	%rcx, %rax
	sbbq	$0, %rax
	cmovnc	%r12, %r8
	cmovnc	%rdi, %r9
	cmovnc	%rsi, %r10
	cmovnc	%rdx, %r11
	cmovnc	%rax, %rcx
	.endr
	movq	0(%rsp), %rax

	movq	%r8, 0(%rax)
	movq	%r9, 8(%rax)
	movq	%r10, 16(%rax)
	movq	%r11, 24(%rax)

	addq	$8, %rsp
	pop		%r13
	pop		%r12
	ret

cdecl(fp_muln_low):
	push	%r12
	push	%r13
	push	%r14

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13
	FP_MUL_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 0

	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_mulm_low):
	push	%r12
	push	%r13
	push	%r14

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13
	FP_MUL_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 1

	pop		%r14
	pop		%r13
	pop		%r12
	ret
