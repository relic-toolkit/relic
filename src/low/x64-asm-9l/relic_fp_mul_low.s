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
	push	%rbx
	subq	$160, %rsp

	mulxq	0(%rsi), %rax, %r8
	movq	%rax, 0(%rsp)
	mulxq	8(%rsi), %rax, %r9
	addq	%r8, %rax
	movq	%rax, 8(%rsp)
	mulxq	16(%rsi), %rax, %r8
	adcq	%r9, %rax
	movq	%rax, 16(%rsp)
	mulxq	24(%rsi), %rax, %r9
	adcq	%r8, %rax
	movq	%rax, 24(%rsp)
	mulxq	32(%rsi), %rax, %r8
	adcq	%r9, %rax
	movq	%rax, 32(%rsp)
	mulxq	40(%rsi), %rax, %r9
	adcq	%r8, %rax
	movq	%rax, 40(%rsp)
	mulxq	48(%rsi), %rax, %r8
	adcq	%r9, %rax
	movq	%rax, 48(%rsp)
	mulxq	56(%rsi), %rax, %r9
	adcq	%r8, %rax
	movq	%rax, 56(%rsp)
	mulxq	64(%rsi), %rax, %r8
	adcq	%r9, %rax
	movq	%rax, 64(%rsp)
	adcq	$0, %r8
	movq	%r8, 72(%rsp)

	movq	(8 * BARJ)(%rsp), %rax
	movq	(8 * BARJ + 8)(%rsp), %rdx
	shrdq	$BARS, %rdx, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	movq	$P0, %rax
	mulxq	%rax, %rax, %rcx
	subq	%rax, 0(%rsp)
	movq	%rcx, 80(%rsp)
	movq	$P1, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 8(%rsp)
	movq	%rcx, 88(%rsp)
	movq	$P2, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 16(%rsp)
	movq	%rcx, 96(%rsp)
	movq	$P3, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 24(%rsp)
	movq	%rcx, 104(%rsp)
	movq	$P4, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 32(%rsp)
	movq	%rcx, 112(%rsp)
	movq	$P5, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 40(%rsp)
	movq	%rcx, 120(%rsp)
	movq	$P6, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 48(%rsp)
	movq	%rcx, 128(%rsp)
	movq	$P7, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 56(%rsp)
	movq	%rcx, 136(%rsp)
	movq	$P8, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 64(%rsp)
	movq	%rcx, 144(%rsp)
	sbbq	$0, 72(%rsp)

	movq	80(%rsp), %rax
	subq	%rax, 8(%rsp)
	movq	88(%rsp), %rax
	sbbq	%rax, 16(%rsp)
	movq	96(%rsp), %rax
	sbbq	%rax, 24(%rsp)
	movq	104(%rsp), %rax
	sbbq	%rax, 32(%rsp)
	movq	112(%rsp), %rax
	sbbq	%rax, 40(%rsp)
	movq	120(%rsp), %rax
	sbbq	%rax, 48(%rsp)
	movq	128(%rsp), %rax
	sbbq	%rax, 56(%rsp)
	movq	136(%rsp), %rax
	sbbq	%rax, 64(%rsp)
	movq	144(%rsp), %rax
	sbbq	%rax, 72(%rsp)

	.rept 2
	movq	0(%rsp), %rax
	movq	$P0, %rdx
	subq	%rdx, %rax
	movq	%rax, 80(%rsp)
	movq	8(%rsp), %rax
	movq	$P1, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 88(%rsp)
	movq	16(%rsp), %rax
	movq	$P2, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 96(%rsp)
	movq	24(%rsp), %rax
	movq	$P3, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 104(%rsp)
	movq	32(%rsp), %rax
	movq	$P4, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 112(%rsp)
	movq	40(%rsp), %rax
	movq	$P5, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 120(%rsp)
	movq	48(%rsp), %rax
	movq	$P6, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 128(%rsp)
	movq	56(%rsp), %rax
	movq	$P7, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 136(%rsp)
	movq	64(%rsp), %rax
	movq	$P8, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 144(%rsp)
	movq	72(%rsp), %rax
	sbbq	$0, %rax
	movq	%rax, 152(%rsp)
	sbbq	%rbx, %rbx
	notq	%rbx
	movq	0(%rsp), %rax
	movq	80(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 0(%rsp)
	movq	8(%rsp), %rax
	movq	88(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsp), %rax
	movq	96(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsp), %rax
	movq	104(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 24(%rsp)
	movq	32(%rsp), %rax
	movq	112(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 32(%rsp)
	movq	40(%rsp), %rax
	movq	120(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 40(%rsp)
	movq	48(%rsp), %rax
	movq	128(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 48(%rsp)
	movq	56(%rsp), %rax
	movq	136(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 56(%rsp)
	movq	64(%rsp), %rax
	movq	144(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 64(%rsp)
	movq	72(%rsp), %rax
	movq	152(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 72(%rsp)
	.endr

	movq	0(%rsp), %rax
	movq	%rax, 0(%rdi)
	movq	8(%rsp), %rax
	movq	%rax, 8(%rdi)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rdi)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rdi)
	movq	32(%rsp), %rax
	movq	%rax, 32(%rdi)
	movq	40(%rsp), %rax
	movq	%rax, 40(%rdi)
	movq	48(%rsp), %rax
	movq	%rax, 48(%rdi)
	movq	56(%rsp), %rax
	movq	%rax, 56(%rdi)
	movq	64(%rsp), %rax
	movq	%rax, 64(%rdi)

	addq	$160, %rsp
	pop		%rbx
	ret

cdecl(fp_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$72, %rsp

	movq	%rdx, %rcx
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbx
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbx, 64(%rsp)

	MULM	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MUL_LOW	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0

	addq	$72, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$72, %rsp

	movq	%rdx, %rcx
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbx
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbx, 64(%rsp)

	MULM	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MUL_LOW	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1

	addq	$72, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
