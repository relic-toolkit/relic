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
 * @version $Id: relic_fp_mul_low.c 683 2011-03-10 23:51:23Z dfaranha $
 * @ingroup bn
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
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$8, %rsp

	movq	%rdi, 0(%rsp)
	mulxq	0(%rsi), %r8, %rax
	mulxq	8(%rsi), %r9, %r13
	addq	%rax, %r9
	mulxq	16(%rsi), %r10, %rax
	adcq	%r13, %r10
	mulxq	24(%rsi), %r11, %r13
	adcq	%rax, %r11
	mulxq	32(%rsi), %rcx, %rax
	adcq	%r13, %rcx
	mulxq	40(%rsi), %rdi, %r12
	adcq	%rax, %rdi
	adcq	$0, %r12

	movq	%rdi, %rax
	shrdq	$BARS, %r12, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	mulxq	p0(%rip), %rax, %r13
	subq	%rax, %r8
	mulxq	p1(%rip), %rax, %rsi
	sbbq	%rax, %r9
	mulxq	p2(%rip), %rax, %r14
	sbbq	%rax, %r10
	mulxq	p3(%rip), %rax, %r15
	sbbq	%rax, %r11
	mulxq	p4(%rip), %rax, %rbx
	sbbq	%rax, %rcx
	mulxq	p5(%rip), %rax, %rbp
	sbbq	%rax, %rdi
	sbbq	$0, %r12

	subq	%r13, %r9
	sbbq	%rsi, %r10
	sbbq	%r14, %r11
	sbbq	%r15, %rcx
	sbbq	%rbx, %rdi
	sbbq	%rbp, %r12

	.rept 2
	movq	%r8, %rbx
	subq	p0(%rip), %rbx
	movq	%r9, %r15
	sbbq	p1(%rip), %r15
	movq	%r10, %r14
	sbbq	p2(%rip), %r14
	movq	%r11, %r13
	sbbq	p3(%rip), %r13
	movq	%rcx, %rsi
	sbbq	p4(%rip), %rsi
	movq	%rdi, %rdx
	sbbq	p5(%rip), %rdx
	movq	%r12, %rax
	sbbq	$0, %rax
	cmovnc	%rbx, %r8
	cmovnc	%r15, %r9
	cmovnc	%r14, %r10
	cmovnc	%r13, %r11
	cmovnc	%rsi, %rcx
	cmovnc	%rdx, %rdi
	cmovnc	%rax, %r12
	.endr
	movq	0(%rsp), %rax

	movq	%r8, 0(%rax)
	movq	%r9, 8(%rax)
	movq	%r10, 16(%rax)
	movq	%r11, 24(%rax)
	movq	%rcx, 32(%rax)
	movq	%rdi, 40(%rax)

	addq	$8, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	FP_MUL_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 0

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

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	FP_MUL_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 1

	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
