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
	push	%rbx
	push	%rdi

	mulxq	0(%rsi), %r8, %rax
	mulxq	8(%rsi), %r9, %rbx
	addq	%rax, %r9
	mulxq	16(%rsi), %r10, %rax
	adcq	%rbx, %r10
	mulxq	24(%rsi), %r11, %r12
	adcq	%rax, %r11
	adcq	$0, %r12

	movq	%r11, %rax
	shrdq	$BARS, %r12, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	movq	$P0, %rax
	mulxq	%rax, %rax, %rbx
	subq	%rax, %r8
	movq	$P1, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, %r9
	movq	$P2, %rax
	mulxq	%rax, %rax, %rsi
	sbbq	%rax, %r10
	movq	$P3, %rax
	mulxq	%rax, %rax, %rdi
	sbbq	%rax, %r11
	sbbq	$0, %r12

	subq	%rbx, %r9
	sbbq	%rcx, %r10
	sbbq	%rsi, %r11
	sbbq	%rdi, %r12

	.rept 2
	movq	%r8, %rax
	movq	$P0, %rdx
	subq	%rdx, %rax
	movq	%r9, %rbx
	movq	$P1, %rdx
	sbbq	%rdx, %rbx
	movq	%r10, %rcx
	movq	$P2, %rdx
	sbbq	%rdx, %rcx
	movq	%r11, %rsi
	movq	$P3, %rdx
	sbbq	%rdx, %rsi
	movq	%r12, %rdi
	sbbq	$0, %rdi
	cmovncq	%rax, %r8
	cmovncq	%rbx, %r9
	cmovncq	%rcx, %r10
	cmovncq	%rsi, %r11
	cmovncq	%rdi, %r12
	.endr

	pop		%rdi
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)

	pop		%rbx
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
