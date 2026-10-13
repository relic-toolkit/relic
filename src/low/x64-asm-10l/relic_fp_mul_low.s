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
 * @ingroup bn
 */

#include "relic_fp_low.h"
#include "macro.s"

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application toBilinear Pairings" by
 * Longa at TCHES'23.
 */

.text

.global cdecl(fp_mul1_low)
.global cdecl(fp_muln_low)
.global cdecl(fp_mulm_low)

/*
 * Function: fp_mul1_low
 * Inputs: rdi = c, rsi = a, rdx = digit < 2^63
 * Output: c = a * digit mod p, in constant time
 */
cdecl(fp_mul1_low):
	push	%rbx
	subq	$176, %rsp

	/* d = a * digit. */
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
	mulxq	72(%rsi), %rax, %r9
	adcq	%r8, %rax
	movq	%rax, 72(%rsp)
	adcq	$0, %r9
	movq	%r9, 80(%rsp)

	/* q = floor(floor(d / 2^(|p| - 1)) * BAR / 2^64) is at most 2 below
	 * floor(d / p). */
	movq	(8 * BARJ)(%rsp), %rax
	movq	(8 * BARJ + 8)(%rsp), %rdx
	shrdq	$BARS, %rdx, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	/* Subtract the low halves of q * p, keeping the high halves in t. */
	movq	$P0, %rax
	mulxq	%rax, %rax, %rcx
	subq	%rax, 0(%rsp)
	movq	%rcx, 88(%rsp)
	movq	$P1, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 8(%rsp)
	movq	%rcx, 96(%rsp)
	movq	$P2, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 16(%rsp)
	movq	%rcx, 104(%rsp)
	movq	$P3, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 24(%rsp)
	movq	%rcx, 112(%rsp)
	movq	$P4, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 32(%rsp)
	movq	%rcx, 120(%rsp)
	movq	$P5, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 40(%rsp)
	movq	%rcx, 128(%rsp)
	movq	$P6, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 48(%rsp)
	movq	%rcx, 136(%rsp)
	movq	$P7, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 56(%rsp)
	movq	%rcx, 144(%rsp)
	movq	$P8, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 64(%rsp)
	movq	%rcx, 152(%rsp)
	movq	$P9, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, 72(%rsp)
	movq	%rcx, 160(%rsp)
	sbbq	$0, 80(%rsp)

	/* Subtract the high halves, leaving d - q * p below 3p. */
	movq	88(%rsp), %rax
	subq	%rax, 8(%rsp)
	movq	96(%rsp), %rax
	sbbq	%rax, 16(%rsp)
	movq	104(%rsp), %rax
	sbbq	%rax, 24(%rsp)
	movq	112(%rsp), %rax
	sbbq	%rax, 32(%rsp)
	movq	120(%rsp), %rax
	sbbq	%rax, 40(%rsp)
	movq	128(%rsp), %rax
	sbbq	%rax, 48(%rsp)
	movq	136(%rsp), %rax
	sbbq	%rax, 56(%rsp)
	movq	144(%rsp), %rax
	sbbq	%rax, 64(%rsp)
	movq	152(%rsp), %rax
	sbbq	%rax, 72(%rsp)
	movq	160(%rsp), %rax
	sbbq	%rax, 80(%rsp)

	/* Subtract p twice, keeping the difference when there is no borrow. */
	.rept 2
	movq	0(%rsp), %rax
	movq	$P0, %rdx
	subq	%rdx, %rax
	movq	%rax, 88(%rsp)
	movq	8(%rsp), %rax
	movq	$P1, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 96(%rsp)
	movq	16(%rsp), %rax
	movq	$P2, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 104(%rsp)
	movq	24(%rsp), %rax
	movq	$P3, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 112(%rsp)
	movq	32(%rsp), %rax
	movq	$P4, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 120(%rsp)
	movq	40(%rsp), %rax
	movq	$P5, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 128(%rsp)
	movq	48(%rsp), %rax
	movq	$P6, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 136(%rsp)
	movq	56(%rsp), %rax
	movq	$P7, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 144(%rsp)
	movq	64(%rsp), %rax
	movq	$P8, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 152(%rsp)
	movq	72(%rsp), %rax
	movq	$P9, %rdx
	sbbq	%rdx, %rax
	movq	%rax, 160(%rsp)
	movq	80(%rsp), %rax
	sbbq	$0, %rax
	movq	%rax, 168(%rsp)
	sbbq	%rbx, %rbx
	notq	%rbx
	movq	0(%rsp), %rax
	movq	88(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 0(%rsp)
	movq	8(%rsp), %rax
	movq	96(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 8(%rsp)
	movq	16(%rsp), %rax
	movq	104(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 16(%rsp)
	movq	24(%rsp), %rax
	movq	112(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 24(%rsp)
	movq	32(%rsp), %rax
	movq	120(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 32(%rsp)
	movq	40(%rsp), %rax
	movq	128(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 40(%rsp)
	movq	48(%rsp), %rax
	movq	136(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 48(%rsp)
	movq	56(%rsp), %rax
	movq	144(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 56(%rsp)
	movq	64(%rsp), %rax
	movq	152(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 64(%rsp)
	movq	72(%rsp), %rax
	movq	160(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 72(%rsp)
	movq	80(%rsp), %rax
	movq	168(%rsp), %rdx
	xorq	%rax, %rdx
	andq	%rbx, %rdx
	xorq	%rdx, %rax
	movq	%rax, 80(%rsp)
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
	movq	72(%rsp), %rax
	movq	%rax, 72(%rdi)
	addq	$176, %rsp
	pop	%rbx
	ret

/*
 * Registers: z in r8-r15, rax, rbx, rbp; T0 = rsi, T1 = rdi; b in rcx.
 * Stack: 0(%rsp) = c, 8(%rsp) = a.
 */
cdecl(fp_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$16, %rsp
	movq	%rdi, 0(%rsp)
	movq	%rsi, 8(%rsp)
	movq	%rdx, %rcx

	MULM	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MUL_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$16, %rsp
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
	subq	$16, %rsp
	movq	%rdi, 0(%rsp)
	movq	%rsi, 8(%rsp)
	movq	%rdx, %rcx

	MULM	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MUL_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$16, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
