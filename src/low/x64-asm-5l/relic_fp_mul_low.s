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
 * @ingroup fp
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
	.if BARJ - 4
	.error "the quotient must come from the two top digits"
	.endif
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	/* d = a * digit in %r8-%r13. */
	mulxq	0(%rsi), %r8, %rax
	mulxq	8(%rsi), %r9, %rbx
	addq	%rax, %r9
	mulxq	16(%rsi), %r10, %rax
	adcq	%rbx, %r10
	mulxq	24(%rsi), %r11, %rbx
	adcq	%rax, %r11
	mulxq	32(%rsi), %r12, %r13
	adcq	%rbx, %r12
	adcq	$0, %r13

	/* q = floor(floor(d / 2^(|p| - 1)) * BAR / 2^64) is at most 2 below
	 * floor(d / p). */
	movq	%r12, %rax
	shrdq	$BARS, %r13, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	/* Subtract the low halves of q * p, keeping the high halves. */
	movq	$P0, %rax
	mulxq	%rax, %rax, %rbx
	subq	%rax, %r8
	movq	$P1, %rax
	mulxq	%rax, %rax, %rcx
	sbbq	%rax, %r9
	movq	$P2, %rax
	mulxq	%rax, %rax, %r14
	sbbq	%rax, %r10
	movq	$P3, %rax
	mulxq	%rax, %rax, %r15
	sbbq	%rax, %r11
	movq	$P4, %rax
	mulxq	%rax, %rax, %rbp
	sbbq	%rax, %r12
	sbbq	$0, %r13

	/* Subtract the high halves, leaving d - q * p below 3p. */
	subq	%rbx, %r9
	sbbq	%rcx, %r10
	sbbq	%r14, %r11
	sbbq	%r15, %r12
	sbbq	%rbp, %r13

	/* Subtract p twice, keeping the difference when there is no borrow. */
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
	movq	%r11, %r14
	movq	$P3, %rdx
	sbbq	%rdx, %r14
	movq	%r12, %r15
	movq	$P4, %rdx
	sbbq	%rdx, %r15
	movq	%r13, %rbp
	sbbq	$0, %rbp
	cmovncq	%rax, %r8
	cmovncq	%rbx, %r9
	cmovncq	%rcx, %r10
	cmovncq	%r14, %r11
	cmovncq	%r15, %r12
	cmovncq	%rbp, %r13
	.endr

	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)

	pop	%rbp
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret

cdecl(fp_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push 	%rbx

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MUL_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 0

    popq	%rbx
    popq	%r14
    popq	%r13
    popq	%r12
    ret

cdecl(fp_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push 	%rbx
	push 	%rbp

	movq	%rdx, %rbp

	MULM	0(%rsi), 0(%rbp), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MUL_LOW	0(%rsi), 0(%rbp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 1

	popq	%rbp
    popq	%rbx
    popq	%r14
    popq	%r13
    popq	%r12
    ret