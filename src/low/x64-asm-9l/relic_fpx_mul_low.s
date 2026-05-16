/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of the low-level prime field squaring.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

.text
.global fp2_muln_c0
.global fp2_muln_c1
.global fp2_mulm_c0
.global fp2_mulm_c1

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application toBilinear Pairings" by
 * Longa at TCHES'23.
 */

fp2_muln_c0:
	push	%r12
	push	%r13 
	push	%r14  
	push	%r15  
	push	%rbx
	push	%rbp

	subq	$144, %rsp
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbp
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbp, 64(%rsp)
	movq	72(%rsi), %r8
	movq	80(%rsi), %r9
	movq	88(%rsi), %r10
	movq	96(%rsi), %r11
	movq	104(%rsi), %r12
	movq	112(%rsi), %r13
	movq	120(%rsi), %r14
	movq	128(%rsi), %r15
	movq	136(%rsi), %rbp
	movq	%r8, 72(%rsp)
	movq	%r9, 80(%rsp)
	movq	%r10, 88(%rsp)
	movq	%r11, 96(%rsp)
	movq	%r12, 104(%rsp)
	movq	%r13, 112(%rsp)
	movq	%r14, 120(%rsp)
	movq	%r15, 128(%rsp)
	movq	%rbp, 136(%rsp)
    movq	%rdx, %rcx

	MULM	0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP2_MUL0_LOW 0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0

	addq	$144, %rsp
	popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret

fp2_mulm_c0:
	push	%r12
	push	%r13 
	push	%r14  
	push	%r15  
	push	%rbx
	push	%rbp

	subq	$144, %rsp
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbp
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbp, 64(%rsp)
	movq	72(%rsi), %r8
	movq	80(%rsi), %r9
	movq	88(%rsi), %r10
	movq	96(%rsi), %r11
	movq	104(%rsi), %r12
	movq	112(%rsi), %r13
	movq	120(%rsi), %r14
	movq	128(%rsi), %r15
	movq	136(%rsi), %rbp
	movq	%r8, 72(%rsp)
	movq	%r9, 80(%rsp)
	movq	%r10, 88(%rsp)
	movq	%r11, 96(%rsp)
	movq	%r12, 104(%rsp)
	movq	%r13, 112(%rsp)
	movq	%r14, 120(%rsp)
	movq	%r15, 128(%rsp)
	movq	%rbp, 136(%rsp)
    movq	%rdx, %rcx

	MULM	0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP2_MUL0_LOW 0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1

	addq	$144, %rsp
	popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret

fp2_muln_c1:
    push	%r12
    push	%r13 
    push	%r14  
    push	%r15  
    push	%rbx
	push	%rbp

	subq	$144, %rsp
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbp
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbp, 64(%rsp)
	movq	72(%rsi), %r8
	movq	80(%rsi), %r9
	movq	88(%rsi), %r10
	movq	96(%rsi), %r11
	movq	104(%rsi), %r12
	movq	112(%rsi), %r13
	movq	120(%rsi), %r14
	movq	128(%rsi), %r15
	movq	136(%rsi), %rbp
	movq	%r8, 72(%rsp)
	movq	%r9, 80(%rsp)
	movq	%r10, 88(%rsp)
	movq	%r11, 96(%rsp)
	movq	%r12, 104(%rsp)
	movq	%r13, 112(%rsp)
	movq	%r14, 120(%rsp)
	movq	%r15, 128(%rsp)
	movq	%rbp, 136(%rsp)
    movq	%rdx, %rcx
    
    // [r8:r14] <- z = a0 x b10 + a1 x b00
	MULM	0(%rcx), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP2_MUL1_LOW	0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0

	addq	$144, %rsp
	popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret

fp2_mulm_c1:
    push	%r12
    push	%r13 
    push	%r14  
    push	%r15  
    push	%rbx
	push	%rbp

	subq	$144, %rsp
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbp
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbp, 64(%rsp)
	movq	72(%rsi), %r8
	movq	80(%rsi), %r9
	movq	88(%rsi), %r10
	movq	96(%rsi), %r11
	movq	104(%rsi), %r12
	movq	112(%rsi), %r13
	movq	120(%rsi), %r14
	movq	128(%rsi), %r15
	movq	136(%rsi), %rbp
	movq	%r8, 72(%rsp)
	movq	%r9, 80(%rsp)
	movq	%r10, 88(%rsp)
	movq	%r11, 96(%rsp)
	movq	%r12, 104(%rsp)
	movq	%r13, 112(%rsp)
	movq	%r14, 120(%rsp)
	movq	%r15, 128(%rsp)
	movq	%rbp, 136(%rsp)
    movq	%rdx, %rcx
    
    // [r8:r14] <- z = a0 x b10 + a1 x b00
	MULM	0(%rcx), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP2_MUL1_LOW	0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1

	addq	$144, %rsp
	popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret
