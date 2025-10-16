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

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application toBilinear Pairings" by
 * Longa at TCHES'23.
 */

.text
.global fp2_sqrn_c0
.global fp2_sqrn_c1
.global fp2_sqrm_c0
.global fp2_sqrm_c1

fp2_sqrn_c0:
	push	%r12
	push	%r13 
	push	%r14  
	push	%r15  
	push	%rbx
	push	%rbp
	subq	$144, %rsp

	// rsp[0..5] <- z = a0 + a1
	movq	0(%rsi), %r8
	addq	72(%rsi),%r8
	movq	8(%rsi), %r10
	adcq	80(%rsi),%r10
	movq	16(%rsi),%r12
	adcq	88(%rsi),%r12
	movq	24(%rsi),%r13
	adcq	96(%rsi),%r13
	movq	32(%rsi),%r14
	adcq	104(%rsi),%r14
	movq	40(%rsi),%r15
	adcq	112(%rsi),%r15
	movq	48(%rsi),%rbp
	adcq	120(%rsi),%rbp
	movq	56(%rsi),%rbx
	adcq	128(%rsi),%rbx
	movq	64(%rsi),%r9
	adcq	136(%rsi),%r9

	movq	%r8, 0(%rsp)
	movq	%r10, 8(%rsp)
	movq	%r12,16(%rsp)
	movq	%r13,24(%rsp)
	movq	%r14,32(%rsp)
	movq	%r15,40(%rsp)
	movq	%rbp,48(%rsp)
	movq	%rbx,56(%rsp)
	movq	%r9,64(%rsp)

	// rsp[6..11] <- a0 - a1 + p
	movq	0(%rsi), %r8
	subq	72(%rsi),%r8
	movq	8(%rsi), %r10
	sbbq	80(%rsi),%r10
	movq	16(%rsi),%r12
	sbbq	88(%rsi),%r12
	movq	24(%rsi),%r13
	sbbq	96(%rsi),%r13
	movq	32(%rsi),%r14
	sbbq	104(%rsi),%r14
	movq	40(%rsi),%r15
	sbbq	112(%rsi),%r15
	movq	48(%rsi),%rbp
	sbbq	120(%rsi),%rbp
	movq	56(%rsi),%rbx
	sbbq	128(%rsi),%rbx
	movq	64(%rsi),%r9
	sbbq	136(%rsi),%r9
	movq	%r9, %rsi

	addq	p0(%rip),%r8
	adcq	p1(%rip),%r10
	adcq	p2(%rip),%r12
	adcq	p3(%rip),%r13
	adcq	p4(%rip),%r14
	adcq	p5(%rip),%r15
	adcq	p6(%rip),%rbp
	adcq	p7(%rip),%rbx
	adcq	p8(%rip),%rsi
	movq	%r8, 72(%rsp)
	movq	%r10, 80(%rsp)
	movq	%r12,88(%rsp)
	movq	%r13,96(%rsp)
	movq	%r14,104(%rsp)
	movq	%r15,112(%rsp)
	movq	%rbp,120(%rsp)
	movq	%rbx,128(%rsp)
	movq	%rsi,136(%rsp)

	MULR	0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbp, %rbx, %rsi
	FP_MULM_LOW	0(%rsp), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbp, %rbx, %rsi, %rax, p0(%rip), 0

	addq	$144, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	ret

fp2_sqrn_c1:
	push	%r12
	push	%r13 
	push	%r14  
	push	%r15  
	push	%rbx
	push	%rbp
	subq	$144, %rsp

	// rsp[0..5] <- z = 2 x a0
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbp
	addq	%r8, %r8
	adcq	%r9, %r9
	adcq	%r10,%r10
	adcq	%r11,%r11
	adcq	%r12,%r12
	adcq	%r13,%r13
	adcq	%r14,%r14
	adcq	%r15,%r15
	adcq	%rbp,%rbp
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
	
	MULM	0(%rsp), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MULM_LOW	0(%rsp), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0

	addq	$144, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	ret

fp2_sqrm_c0:
	push	%r12
	push	%r13 
	push	%r14  
	push	%r15  
	push	%rbx
	push	%rbp
	subq	$144, %rsp

	// rsp[0..5] <- z = a0 + a1
	movq	0(%rsi), %r8
	addq	72(%rsi),%r8
	movq	8(%rsi), %r10
	adcq	80(%rsi),%r10
	movq	16(%rsi),%r12
	adcq	88(%rsi),%r12
	movq	24(%rsi),%r13
	adcq	96(%rsi),%r13
	movq	32(%rsi),%r14
	adcq	104(%rsi),%r14
	movq	40(%rsi),%r15
	adcq	112(%rsi),%r15
	movq	48(%rsi),%rbp
	adcq	120(%rsi),%rbp
	movq	56(%rsi),%rbx
	adcq	128(%rsi),%rbx
	movq	64(%rsi),%r9
	adcq	136(%rsi),%r9

	movq	%r8, 0(%rsp)
	movq	%r10, 8(%rsp)
	movq	%r12,16(%rsp)
	movq	%r13,24(%rsp)
	movq	%r14,32(%rsp)
	movq	%r15,40(%rsp)
	movq	%rbp,48(%rsp)
	movq	%rbx,56(%rsp)
	movq	%r9,64(%rsp)

	// rsp[6..11] <- a0 - a1 + p
	movq	0(%rsi), %r8
	subq	72(%rsi),%r8
	movq	8(%rsi), %r10
	sbbq	80(%rsi),%r10
	movq	16(%rsi),%r12
	sbbq	88(%rsi),%r12
	movq	24(%rsi),%r13
	sbbq	96(%rsi),%r13
	movq	32(%rsi),%r14
	sbbq	104(%rsi),%r14
	movq	40(%rsi),%r15
	sbbq	112(%rsi),%r15
	movq	48(%rsi),%rbp
	sbbq	120(%rsi),%rbp
	movq	56(%rsi),%rbx
	sbbq	128(%rsi),%rbx
	movq	64(%rsi),%r9
	sbbq	136(%rsi),%r9
	movq	%r9, %rsi

	addq	p0(%rip),%r8
	adcq	p1(%rip),%r10
	adcq	p2(%rip),%r12
	adcq	p3(%rip),%r13
	adcq	p4(%rip),%r14
	adcq	p5(%rip),%r15
	adcq	p6(%rip),%rbp
	adcq	p7(%rip),%rbx
	adcq	p8(%rip),%rsi
	movq	%r8, 72(%rsp)
	movq	%r10, 80(%rsp)
	movq	%r12,88(%rsp)
	movq	%r13,96(%rsp)
	movq	%r14,104(%rsp)
	movq	%r15,112(%rsp)
	movq	%rbp,120(%rsp)
	movq	%rbx,128(%rsp)
	movq	%rsi,136(%rsp)

	MULR	0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbp, %rbx, %rsi
	FP_MULM_LOW	0(%rsp), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbp, %rbx, %rsi, %rax, p0(%rip), 1

	addq	$144, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	ret

fp2_sqrm_c1:
	push	%r12
	push	%r13 
	push	%r14  
	push	%r15  
	push	%rbx
	push	%rbp
	subq	$144, %rsp

	// rsp[0..5] <- z = 2 x a0
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbp
	addq	%r8, %r8
	adcq	%r9, %r9
	adcq	%r10,%r10
	adcq	%r11,%r11
	adcq	%r12,%r12
	adcq	%r13,%r13
	adcq	%r14,%r14
	adcq	%r15,%r15
	adcq	%rbp,%rbp
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
	
	MULM	0(%rsp), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MULM_LOW	0(%rsp), 72(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1

	addq	$144, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	ret