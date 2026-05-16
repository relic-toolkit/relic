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
	push	%rbx
	subq	$80, %rsp

	movq	0(%rsi), %r8
	addq	40(%rsi),%r8
	movq	8(%rsi), %r9
	adcq	48(%rsi),%r9
	movq	16(%rsi),%r10
	adcq	56(%rsi),%r10
	movq	24(%rsi),%r11
	adcq	64(%rsi),%r11
	movq	32(%rsi),%r12
	adcq	72(%rsi),%r12
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10,16(%rsp)
	movq	%r11,24(%rsp)
	movq	%r12,32(%rsp)

	movq	0(%rsi), %r8
	subq	40(%rsi),%r8
	movq	8(%rsi), %r10
	sbbq	48(%rsi),%r10
	movq	16(%rsi),%r12
	sbbq	56(%rsi),%r12
	movq	24(%rsi),%r13
	sbbq	64(%rsi),%r13
	movq	32(%rsi),%r14
	sbbq	72(%rsi),%r14
	addq	p0(%rip),%r8
	adcq	p1(%rip),%r10
	adcq	p2(%rip),%r12
	adcq	p3(%rip),%r13
	adcq	p4(%rip),%r14
	movq	%r8, 40(%rsp)
	movq	%r10,48(%rsp)
	movq	%r12,56(%rsp)
	movq	%r13,64(%rsp)
	movq	%r14,72(%rsp)

	MULR	0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MULM_LOW	0(%rsp), 40(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 0

	addq	$80, %rsp
	popq	%rbx
	popq	%r14
	popq	%r13
	popq	%r12
	ret

fp2_sqrn_c1:
	push	%r12
	push	%r13 
	push	%r14  
	push	%rbx
	subq	$40, %rsp

	// rsp[0..5] <- z = 2 x a0
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11
	movq	32(%rsi),%r12
	addq	%r8, %r8
	adcq	%r9, %r9
	adcq	%r10,%r10
	adcq	%r11,%r11
	adcq	%r12,%r12
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10,16(%rsp)
	movq	%r11,24(%rsp)
	movq	%r12,32(%rsp)
	
	MULM	0(%rsp), 40(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MULM_LOW	0(%rsp), 40(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 0

	addq	$40, %rsp
	popq	%rbx
	popq	%r14
	popq	%r13
	popq	%r12
	ret

fp2_sqrm_c0:
	push	%r12
	push	%r13 
	push	%r14  
	push	%rbx
	subq	$80, %rsp

	// rsp[0..4] <- z = a0 + a1
	movq	0(%rsi), %r8
	addq	40(%rsi),%r8
	movq	8(%rsi), %r9
	adcq	48(%rsi),%r9
	movq	16(%rsi),%r10
	adcq	56(%rsi),%r10
	movq	24(%rsi),%r11
	adcq	64(%rsi),%r11
	movq	32(%rsi),%r12
	adcq	72(%rsi),%r12
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10,16(%rsp)
	movq	%r11,24(%rsp)
	movq	%r12,32(%rsp)

	// rsp[6..11] <- a0 - a1 + p
	movq	0(%rsi), %r8
	subq	40(%rsi),%r8
	movq	8(%rsi), %r10
	sbbq	48(%rsi),%r10
	movq	16(%rsi),%r12
	sbbq	56(%rsi),%r12
	movq	24(%rsi),%r13
	sbbq	64(%rsi),%r13
	movq	32(%rsi),%r14
	sbbq	72(%rsi),%r14
	addq	p0(%rip),%r8
	adcq	p1(%rip),%r10
	adcq	p2(%rip),%r12
	adcq	p3(%rip),%r13
	adcq	p4(%rip),%r14
	movq	%r8, 40(%rsp)
	movq	%r10,48(%rsp)
	movq	%r12,56(%rsp)
	movq	%r13,64(%rsp)
	movq	%r14,72(%rsp)

	MULR	0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MULM_LOW	0(%rsp), 40(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 1

	addq	$80, %rsp
	popq	%rbx
	popq	%r14
	popq	%r13
	popq	%r12
	ret

fp2_sqrm_c1:
	push	%r12
	push	%r13 
	push	%r14  
	push	%rbx
	subq	$40, %rsp

	// rsp[0..5] <- z = 2 x a0
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi),%r10
	movq	24(%rsi),%r11
	movq	32(%rsi),%r12
	addq	%r8, %r8
	adcq	%r9, %r9
	adcq	%r10,%r10
	adcq	%r11,%r11
	adcq	%r12,%r12
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10,16(%rsp)
	movq	%r11,24(%rsp)
	movq	%r12,32(%rsp)
	
	MULM	0(%rsp), 40(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14
	FP_MULM_LOW	0(%rsp), 40(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 1

	addq	$40, %rsp
	popq	%rbx
	popq	%r14
	popq	%r13
	popq	%r12
	ret