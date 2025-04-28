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

#include "macro.s"

.text

.global fp_muln_low
.global fp_mulm_low

fp_muln_low:
	movq %rdx,%rcx
	FP_MULN_LOW %rdi, %r8, %r9, %r10, %rsi, %rcx
	ret

fp_mulm_low:
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push 	%rbx
	push 	%rbp
	subq 	$48, %rsp

	movq	%rdx, %rbp

    // [r8:r14] <- z = 2 x a00 x a1
	MULM	0(%rsi), 0(%rbp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15

	FP_MULM_LOW	0(%rsi), 0(%rbp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip)

	// Final correction
	movq	%r14, %r13
	movq	%r8, %r15
	movq	%r9, %rbx
	movq	%r10, %rcx
	movq	%r11, %rdx
	movq	%r12, %rsi
	subq	p0(%rip), %r13
	sbbq	p1(%rip), %r15
	sbbq	p2(%rip), %rbx
	sbbq	p3(%rip), %rcx
	sbbq	p4(%rip), %rdx
	sbbq	p5(%rip), %rsi
	cmovc	%r14, %r13
	cmovc	%r8, %r15
	cmovc	%r9, %rbx
	cmovc	%r10, %rcx
	cmovc	%r11, %rdx
	cmovc	%r12, %rsi
    movq	%r13, 0(%rdi)
	movq	%r15, 8(%rdi)
	movq	%rbx, 16(%rdi)
	movq	%rcx, 24(%rdi)
	movq	%rdx, 32(%rdi)
	movq	%rsi, 40(%rdi)

	addq	$48, %rsp
	popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
    popq	%r12
    ret