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
.global cdecl(fp2_sqrn_c0)
.global cdecl(fp2_sqrn_c1)
.global cdecl(fp2_sqrm_c0)
.global cdecl(fp2_sqrm_c1)

#if OPSYS != WINDOWS
.hidden cdecl(fp2_sqrn_c0)
.hidden cdecl(fp2_sqrn_c1)
.hidden cdecl(fp2_sqrm_c0)
.hidden cdecl(fp2_sqrm_c1)
#endif

/*
 * Registers: z in r8-r15, rax, rbx, rbp; T0 = rsi, T1 = rdi.
 * Stack: 0(%rsp) = c, 8(%rsp) = pointer to the first operand, which is kept
 * at 16(%rsp), and the second operand of c_0 at 96(%rsp).
 */

cdecl(fp2_sqrn_c0):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$176, %rsp
	movq	%rdi, 0(%rsp)
	leaq	16(%rsp), %rax
	movq	%rax, 8(%rsp)

	// 16(%rsp) <- a_0 + a_1
	movq	0(%rsi), %rax
	addq	80(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	8(%rsi), %rax
	adcq	88(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	16(%rsi), %rax
	adcq	96(%rsi), %rax
	movq	%rax, 32(%rsp)
	movq	24(%rsi), %rax
	adcq	104(%rsi), %rax
	movq	%rax, 40(%rsp)
	movq	32(%rsi), %rax
	adcq	112(%rsi), %rax
	movq	%rax, 48(%rsp)
	movq	40(%rsi), %rax
	adcq	120(%rsi), %rax
	movq	%rax, 56(%rsp)
	movq	48(%rsi), %rax
	adcq	128(%rsi), %rax
	movq	%rax, 64(%rsp)
	movq	56(%rsi), %rax
	adcq	136(%rsi), %rax
	movq	%rax, 72(%rsp)
	movq	64(%rsi), %rax
	adcq	144(%rsi), %rax
	movq	%rax, 80(%rsp)
	movq	72(%rsi), %rax
	adcq	152(%rsi), %rax
	movq	%rax, 88(%rsp)

	// 96(%rsp) <- a_0 - a_1 + p
	movq	0(%rsi), %r8
	subq	80(%rsi), %r8
	movq	8(%rsi), %r9
	sbbq	88(%rsi), %r9
	movq	16(%rsi), %r10
	sbbq	96(%rsi), %r10
	movq	24(%rsi), %r11
	sbbq	104(%rsi), %r11
	movq	32(%rsi), %r12
	sbbq	112(%rsi), %r12
	movq	40(%rsi), %r13
	sbbq	120(%rsi), %r13
	movq	48(%rsi), %r14
	sbbq	128(%rsi), %r14
	movq	56(%rsi), %r15
	sbbq	136(%rsi), %r15
	movq	64(%rsi), %rax
	sbbq	144(%rsi), %rax
	movq	72(%rsi), %rbx
	sbbq	152(%rsi), %rbx
	addq	p0(%rip), %r8
	adcq	p1(%rip), %r9
	adcq	p2(%rip), %r10
	adcq	p3(%rip), %r11
	adcq	p4(%rip), %r12
	adcq	p5(%rip), %r13
	adcq	p6(%rip), %r14
	adcq	p7(%rip), %r15
	adcq	p8(%rip), %rax
	adcq	p9(%rip), %rbx
	movq	%r8, 96(%rsp)
	movq	%r9, 104(%rsp)
	movq	%r10, 112(%rsp)
	movq	%r11, 120(%rsp)
	movq	%r12, 128(%rsp)
	movq	%r13, 136(%rsp)
	movq	%r14, 144(%rsp)
	movq	%r15, 152(%rsp)
	movq	%rax, 160(%rsp)
	movq	%rbx, 168(%rsp)

	MULM	8(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MULM_LOW	8(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$176, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp2_sqrm_c0):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$176, %rsp
	movq	%rdi, 0(%rsp)
	leaq	16(%rsp), %rax
	movq	%rax, 8(%rsp)

	// 16(%rsp) <- a_0 + a_1
	movq	0(%rsi), %rax
	addq	80(%rsi), %rax
	movq	%rax, 16(%rsp)
	movq	8(%rsi), %rax
	adcq	88(%rsi), %rax
	movq	%rax, 24(%rsp)
	movq	16(%rsi), %rax
	adcq	96(%rsi), %rax
	movq	%rax, 32(%rsp)
	movq	24(%rsi), %rax
	adcq	104(%rsi), %rax
	movq	%rax, 40(%rsp)
	movq	32(%rsi), %rax
	adcq	112(%rsi), %rax
	movq	%rax, 48(%rsp)
	movq	40(%rsi), %rax
	adcq	120(%rsi), %rax
	movq	%rax, 56(%rsp)
	movq	48(%rsi), %rax
	adcq	128(%rsi), %rax
	movq	%rax, 64(%rsp)
	movq	56(%rsi), %rax
	adcq	136(%rsi), %rax
	movq	%rax, 72(%rsp)
	movq	64(%rsi), %rax
	adcq	144(%rsi), %rax
	movq	%rax, 80(%rsp)
	movq	72(%rsi), %rax
	adcq	152(%rsi), %rax
	movq	%rax, 88(%rsp)

	// 96(%rsp) <- a_0 - a_1 + p
	movq	0(%rsi), %r8
	subq	80(%rsi), %r8
	movq	8(%rsi), %r9
	sbbq	88(%rsi), %r9
	movq	16(%rsi), %r10
	sbbq	96(%rsi), %r10
	movq	24(%rsi), %r11
	sbbq	104(%rsi), %r11
	movq	32(%rsi), %r12
	sbbq	112(%rsi), %r12
	movq	40(%rsi), %r13
	sbbq	120(%rsi), %r13
	movq	48(%rsi), %r14
	sbbq	128(%rsi), %r14
	movq	56(%rsi), %r15
	sbbq	136(%rsi), %r15
	movq	64(%rsi), %rax
	sbbq	144(%rsi), %rax
	movq	72(%rsi), %rbx
	sbbq	152(%rsi), %rbx
	addq	p0(%rip), %r8
	adcq	p1(%rip), %r9
	adcq	p2(%rip), %r10
	adcq	p3(%rip), %r11
	adcq	p4(%rip), %r12
	adcq	p5(%rip), %r13
	adcq	p6(%rip), %r14
	adcq	p7(%rip), %r15
	adcq	p8(%rip), %rax
	adcq	p9(%rip), %rbx
	movq	%r8, 96(%rsp)
	movq	%r9, 104(%rsp)
	movq	%r10, 112(%rsp)
	movq	%r11, 120(%rsp)
	movq	%r12, 128(%rsp)
	movq	%r13, 136(%rsp)
	movq	%r14, 144(%rsp)
	movq	%r15, 152(%rsp)
	movq	%rax, 160(%rsp)
	movq	%rbx, 168(%rsp)

	MULM	8(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MULM_LOW	8(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$176, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp2_sqrn_c1):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$96, %rsp
	movq	%rdi, 0(%rsp)
	leaq	16(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	%rsi, %rcx

	// 16(%rsp) <- 2 x a_0
	movq	0(%rsi), %rax
	addq	%rax, %rax
	movq	%rax, 16(%rsp)
	movq	8(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 24(%rsp)
	movq	16(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 32(%rsp)
	movq	24(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 40(%rsp)
	movq	32(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 48(%rsp)
	movq	40(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 56(%rsp)
	movq	48(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 64(%rsp)
	movq	56(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 72(%rsp)
	movq	64(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 80(%rsp)
	movq	72(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 88(%rsp)

	MULM	8(%rsp), 80(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MULM_LOW	8(%rsp), 80(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$96, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp2_sqrm_c1):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$96, %rsp
	movq	%rdi, 0(%rsp)
	leaq	16(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	%rsi, %rcx

	// 16(%rsp) <- 2 x a_0
	movq	0(%rsi), %rax
	addq	%rax, %rax
	movq	%rax, 16(%rsp)
	movq	8(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 24(%rsp)
	movq	16(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 32(%rsp)
	movq	24(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 40(%rsp)
	movq	32(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 48(%rsp)
	movq	40(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 56(%rsp)
	movq	48(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 64(%rsp)
	movq	56(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 72(%rsp)
	movq	64(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 80(%rsp)
	movq	72(%rsi), %rax
	adcq	%rax, %rax
	movq	%rax, 88(%rsp)

	MULM	8(%rsp), 80(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MULM_LOW	8(%rsp), 80(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$96, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
