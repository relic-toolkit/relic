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
.global cdecl(fp2_muln_c0)
.global cdecl(fp2_muln_c1)
.global cdecl(fp2_mulm_c0)
.global cdecl(fp2_mulm_c1)

#if OPSYS != WINDOWS
.hidden cdecl(fp2_muln_c0)
.hidden cdecl(fp2_muln_c1)
.hidden cdecl(fp2_mulm_c0)
.hidden cdecl(fp2_mulm_c1)
#endif

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application toBilinear Pairings" by
 * Longa at TCHES'23.
 *
 * Registers: z in r8-r15, rax, rbx, rbp; T0 = rsi, T1 = rdi; b in rcx.
 * Stack: 0(%rsp) = c, 8(%rsp) = a.
 */

cdecl(fp2_muln_c0):
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

	// z = a_00 x b_0
	MULM	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP2_MUL0_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$16, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp2_mulm_c0):
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

	// z = a_00 x b_0
	MULM	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP2_MUL0_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$16, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp2_muln_c1):
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

	// z = a_00 x b_1
	MULM	8(%rsp), 80(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP2_MUL1_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$16, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp2_mulm_c1):
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

	// z = a_00 x b_1
	MULM	8(%rsp), 80(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP2_MUL1_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$16, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
