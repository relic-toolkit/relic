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
 * Implementation of the low-level quadratic extension field multiplication.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application toBilinear Pairings" by
 * Longa at TCHES'23.
 *
 * Registers: z in r8-r15, rax, rbx, rbp; T0 = rsi, T1 = rdi; b in rcx.
 * Stack: 0(%rsp) = c, 8(%rsp) = a, 16(%rsp) = c1.
 */

.text

#ifdef FP2_ASM

.global cdecl(fp2_muln_low)

/*
 * Function: fp2_muln_low
 * Inputs: rdi = c, rsi = a, rdx = b
 * Output: c = a * b, with c[1] at RLC_DV_STRIDE bytes from c[0]
 */
cdecl(fp2_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$104, %rsp
	movq	%rdi, 0(%rsp)
	movq	%rsi, 8(%rsp)
	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 16(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$104, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

.global cdecl(fp2_mulm_low)

#ifdef FP2_MUL_RDC

/*
 * Function: fp2_mulm_low
 * Inputs: rdi = c, rsi = a, rdx = b
 * Output: c = a * b/R mod p, coefficient-wise
 */
cdecl(fp2_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$104, %rsp
	movq	%rdi, 0(%rsp)
	movq	%rsi, 8(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$104, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#else

/*
 * Function: fp2_mulm_low
 * Inputs: rdi = c, rsi = a, rdx = b
 * Output: c = a * b/R mod p, coefficient-wise, by reducing the product of
 * fp2_muln_low separately
 */
cdecl(fp2_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$432, %rsp
	movq	%rdi, 424(%rsp)
	leaq	104(%rsp), %rax
	movq	%rax, 0(%rsp)
	movq	%rsi, 8(%rsp)
	leaq	264(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	8(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	movq	424(%rsp), %rdi
	FP_RDCN_LOW	104(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rcx, %rbp, p0(%rip)
	movq	424(%rsp), %rdi
	addq	$80, %rdi
	FP_RDCN_LOW	264(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rcx, %rbp, p0(%rip)

	addq	$432, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif /* FP2_ASM */
