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
	subq	$48, %rsp
	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 0, 0(%rsp)

	addq	$48, %rsp
	popq	%r14
	popq	%r13
	popq	%r12
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
	subq	$48, %rsp
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 1, 0(%rsp)

	addq	$48, %rsp
	popq	%r14
	popq	%r13
	popq	%r12
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
	subq	$192, %rsp
	movq	%rdi, 8(%rsp)
	movq	%rdx, %rcx
	leaq	128(%rsp), %rax
	movq	%rax, 0(%rsp)
	leaq	64(%rsp), %rdi

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 0, 0(%rsp)

	movq	8(%rsp), %rdi
	FP_RDCN_LOW	64(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %rdx, %rsi, p0(%rip)
	movq	8(%rsp), %rdi
	addq	$32, %rdi
	FP_RDCN_LOW	128(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %rdx, %rsi, p0(%rip)

	addq	$192, %rsp
	popq	%r14
	popq	%r13
	popq	%r12
	ret

#endif

#endif /* FP2_ASM */
