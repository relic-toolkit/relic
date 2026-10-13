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
 * Implementation of the low-level quadratic extension field multiplication.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application to Bilinear Pairings" by
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
	push	%rbx
	push	%rbp
	subq	$48, %rsp
	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rbp

	FP2_MUL_LOW	0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 0, 0(%rsp)

	addq	$48, %rsp
	popq	%rbp
	popq	%rbx
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
	push	%rbx
	push	%rbp
	subq	$48, %rsp
	movq	%rdx, %rbp

	FP2_MUL_LOW	0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 1, 0(%rsp)

	addq	$48, %rsp
	popq	%rbp
	popq	%rbx
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
	push	%rbx
	push	%rbp
	subq	$224, %rsp
	movq	%rdi, 8(%rsp)
	movq	%rdx, %rbp
	leaq	144(%rsp), %rax
	movq	%rax, 0(%rsp)
	leaq	64(%rsp), %rdi

	FP2_MUL_LOW	0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbx, p0(%rip), 0, 0(%rsp)

	movq	8(%rsp), %rdi
	FP_RDCN_LOW	64(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %rsi, %r13, p0(%rip)
	movq	8(%rsp), %rdi
	addq	$40, %rdi
	FP_RDCN_LOW	144(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %rsi, %r13, p0(%rip)

	addq	$224, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r14
	popq	%r13
	popq	%r12
	ret

#endif

#endif /* FP2_ASM */
