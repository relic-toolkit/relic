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
	subq	$232, %rsp
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
	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 152(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0, 144(%rsp)

	addq	$232, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r15
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
	push	%r15
	push	%rbx
	push	%rbp
	subq	$232, %rsp
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

	FP2_MUL_LOW	0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1, 144(%rsp)

	addq	$232, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r15
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
	push	%r15
	push	%rbx
	push	%rbp
	subq	$456, %rsp
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
	movq	%rdi, 160(%rsp)
	leaq	312(%rsp), %rax
	movq	%rax, 152(%rsp)
	leaq	168(%rsp), %rdi
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0, 144(%rsp)

	movq	160(%rsp), %rdi
	FP_RDCN_LOW	168(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rsi, p0(%rip)
	movq	160(%rsp), %rdi
	addq	$72, %rdi
	FP_RDCN_LOW	312(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rsi, p0(%rip)

	addq	$456, %rsp
	popq	%rbp
	popq	%rbx
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	ret

#endif

#endif /* FP2_ASM */
