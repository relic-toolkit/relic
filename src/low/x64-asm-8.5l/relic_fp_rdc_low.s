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
 * Implementation of the low-level prime field modular reduction functions.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

.text

.global cdecl(fp_rdcn_low)

/*
 * Function: fp_rdcn_low
 * Inputs: rdi = c, rsi = a, with a a double-length value of 17 limbs
 * Output: c = a * 2^-576 mod p
 *
 * Montgomery reduction is linear in a, so the reduction steps only run on the
 * low half l = a mod 2^576, giving t = (l + m * p) / 2^576 <= p. The high half
 * h = floor(a / 2^576) < 2^512 is added afterwards, and t + h < 2p.
 */
cdecl(fp_rdcn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	// 0(%rsp) <- c: rdi is needed as a temporary.
	push	%rdi

	xorq	%rax, %rax
	xorq	%rbp, %rbp
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbx

	// z = (z0 x u0) x p + z clears z0, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r8, %rdx, %rcx
	MULADD	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rcx, %rdi, p0(%rip)

	// z = (z1 x u0) x p + z clears z1, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r9, %rdx, %rcx
	MULADD	%r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %rcx, %rdi, p0(%rip)

	// z = (z2 x u0) x p + z clears z2, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r10, %rdx, %rcx
	MULADD	%r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %rcx, %rdi, p0(%rip)

	// z = (z3 x u0) x p + z clears z3, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r11, %rdx, %rcx
	MULADD	%r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %rcx, %rdi, p0(%rip)

	// z = (z4 x u0) x p + z clears z4, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r12, %rdx, %rcx
	MULADD	%r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %rcx, %rdi, p0(%rip)

	// z = (z5 x u0) x p + z clears z5, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r13, %rdx, %rcx
	MULADD	%r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %rcx, %rdi, p0(%rip)

	// z = (z6 x u0) x p + z clears z6, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r14, %rdx, %rcx
	MULADD	%r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %rcx, %rdi, p0(%rip)

	// z = (z7 x u0) x p + z clears z7, which becomes the new top.
	movq	$U0, %rdx
	mulx	%r15, %rdx, %rcx
	MULADD	%r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rcx, %rdi, p0(%rip)

	// z = (z8 x u0) x p + z clears z8, which becomes the new top.
	movq	$U0, %rdx
	mulx	%rbx, %rdx, %rcx
	MULADD	%rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rcx, %rdi, p0(%rip)

	// t += h
	addq	72(%rsi), %rbp
	adcq	80(%rsi), %r8
	adcq	88(%rsi), %r9
	adcq	96(%rsi), %r10
	adcq	104(%rsi), %r11
	adcq	112(%rsi), %r12
	adcq	120(%rsi), %r13
	adcq	128(%rsi), %r14
	adcq	$0, %r15

	pop	%rdi
	FINALC	%rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rdi

	pop	%rbp
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret
