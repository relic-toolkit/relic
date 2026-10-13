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
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application to Bilinear Pairings" by
 * Longa at TCHES'23.
 */

.text
.global cdecl(fp_mul1_low)
.global cdecl(fp_muln_low)
.global cdecl(fp_mulm_low)

/*
 * Function: fp_mul1_low
 * Inputs: rdi = c, rsi = a, rdx = digit < 2^63
 * Output: c = a * digit mod p, in constant time
 */
cdecl(fp_mul1_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	/* d = a * digit in r8-r15, rbx, rbp. */
	xorq	%rax, %rax
	mulx	0(%rsi), %r8, %r9
	mulx	8(%rsi), %r11, %r10
	adox	%r11, %r9
	mulx	16(%rsi), %r12, %r11
	adox	%r12, %r10
	mulx	24(%rsi), %r13, %r12
	adox	%r13, %r11
	mulx	32(%rsi), %r14, %r13
	adox	%r14, %r12
	mulx	40(%rsi), %r15, %r14
	adox	%r15, %r13
	mulx	48(%rsi), %rbx, %r15
	adox	%rbx, %r14
	mulx	56(%rsi), %rbp, %rbx
	adox	%rbp, %r15
	mulx	64(%rsi), %rsi, %rbp
	adox	%rsi, %rbx
	adox	%rax, %rbp

	/* q = floor(floor(d / 2^(|p| - 1)) * BAR / 2^64) is at most 2 below
	 * floor(d / p). Limbs BARJ = 8 and 9 of d are in rbx and rbp. */
	movq	%rbx, %rax
	shrdq	$BARS, %rbp, %rax
	movq	$BAR, %rdx
	mulx	%rax, %rax, %rdx

	/* d = d - q * p, which is below 3p. */
	MULSUB	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rcx, p0(%rip)

	/* Subtract p twice, keeping the difference when there is no borrow. */
	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rdi
	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rdi

	pop	%rbp
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret

cdecl(fp_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	// 8(%rsp) <- c, 0(%rsp) <- a: rdi and rsi are needed as temporaries.
	push	%rdi
	push	%rsi

	movq	%rdx, %rcx

	MULM	0(%rsp), 1, 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MULM_LOW	0(%rsp), 1, 0(%rcx), 8(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0

	addq	$16, %rsp
	pop	%rbp
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret

cdecl(fp_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	// 8(%rsp) <- c, 0(%rsp) <- a: rdi and rsi are needed as temporaries.
	push	%rdi
	push	%rsi

	movq	%rdx, %rcx

	MULM	0(%rsp), 1, 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MULM_LOW	0(%rsp), 1, 0(%rcx), 8(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1

	addq	$16, %rsp
	pop	%rbp
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret
