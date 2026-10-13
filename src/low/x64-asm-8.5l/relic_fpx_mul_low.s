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
 * Implementation of the low-level quadratic extension field multiplication
 * functions, for u^2 = -5.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

.text
.global cdecl(fp2_mulm_c0)
.global cdecl(fp2_mulm_c1)

#if OPSYS != WINDOWS
.hidden cdecl(fp2_mulm_c0)
.hidden cdecl(fp2_mulm_c1)
#endif

/*
 * Techniques and code heavily inspired from "Efficient Algorithms for Large
 * Prime Characteristic Fields and Their Application to Bilinear Pairings" by
 * Longa at TCHES'23.
 */

/*
 * Function: fp2_mulm_c0
 * Inputs: rdi = c, rsi = a, rdx = b
 * Output: c = a0 * b0 - 5 * a1 * b1 mod p, in Montgomery form, where a1 and b1
 * follow a0 and b0 in memory
 */
cdecl(fp2_mulm_c0):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	// 0(%rsp) <- a, 8(%rsp) <- c, 16(%rsp) <- 5 x b1 in 9 limbs.
	subq	$88, %rsp
	movq	%rsi, 0(%rsp)
	movq	%rdi, 8(%rsp)
	movq	%rdx, %rcx

	// 5 x b1 < 2^547 fits in 9 limbs.
	movq	$5, %rdx
	xorq	%rax, %rax
	mulx	72(%rcx), %r8, %r9
	mulx	80(%rcx), %r11, %r10
	adox	%r11, %r9
	mulx	88(%rcx), %r12, %r11
	adox	%r12, %r10
	mulx	96(%rcx), %r13, %r12
	adox	%r13, %r11
	mulx	104(%rcx), %r14, %r13
	adox	%r14, %r12
	mulx	112(%rcx), %r15, %r14
	adox	%r15, %r13
	mulx	120(%rcx), %rbx, %r15
	adox	%rbx, %r14
	mulx	128(%rcx), %rbp, %rbx
	adox	%rbp, %r15
	mulx	136(%rcx), %rsi, %rbp
	adox	%rsi, %rbx
	movq	%r8, 16(%rsp)
	movq	%r9, 24(%rsp)
	movq	%r10, 32(%rsp)
	movq	%r11, 40(%rsp)
	movq	%r12, 48(%rsp)
	movq	%r13, 56(%rsp)
	movq	%r14, 64(%rsp)
	movq	%r15, 72(%rsp)
	movq	%rbx, 80(%rsp)

	MULM	0(%rsp), 1, 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP2_MUL0_LOW	0(%rsp), 1, 0(%rcx), 16(%rsp), 8(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rdi, p0(%rip)

	addq	$88, %rsp
	pop	%rbp
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret

/*
 * Function: fp2_mulm_c1
 * Inputs: rdi = c, rsi = a, rdx = b
 * Output: c = a0 * b1 + a1 * b0 mod p, in Montgomery form, where a1 and b1
 * follow a0 and b0 in memory
 */
cdecl(fp2_mulm_c1):
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

	MULM	0(%rsp), 1, 72(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP2_MUL1_LOW	0(%rsp), 1, 0(%rcx), 72(%rcx), 8(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rdi, p0(%rip)

	addq	$16, %rsp
	pop	%rbp
	pop	%rbx
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	ret
