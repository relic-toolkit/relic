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
 * Implementation of low-level prime field modular reduction.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"

#include "macro.s"

.text

.global fp_rdcn_low

/*
 * Function: fp_rdcn_low
 * Inputs: rdi = c, rsi = a
 */
fp_rdcn_low:
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push 	%rbx
	push	%rbp
	push	%rdi
	movq	%rsi, %rdi

	movq	0(%rdi),%r8
	movq	8(%rdi),%r9
	movq	16(%rdi),%r10
	movq	24(%rdi),%r11
	movq	32(%rdi),%r12
	movq	40(%rdi),%r13
	movq	48(%rdi),%r14
	movq	56(%rdi),%r15
	movq	64(%rdi),%rbx
	movq	72(%rdi),%rbp
	xorq	%rax, %rax

	movq	$U0, %rdx
	mulx	%r8, %rdx, %rcx
	MULADD	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip)
	movq	80(%rdi),%r8
	adox	%rax, %r8
	movq	$U0, %rdx
	mulx	%r9, %rdx, %rcx
    MULADD	%r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %rsi, %rax, p0(%rip)
	movq	88(%rdi),%r9
	adox	%rax, %r9
	movq	$U0, %rdx
	mulx	%r10, %rdx, %rcx
    MULADD	%r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %rsi, %rax, p0(%rip)
	movq	96(%rdi),%r10
	adox	%rax, %r10
	movq	$U0, %rdx
	mulx	%r11, %rdx, %rcx
    MULADD	%r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %rsi, %rax, p0(%rip)
	movq	104(%rdi),%r11
	adox	%rax, %r11
	movq	$U0, %rdx
	mulx	%r12, %rdx, %rcx
    MULADD	%r12, %r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %rsi, %rax, p0(%rip)
	movq	112(%rdi),%r12
	adox	%rax, %r12
	movq	$U0, %rdx
	mulx	%r13, %rdx, %rcx
    MULADD	%r13, %r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %rsi, %rax, p0(%rip)
	movq	120(%rdi),%r13
	adox	%rax, %r13
	movq	$U0, %rdx
	mulx	%r14, %rdx, %rcx
    MULADD	%r14, %r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %rsi, %rax, p0(%rip)
	movq	128(%rdi),%r14
	adox	%rax, %r14
	movq	$U0, %rdx
	mulx	%r15, %rdx, %rcx
    MULADD	%r15, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rsi, %rax, p0(%rip)
	movq	136(%rdi),%r15
	adox	%rax, %r15
	movq	$U0, %rdx
	mulx	%rbx, %rdx, %rcx
    MULADD	%rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rsi, %rax, p0(%rip)
	popq	%rdi

	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax
	
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
