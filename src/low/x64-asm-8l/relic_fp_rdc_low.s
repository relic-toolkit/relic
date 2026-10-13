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

.global cdecl(fp_rdcn_low)

/*
 * Function: fp_rdcn_low
 * Inputs: rdi = c, rsi = a
 */
cdecl(fp_rdcn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbx
	// rcx holds the carry into the next word loaded, and CF and OF are
	// clear before each MULADD.
	xorq	%rcx, %rcx
	xorq	%rax, %rax

	movq	$U0, %rdx
	mulx	%r8, %rdx, %rbp
	MULADD	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip)
	movq	72(%rsi), %r8
	adcx	%rcx, %r8
	adox	%rax, %r8
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r9, %rdx, %rbp
	MULADD	%r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %r8, %rbp, %rax, p0(%rip)
	movq	80(%rsi), %r9
	adcx	%rcx, %r9
	adox	%rax, %r9
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r10, %rdx, %rbp
	MULADD	%r10, %r11, %r12, %r13, %r14, %r15, %rbx, %r8, %r9, %rbp, %rax, p0(%rip)
	movq	88(%rsi), %r10
	adcx	%rcx, %r10
	adox	%rax, %r10
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r11, %rdx, %rbp
	MULADD	%r11, %r12, %r13, %r14, %r15, %rbx, %r8, %r9, %r10, %rbp, %rax, p0(%rip)
	movq	96(%rsi), %r11
	adcx	%rcx, %r11
	adox	%rax, %r11
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r12, %rdx, %rbp
	MULADD	%r12, %r13, %r14, %r15, %rbx, %r8, %r9, %r10, %r11, %rbp, %rax, p0(%rip)
	movq	104(%rsi), %r12
	adcx	%rcx, %r12
	adox	%rax, %r12
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r13, %rdx, %rbp
	MULADD	%r13, %r14, %r15, %rbx, %r8, %r9, %r10, %r11, %r12, %rbp, %rax, p0(%rip)
	movq	112(%rsi), %r13
	adcx	%rcx, %r13
	adox	%rax, %r13
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r14, %rdx, %rbp
	MULADD	%r14, %r15, %rbx, %r8, %r9, %r10, %r11, %r12, %r13, %rbp, %rax, p0(%rip)
	movq	120(%rsi), %r14
	adcx	%rcx, %r14
	adox	%rax, %r14
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r15, %rdx, %rbp
	MULADD	%r15, %rbx, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rbp, %rax, p0(%rip)

	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
