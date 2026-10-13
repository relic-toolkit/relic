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

	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	// rcx holds the carry into the next word loaded, and CF and OF are
	// clear before each MULADD.
	xorq	%rcx, %rcx
	xorq	%rax, %rax

	movq	$U0, %rdx
	mulx	%r8, %rdx, %r13
	MULADD	%r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip)
	movq	40(%rsi), %r8
	adcx	%rcx, %r8
	adox	%rax, %r8
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r9, %rdx, %r13
	MULADD	%r9, %r10, %r11, %r12, %r8, %r13, %r14, p0(%rip)
	movq	48(%rsi), %r9
	adcx	%rcx, %r9
	adox	%rax, %r9
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r10, %rdx, %r13
	MULADD	%r10, %r11, %r12, %r8, %r9, %r13, %r14, p0(%rip)
	movq	56(%rsi), %r10
	adcx	%rcx, %r10
	adox	%rax, %r10
	movq	$0, %rcx
	adcx	%rax, %rcx
	adox	%rax, %rcx

	movq	$U0, %rdx
	mulx	%r11, %rdx, %r13
	MULADD	%r11, %r12, %r8, %r9, %r10, %r13, %r14, p0(%rip)

	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14

	pop		%r14
	pop		%r13
	pop		%r12
	ret
