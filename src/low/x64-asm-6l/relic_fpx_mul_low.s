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
 * Implementation of the low-level prime field squaring.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

.text
.global fp2_muln_c0
.global fp2_muln_c1
.global fp2_mulm_c0
.global fp2_mulm_c1

fp2_muln_c0:
	push	%r12
	push	%r13 
	push	%r14  
	push	%r15  
	push	%rbx
	push	%rbp
	movq	%rdx, %rbp

	MULM	0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	FP2_MUL0_LOW 0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 0

	popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret

fp2_mulm_c0:
    push	%r12
    push	%r13 
    push	%r14  
    push	%r15  
    push	%rbx
    push	%rbp
    movq	%rdx, %rbp

	MULM	0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	FP2_MUL0_LOW 0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 1

    popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret

fp2_muln_c1:
    push	%r12
    push	%r13 
    push	%r14  
    push	%r15  
    push	%rbx
    push	%rbp
    movq	%rdx, %rbp
    
    // [r8:r14] <- z = a0 x b10 + a1 x b00
	MULM	0(%rbp), 48(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	FP2_MUL1_LOW	0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 0

    popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret

fp2_mulm_c1:
    push	%r12
    push	%r13 
    push	%r14  
    push	%r15  
    push	%rbx
    push	%rbp
    movq	%rdx, %rbp
    
    // [r8:r14] <- z = a0 x b10 + a1 x b00
	MULM	0(%rbp), 48(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15
	FP2_MUL1_LOW	0(%rbp), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 1

    popq	%rbp
    popq	%rbx
    popq	%r15
    popq	%r14
    popq	%r13
	popq	%r12
    ret
