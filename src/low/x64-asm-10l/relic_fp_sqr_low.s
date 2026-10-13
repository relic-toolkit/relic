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
 * Implementation of the low-level prime field squaring functions.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

.text
.global cdecl(fp_sqrn_low)
.global cdecl(fp_sqrm_low)

/*
 * Registers: w in r8-r15, rax, rbx; T0 = rcx, T1 = rbp; a in rsi, c in rdi.
 */

/*
 * Function: fp_sqrn_low
 * Inputs: rdi = c, rsi = a
 * Output: c = a^2
 */
cdecl(fp_sqrn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	FP_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rcx, %rbp, p0(%rip), 0, 0(%rsp)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

/*
 * Function: fp_sqrm_low
 * Inputs: rdi = c, rsi = a
 * Output: c = a^2/R mod p
 */
cdecl(fp_sqrm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$160, %rsp

	FP_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rcx, %rbp, p0(%rip), 1, 0(%rsp)

	addq	$160, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
