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
 * Implementation of the low-level prime field addition and subtraction
 * functions.
 *
 * Double-length values follow the half-limb convention described in macro.s:
 * they occupy 17 limbs and are reduced modulo p * 2^544 = (p * 2^32) * 2^512.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

#if defined(__APPLE__)
.section __TEXT,__const
#else
.section .rodata
#endif

.p2align 3
p0: .quad P0
p1: .quad P1
p2: .quad P2
p3: .quad P3
p4: .quad P4
p5: .quad P5
p6: .quad P6
p7: .quad P7
p8: .quad P8
_p0: .quad _P0
_p1: .quad _P1
_p2: .quad _P2
_p3: .quad _P3
_p4: .quad _P4
_p5: .quad _P5
_p6: .quad _P6
_p7: .quad _P7
_p8: .quad _P8

.global p0
.global p1
.global p2
.global p3
.global p4
.global p5
.global p6
.global p7
.global p8
.global _p0
.global _p1
.global _p2
.global _p3
.global _p4
.global _p5
.global _p6
.global _p7
.global _p8

#if OPSYS != WINDOWS

.hidden p0
.hidden p1
.hidden p2
.hidden p3
.hidden p4
.hidden p5
.hidden p6
.hidden p7
.hidden p8
.hidden _p0
.hidden _p1
.hidden _p2
.hidden _p3
.hidden _p4
.hidden _p5
.hidden _p6
.hidden _p7
.hidden _p8

#endif

.text

.global cdecl(fp_add1_low)
.global cdecl(fp_addn_low)
.global cdecl(fp_addm_low)
.global cdecl(fp_addd_low)
.global cdecl(fp_addc_low)
.global cdecl(fp_sub1_low)
.global cdecl(fp_subn_low)
.global cdecl(fp_subm_low)
.global cdecl(fp_subd_low)
.global cdecl(fp_subc_low)
.global cdecl(fp_negm_low)
.global cdecl(fp_dbln_low)
.global cdecl(fp_dblm_low)
.global cdecl(fp_hlvm_low)
.global cdecl(fp_hlvd_low)

cdecl(fp_add1_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r10
	addq	%rdx   , %r10
	movq	%r10   , 0(%rdi)

	ADD1 1 (RLC_FP_DIGS - 1)
	adcq	$0, %rax

	ret

cdecl(fp_addn_low):
	xorq	%rax, %rax
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11   , 0(%rdi)

	ADDN 	1 (RLC_FP_DIGS - 1)

	adcq    $0, %rax

	ret

/* a + b < 2p fits in 9 limbs, so only the 9-limb sum is compared with p. */
cdecl(fp_addm_low):
	push	%rbx
	push	%rbp

	movq	0(%rsi), %r8
	addq	0(%rdx), %r8
	movq	8(%rsi), %r9
	adcq	8(%rdx), %r9
	movq	16(%rsi), %r10
	adcq	16(%rdx), %r10
	movq	24(%rsi), %r11
	adcq	24(%rdx), %r11
	movq	32(%rsi), %rax
	adcq	32(%rdx), %rax
	movq	40(%rsi), %rcx
	adcq	40(%rdx), %rcx
	movq	48(%rsi), %rbx
	adcq	48(%rdx), %rbx
	movq	56(%rsi), %rbp
	adcq	56(%rdx), %rbp
	movq	64(%rsi), %rsi
	adcq	64(%rdx), %rsi

	FINALC	%r8, %r9, %r10, %r11, %rax, %rcx, %rbx, %rbp, %rsi, %rdi

	pop	%rbp
	pop	%rbx
	ret

cdecl(fp_addd_low):
	xorq	%rax, %rax
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11   , 0(%rdi)

	ADDN 	1 (2 * RLC_FP_DIGS - 2)

	adcq	$0, %rax
	ret

/* Adds modulo p * 2^544, which only touches limbs 8..16. */
cdecl(fp_addc_low):
	push	%rbx
	push	%rbp

	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11   , 0(%rdi)

	ADDN	1 (RLC_FP_DIGS - 2)

	movq	64(%rsi), %r8
	adcq	64(%rdx), %r8
	movq	72(%rsi), %r9
	adcq	72(%rdx), %r9
	movq	80(%rsi), %r10
	adcq	80(%rdx), %r10
	movq	88(%rsi), %r11
	adcq	88(%rdx), %r11
	movq	96(%rsi), %rax
	adcq	96(%rdx), %rax
	movq	104(%rsi), %rcx
	adcq	104(%rdx), %rcx
	movq	112(%rsi), %rbx
	adcq	112(%rdx), %rbx
	movq	120(%rsi), %rbp
	adcq	120(%rdx), %rbp
	movq	128(%rsi), %rsi
	adcq	128(%rdx), %rsi
	movq	$0, %rdx
	adcq	$0, %rdx

	movq	%r8, 64(%rdi)
	movq	%r9, 72(%rdi)
	movq	%r10, 80(%rdi)
	movq	%r11, 88(%rdi)
	movq	%rax, 96(%rdi)
	movq	%rcx, 104(%rdi)
	movq	%rbx, 112(%rdi)
	movq	%rbp, 120(%rdi)
	movq	%rsi, 128(%rdi)
	subq	_p0(%rip), %r8
	sbbq	_p1(%rip), %r9
	sbbq	_p2(%rip), %r10
	sbbq	_p3(%rip), %r11
	sbbq	_p4(%rip), %rax
	sbbq	_p5(%rip), %rcx
	sbbq	_p6(%rip), %rbx
	sbbq	_p7(%rip), %rbp
	sbbq	_p8(%rip), %rsi
	sbbq	$0, %rdx
	cmovc	64(%rdi), %r8
	cmovc	72(%rdi), %r9
	cmovc	80(%rdi), %r10
	cmovc	88(%rdi), %r11
	cmovc	96(%rdi), %rax
	cmovc	104(%rdi), %rcx
	cmovc	112(%rdi), %rbx
	cmovc	120(%rdi), %rbp
	cmovc	128(%rdi), %rsi
	movq	%r8, 64(%rdi)
	movq	%r9, 72(%rdi)
	movq	%r10, 80(%rdi)
	movq	%r11, 88(%rdi)
	movq	%rax, 96(%rdi)
	movq	%rcx, 104(%rdi)
	movq	%rbx, 112(%rdi)
	movq	%rbp, 120(%rdi)
	movq	%rsi, 128(%rdi)

	pop	%rbp
	pop	%rbx
	ret

cdecl(fp_sub1_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r10
	subq	%rdx   , %r10
	movq	%r10   , 0(%rdi)

	SUB1 	1 (RLC_FP_DIGS - 1)
	adcq	$0, %rax

	ret

cdecl(fp_subn_low):
	xorq	%rax   , %rax
	movq	0(%rsi), %r11
	subq	0(%rdx), %r11
	movq	%r11   , 0(%rdi)

	SUBN 1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax

	ret

cdecl(fp_subm_low):
	push	%rbx

	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8    , 0(%rdi)

	SUBN	1 (RLC_FP_DIGS - 1)

	movq	$0, %rax
	movq	$0, %rcx
	movq	$0, %rdx
	movq	$0, %rsi
	movq	$0, %r8
	movq	$0, %r9
	movq	$0, %r10
	movq	$0, %r11
	movq	$0, %rbx

	cmovc	p0(%rip), %rax
	cmovc	p1(%rip), %rcx
	cmovc	p2(%rip), %rdx
	cmovc	p3(%rip), %rsi
	cmovc	p4(%rip), %r8
	cmovc	p5(%rip), %r9
	cmovc	p6(%rip), %r10
	cmovc	p7(%rip), %r11
	cmovc	p8(%rip), %rbx

	addq	%rax, 0(%rdi)
	adcq	%rcx, 8(%rdi)
	adcq	%rdx, 16(%rdi)
	adcq	%rsi, 24(%rdi)
	adcq	%r8, 32(%rdi)
	adcq	%r9, 40(%rdi)
	adcq	%r10, 48(%rdi)
	adcq	%r11, 56(%rdi)
	adcq	%rbx, 64(%rdi)

	pop	%rbx
	ret

cdecl(fp_subd_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8, 0(%rdi)

	SUBN 	1 (2 * RLC_FP_DIGS - 2)

	adcq	$0, %rax
	ret

/* Subtracts modulo p * 2^544, adding p * 2^32 to limbs 8..16 on borrow. */
cdecl(fp_subc_low):
	push	%rbx

	movq    0(%rsi), %r8
	subq    0(%rdx), %r8
	movq    %r8,     0(%rdi)

	SUBN 	1 (2 * RLC_FP_DIGS - 2)

	movq	$0, %rax
	movq	$0, %rcx
	movq	$0, %rdx
	movq	$0, %rsi
	movq	$0, %r8
	movq	$0, %r9
	movq	$0, %r10
	movq	$0, %r11
	movq	$0, %rbx

	cmovc	_p0(%rip), %rax
	cmovc	_p1(%rip), %rcx
	cmovc	_p2(%rip), %rdx
	cmovc	_p3(%rip), %rsi
	cmovc	_p4(%rip), %r8
	cmovc	_p5(%rip), %r9
	cmovc	_p6(%rip), %r10
	cmovc	_p7(%rip), %r11
	cmovc	_p8(%rip), %rbx

	addq	%rax, 64(%rdi)
	adcq	%rcx, 72(%rdi)
	adcq	%rdx, 80(%rdi)
	adcq	%rsi, 88(%rdi)
	adcq	%r8, 96(%rdi)
	adcq	%r9, 104(%rdi)
	adcq	%r10, 112(%rdi)
	adcq	%r11, 120(%rdi)
	adcq	%rbx, 128(%rdi)

	pop	%rbx
	ret

cdecl(fp_negm_low):
	push	%rbx
	push	%rbp

	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%rax, %rax
	xorq	%rcx, %rcx
	xorq	%rdx, %rdx
	xorq	%rbx, %rbx
	xorq	%rbp, %rbp

	movq	0(%rsi), %r8
	orq	8(%rsi), %r8
	orq	16(%rsi), %r8
	orq	24(%rsi), %r8
	orq	32(%rsi), %r8
	orq	40(%rsi), %r8
	orq	48(%rsi), %r8
	orq	56(%rsi), %r8
	orq	64(%rsi), %r8
	testq	%r8, %r8
	cmovnz	p0(%rip), %r8
	cmovnz	p1(%rip), %r9
	cmovnz	p2(%rip), %r10
	cmovnz	p3(%rip), %r11
	cmovnz	p4(%rip), %rax
	cmovnz	p5(%rip), %rcx
	cmovnz	p6(%rip), %rdx
	cmovnz	p7(%rip), %rbx
	cmovnz	p8(%rip), %rbp
	subq	0(%rsi), %r8
	movq	%r8, 0(%rdi)
	sbbq	8(%rsi), %r9
	movq	%r9, 8(%rdi)
	sbbq	16(%rsi), %r10
	movq	%r10, 16(%rdi)
	sbbq	24(%rsi), %r11
	movq	%r11, 24(%rdi)
	sbbq	32(%rsi), %rax
	movq	%rax, 32(%rdi)
	sbbq	40(%rsi), %rcx
	movq	%rcx, 40(%rdi)
	sbbq	48(%rsi), %rdx
	movq	%rdx, 48(%rdi)
	sbbq	56(%rsi), %rbx
	movq	%rbx, 56(%rdi)
	sbbq	64(%rsi), %rbp
	movq	%rbp, 64(%rdi)

	pop	%rbp
	pop	%rbx
	ret

cdecl(fp_dbln_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r8
	addq	%r8    , %r8
	movq	%r8    , 0(%rdi)

	DBLN 1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax
	ret

/* 2a < 2p fits in 9 limbs, so only the 9-limb double is compared with p. */
cdecl(fp_dblm_low):
	push	%rbx
	push	%rbp

	movq	0(%rsi), %r8
	addq	%r8, %r8
	movq	8(%rsi), %r9
	adcq	%r9, %r9
	movq	16(%rsi), %r10
	adcq	%r10, %r10
	movq	24(%rsi), %r11
	adcq	%r11, %r11
	movq	32(%rsi), %rax
	adcq	%rax, %rax
	movq	40(%rsi), %rcx
	adcq	%rcx, %rcx
	movq	48(%rsi), %rbx
	adcq	%rbx, %rbx
	movq	56(%rsi), %rbp
	adcq	%rbp, %rbp
	movq	64(%rsi), %rsi
	adcq	%rsi, %rsi

	FINALC	%r8, %r9, %r10, %r11, %rax, %rcx, %rbx, %rbp, %rsi, %rdi

	pop	%rbp
	pop	%rbx
	ret

/* a + p < 2^545 fits in 9 limbs, so there is no carry to shift in. */
cdecl(fp_hlvm_low):
	push	%rbx
	push	%rbp
	push	%r12

	xorq	%r12, %r12
	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %rax
	movq	$P5, %rcx
	movq	$P6, %rdx
	movq	$P7, %rbx
	movq	$P8, %rbp
	testq	$1, 0(%rsi)
	cmovz	%r12, %r8
	cmovz	%r12, %r9
	cmovz	%r12, %r10
	cmovz	%r12, %r11
	cmovz	%r12, %rax
	cmovz	%r12, %rcx
	cmovz	%r12, %rdx
	cmovz	%r12, %rbx
	cmovz	%r12, %rbp
	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %rax
	adcq	40(%rsi), %rcx
	adcq	48(%rsi), %rdx
	adcq	56(%rsi), %rbx
	adcq	64(%rsi), %rbp
	shrdq	$1, %r9, %r8
	shrdq	$1, %r10, %r9
	shrdq	$1, %r11, %r10
	shrdq	$1, %rax, %r11
	shrdq	$1, %rcx, %rax
	shrdq	$1, %rdx, %rcx
	shrdq	$1, %rbx, %rdx
	shrdq	$1, %rbp, %rbx
	shrq	$1, %rbp
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)
	movq	%rcx, 40(%rdi)
	movq	%rdx, 48(%rdi)
	movq	%rbx, 56(%rdi)
	movq	%rbp, 64(%rdi)

	pop	%r12
	pop	%rbp
	pop	%rbx
	ret

/* Halves a 17-limb value, adding p first if it is odd. */
cdecl(fp_hlvd_low):
	push	%rbx
	push	%rbp
	push	%r12

	xorq	%r12, %r12
	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %rax
	movq	$P5, %rcx
	movq	$P6, %rdx
	movq	$P7, %rbx
	movq	$P8, %rbp
	testq	$1, 0(%rsi)
	cmovz	%r12, %r8
	cmovz	%r12, %r9
	cmovz	%r12, %r10
	cmovz	%r12, %r11
	cmovz	%r12, %rax
	cmovz	%r12, %rcx
	cmovz	%r12, %rdx
	cmovz	%r12, %rbx
	cmovz	%r12, %rbp
	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %rax
	adcq	40(%rsi), %rcx
	adcq	48(%rsi), %rdx
	adcq	56(%rsi), %rbx
	adcq	64(%rsi), %rbp
	movq	72(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 72(%rdi)
	movq	80(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 80(%rdi)
	movq	88(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 88(%rdi)
	movq	96(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 96(%rdi)
	movq	104(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 104(%rdi)
	movq	112(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 112(%rdi)
	movq	120(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 120(%rdi)
	movq	128(%rsi), %r12
	adcq	$0, %r12
	movq	%r12, 128(%rdi)
	movq	$0, %r12
	adcq	$0, %r12
	shrdq	$1, %r9, %r8
	shrdq	$1, %r10, %r9
	shrdq	$1, %r11, %r10
	shrdq	$1, %rax, %r11
	shrdq	$1, %rcx, %rax
	shrdq	$1, %rdx, %rcx
	shrdq	$1, %rbx, %rdx
	shrdq	$1, %rbp, %rbx
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)
	movq	%rcx, 40(%rdi)
	movq	%rdx, 48(%rdi)
	movq	%rbx, 56(%rdi)

	// Limb 8 is still in %rbp, so shift limbs 8..15 in place, which leaves
	// limb 16 in %rbp, then shift limb 16 with the carry in %r12.
	RSH1D 8 16 %rbp %rbx
	shrdq	$1, %r12, %rbp
	movq	%rbp, 128(%rdi)

	pop	%r12
	pop	%rbp
	pop	%rbx
	ret
