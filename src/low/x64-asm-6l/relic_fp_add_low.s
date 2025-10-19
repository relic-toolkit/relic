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
 * Implementation of the low-level prime field addition and subtraction
 * functions.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

.data

p0: .quad P0
p1: .quad P1
p2: .quad P2
p3: .quad P3
p4: .quad P4
p5: .quad P5
u0: .quad U0

.global p0
.global p1
.global p2
.global p3
.global p4
.global p5
.global u0

#if OPSYS != WINDOWS

.hidden p0
.hidden p1
.hidden p2
.hidden p3
.hidden p4
.hidden p5

#endif

.text

.global fp_add1_low
.global fp_addn_low
.global fp_addm_low
.global fp_addd_low
.global fp_addc_low
.global fp_sub1_low
.global fp_subn_low
.global fp_subm_low
.global fp_subd_low
.global fp_subc_low
.global fp_negm_low
.global fp_dbln_low
.global fp_dblm_low
.global fp_hlvm_low
.global fp_hlvd_low

fp_add1_low:
	movq	0(%rsi), %r10
	addq	%rdx   , %r10
	movq	%r10   , 0(%rdi)

	ADD1 1 (RLC_FP_DIGS - 1)
	xorq	%rax, %rax

	ret

fp_addn_low:
	xorq	%rax, %rax
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11   , 0(%rdi)

	ADDN 	1 (RLC_FP_DIGS - 1)

	adcq    $0, %rax

	ret

fp_addm_low:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	movq	 0(%rdx), %r8
	addq	 0(%rsi), %r8
	movq	 8(%rdx), %r9
	adcq	 8(%rsi), %r9
	movq	16(%rdx), %r10
	adcq	16(%rsi), %r10
	movq	24(%rdx), %r11
	adcq	24(%rsi), %r11
	movq	32(%rdx), %r12
	adcq	32(%rsi), %r12
	movq	40(%rdx), %r13
	adcq	40(%rsi), %r13

	movq 	%r8 , %rax
	movq 	%r9 , %rcx
	movq 	%r10, %rdx
	movq 	%r11, %rsi
	movq	%r12, %rbx
	movq	%r13, %rbp

	subq	p0(%rip), %rax
	sbbq	p1(%rip), %rcx
	sbbq	p2(%rip), %rdx
	sbbq	p3(%rip), %rsi
	sbbq	p4(%rip), %rbx
	sbbq	p5(%rip), %rbp

	cmovnc	%rax, %r8
	cmovnc	%rcx, %r9
	cmovnc	%rdx, %r10
	cmovnc	%rsi, %r11
	cmovnc	%rbx, %r12
	cmovnc	%rbp, %r13

	movq	%r8 ,  0(%rdi)
	movq	%r9 ,  8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)

	pop		%r13
	pop		%r12
	pop		%rbp
	pop		%rbx
	ret

fp_addd_low:
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11   , 0(%rdi)

	ADDN 	1 (2 * RLC_FP_DIGS - 1)

	ret

fp_addc_low:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	movq	0(%rsi), %r8
	addq	0(%rdx), %r8
	movq	%r8    , 0(%rdi)

	ADDN	1 (RLC_FP_DIGS - 1)

	movq     48(%rsi), %r8
	adcq     48(%rdx), %r8
	movq     56(%rsi), %r9
	adcq     56(%rdx), %r9
	movq     64(%rsi), %r10
	adcq     64(%rdx), %r10
	movq     72(%rsi), %r11
	adcq     72(%rdx), %r11
	movq     80(%rsi), %r12
	adcq     80(%rdx), %r12
	movq     88(%rsi), %r13
	adcq     88(%rdx), %r13

	movq 	%r8 , %rax
	movq 	%r9 , %rcx
	movq 	%r10, %rdx
	movq 	%r11, %rsi
	movq	%r12, %rbx
	movq	%r13, %rbp

	subq	p0(%rip), %rax
	sbbq	p1(%rip), %rcx
	sbbq	p2(%rip), %rdx
	sbbq	p3(%rip), %rsi
	sbbq	p4(%rip), %rbx
	sbbq	p5(%rip), %rbp

	cmovnc	%rax, %r8
	cmovnc	%rcx, %r9
	cmovnc	%rdx, %r10
	cmovnc	%rsi, %r11
	cmovnc	%rbx, %r12
	cmovnc	%rbp, %r13

	movq	%r8 , 48(%rdi)
	movq	%r9 , 56(%rdi)
	movq	%r10, 64(%rdi)
	movq	%r11, 72(%rdi)
	movq	%r12, 80(%rdi)
	movq	%r13, 88(%rdi)
	xorq	%rax, %rax

	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	ret

fp_sub1_low:
	movq	0(%rsi), %r10
	subq	%rdx   , %r10
	movq	%r10   , 0(%rdi)

	SUB1 	1 (RLC_FP_DIGS - 1)
	xorq	%rax, %rax

	ret

fp_subn_low:
	xorq	%rax   , %rax
	movq	0(%rsi), %r11
	subq	0(%rdx), %r11
	movq	%r11   , 0(%rdi)

	SUBN 1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax

	ret

fp_subm_low:
    push	%rbx
    push	%rbp
    push	%r12
    push	%r13

    movq	 0(%rsi), %r8
    subq	 0(%rdx), %r8
    movq	 8(%rsi), %r9
    sbbq	 8(%rdx), %r9
    movq	16(%rsi), %r10
    sbbq	16(%rdx), %r10
    movq	24(%rsi), %r11
    sbbq	24(%rdx), %r11
    movq	32(%rsi), %r12
    sbbq	32(%rdx), %r12
    movq	40(%rsi), %r13
    sbbq	40(%rdx), %r13

    movq 	$0, %rax
    movq 	$0, %rcx
    movq 	$0, %rdx
    movq 	$0, %rsi
    movq	$0, %rbx
    movq	$0, %rbp

    cmovc	p0(%rip), %rax
    cmovc	p1(%rip), %rcx
    cmovc	p2(%rip), %rdx
    cmovc	p3(%rip), %rsi
    cmovc	p4(%rip), %rbx
    cmovc	p5(%rip), %rbp

    addq	%rax, %r8
    adcq	%rcx, %r9
    adcq	%rdx, %r10
    adcq	%rsi, %r11
    adcq	%rbx, %r12
    adcq	%rbp, %r13

    movq	%r8 ,  0(%rdi)
    movq	%r9 ,  8(%rdi)
    movq	%r10, 16(%rdi)
    movq	%r11, 24(%rdi)
    movq	%r12, 32(%rdi)
    movq	%r13, 40(%rdi)

    pop		%r13
    pop		%r12
    pop		%rbp
    pop		%rbx
    ret

fp_subd_low:
	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8, 0(%rdi)

	SUBN 	1 (2 * RLC_FP_DIGS - 1)

	ret

fp_subc_low:
	xorq    %rax,%rax
	xorq    %rcx,%rcx

	movq    0(%rsi), %r8
	subq    0(%rdx), %r8
	movq    %r8,     0(%rdi)

	SUBN 	1 (2 * RLC_FP_DIGS - 1)

	movq	$0, %r8
	movq	$0, %r9
	movq	$0, %r10
	movq	$0, %r11

	cmovc	p0(%rip), %rax
	cmovc	p1(%rip), %rcx
	cmovc	p2(%rip), %r8
	cmovc	p3(%rip), %r9
	cmovc	p4(%rip), %r10
	cmovc	p5(%rip), %r11

	addq	%rax, 48(%rdi)
	adcq	%rcx, 56(%rdi)
	adcq	%r8,  64(%rdi)
	adcq	%r9,  72(%rdi)
	adcq	%r10, 80(%rdi)
	adcq	%r11, 88(%rdi)

	ret

fp_negm_low:
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%rax, %rax
	xorq	%rcx, %rcx

    movq    0(%rsi) , %r8
    or 	    8(%rsi) , %r8
    or 	    16(%rsi), %r8
    or 	    24(%rsi), %r8
    or 	    32(%rsi), %r8
    or 	    40(%rsi), %r8
    test    %r8, %r8
	cmovnz 	p0(%rip), %r8
	cmovnz 	p1(%rip), %r9
	cmovnz 	p2(%rip), %r10
	cmovnz 	p3(%rip), %r11
	cmovnz 	p4(%rip), %rax
	cmovnz 	p5(%rip), %rcx
	subq 	0(%rsi) , %r8
	movq 	%r8     , 0(%rdi)
	sbbq 	8(%rsi) , %r9
	movq 	%r9     , 8(%rdi)
	sbbq 	16(%rsi), %r10
	movq 	%r10    , 16(%rdi)
	sbbq 	24(%rsi), %r11
	movq 	%r11    , 24(%rdi)
	sbbq 	32(%rsi), %rax
	movq 	%rax    , 32(%rdi)
	sbbq 	40(%rsi), %rcx
	movq 	%rcx    , 40(%rdi)
	ret

fp_dbln_low:
	movq	0(%rsi), %r8
	addq	%r8    , %r8
	movq	%r8    , 0(%rdi)

	DBLN 1 (RLC_FP_DIGS - 1)

	xorq	%rax,%rax
	ret

fp_dblm_low:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	xorq	%rax, %rax
	xorq	%rcx, %rcx
	xorq	%rdx, %rdx

	movq	0(%rsi) , %r8
	addq	%r8     , %r8
	movq	8(%rsi) , %r9
	adcq	%r9     , %r9
	movq	16(%rsi), %r10
	adcq	%r10    , %r10
	movq	24(%rsi), %r11
	adcq	%r11    , %r11
	movq	32(%rsi), %r12
	adcq	%r12    , %r12
	movq	40(%rsi), %r13
	adcq	%r13    , %r13

	movq 	%r8 , %rax
	movq 	%r9 , %rcx
	movq 	%r10, %rdx
	movq 	%r11, %rsi
	movq	%r12, %rbx
	movq	%r13, %rbp

	subq	p0(%rip), %rax
	sbbq	p1(%rip), %rcx
	sbbq	p2(%rip), %rdx
	sbbq	p3(%rip), %rsi
	sbbq	p4(%rip), %rbx
	sbbq	p5(%rip), %rbp

	cmovnc	%rax, %r8
	cmovnc	%rcx, %r9
	cmovnc	%rdx, %r10
	cmovnc	%rsi, %r11
	cmovnc	%rbx, %r12
	cmovnc	%rbp, %r13

	movq	%r8 ,  0(%rdi)
	movq	%r9 ,  8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	xorq	%rax, %rax

	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	ret

fp_hlvm_low:
	push	%r12
	push	%r13

	xorq	%rdx, %rdx

	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %r12
	movq	$P5, %r13

  	movq 	$1     ,%rax
  	movq 	0(%rsi),%rcx
  	andq 	%rcx   ,%rax

	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %r12
	cmovz	%rdx, %r13

	addq	%rcx    , %r8
	movq	8(%rsi) , %rdx
	adcq	%rdx    , %r9
	movq	16(%rsi), %rdx
	adcq	%rdx    , %r10
	movq	24(%rsi), %rdx
	adcq	%rdx    , %r11
	movq	32(%rsi), %rdx
	adcq	%rdx    , %r12
	movq	40(%rsi), %rdx
	adcq	%rdx    , %r13

	rcrq 	$1, %r13
	rcrq 	$1, %r12
  	rcrq 	$1, %r11
  	rcrq 	$1, %r10
  	rcrq 	$1, %r9
  	rcrq 	$1, %r8

	movq	%r8 ,  0(%rdi)
	movq	%r9 ,  8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	xorq	%rax, %rax

	pop		%r13
	pop		%r12
	ret

fp_hlvd_low:
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	xorq	%rdx, %rdx

	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %r12
	movq	$P5, %r13

  	movq 	$1     ,%rax
  	movq 	0(%rsi),%rcx
  	andq 	%rcx   ,%rax

	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %r12
	cmovz	%rdx, %r13

	addq	%rcx     , %r8
	adcq	8(%rsi)  , %r9
	adcq	16(%rsi) , %r10
	adcq	24(%rsi) , %r11
	adcq	32(%rsi) , %r12
	adcq	40(%rsi) , %r13
	movq	48(%rsi) , %r14
	adcq	$0       , %r14
	movq	56(%rsi) , %r15
	adcq	$0       , %r15
	movq	64(%rsi) , %rax
	adcq	$0       , %rax
	movq	72(%rsi) , %rbx
	adcq	$0       , %rbx
	movq	80(%rsi) , %rcx
	adcq	$0       , %rcx
	movq	88(%rsi) , %rdx
	adcq	$0       , %rdx

  	rcrq 	$1, %rdx
  	rcrq 	$1, %rcx
  	rcrq 	$1, %rbx
  	rcrq 	$1, %rax
	rcrq 	$1, %r15
	rcrq 	$1, %r14
	rcrq 	$1, %r13
	rcrq 	$1, %r12
  	rcrq 	$1, %r11
  	rcrq 	$1, %r10
  	rcrq 	$1, %r9
  	rcrq 	$1, %r8

  	movq 	%rdx, 88(%rdi)
  	movq 	%rcx, 80(%rdi)
  	movq 	%rbx, 72(%rdi)
  	movq 	%rax, 64(%rdi)
  	movq 	%r15, 56(%rdi)
  	movq 	%r14, 48(%rdi)
  	movq 	%r13, 40(%rdi)
  	movq 	%r12, 32(%rdi)
  	movq 	%r11, 24(%rdi)
  	movq 	%r10, 16(%rdi)
  	movq 	%r9 ,  8(%rdi)
  	movq 	%r8 ,  0(%rdi)

	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	pop		%rbp
	pop		%rbx
	ret
