/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the multiple precision integer arithmetic multiplication
 * functions in ASM.
 *
 * @ingroup bn
 */

.text
.global bn_muls_low

/**
 * c = rdi, a = rsi, sa = rdx, digit = rcx, size = RLC_FP_DIGS
 */
bn_muls_low:
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    pushq   %rbp
    movq    %rcx, %rax
    shrq    $63, %rax
    xorq    %rdx, %rax     # sign = sa ^ sd;
    movq    %rcx, %rdx
    negq    %rcx
    cmovns  %rcx, %rdx     # rdx = (digit < 0 ? -digit : digit);
    xorq    %rcx, %rcx     # clear flags, create zero

    mulxq   0(%rsi), %r8, %r9

    mulxq   8(%rsi), %r11, %r10
    adcx    %r11, %r9

    mulxq   16(%rsi), %r12, %r11
    adcx    %r12, %r10

    mulxq   24(%rsi), %r13, %r12
    adcx    %r13, %r11

    mulxq   32(%rsi), %r14, %r13
    adcx    %r14, %r12

    mulxq   40(%rsi), %r15, %r14
    adcx    %r15, %r13

    mulxq   48(%rsi), %rbp, %r15
    adcx    %rbp, %r14

    mulxq   56(%rsi), %rsi, %rbp
    adcx    %rsi, %r15
    adcx    %rcx, %rbp

    negq    %rax
    xorq    %rax, %r8
    xorq    %rax, %r9
    xorq    %rax, %r10
    xorq    %rax, %r11
    xorq    %rax, %r12
    xorq    %rax, %r13
    xorq    %rax, %r14
    xorq    %rax, %r15
    xorq    %rax, %rbp

    negq    %rax
    addq    %rax, %r8
    adcx    %rcx, %r9
    adcx    %rcx, %r10
    adcx    %rcx, %r11
    adcx    %rcx, %r12
    adcx    %rcx, %r13
    adcx    %rcx, %r14
    adcx    %rcx, %r15
    adcx    %rcx, %rbp
    movq    %r8, 0(%rdi)
    movq    %r9, 8(%rdi)
    movq    %r10,16(%rdi)
    movq    %r11,24(%rdi)
    movq    %r12,32(%rdi)
    movq    %r13,40(%rdi)
    movq    %r14,48(%rdi)
    movq    %r15,56(%rdi)
    movq    %rbp, %rax

    popq    %rbp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    ret
