#!/usr/bin/env python3
"""Generates the x64-asm-Nl backend sources.

Usage: tools/relic-gen-x64.py N DIR

Writes macro.s and the assembly files of the backend for N limbs, from 4 to
12, Fp2 included up to 11, where DIR holds the C files and CMakeLists.txt of
the backend. The supported primes come from PRIMES below. Existing files keep
their license headers, and new files get the current year. Check a backend
with tools/relic-check-fp.c.
"""

import datetime
import os
import sys

# Primes per limb count: (FP_PRIME, hex of p, comment or None), with an
# optional condition that selects among primes of the same FP_PRIME.
PRIMES = {
	4: [
		(254, ("2523648240000001BA344D80000000086121000000000013A7000000"
			"00000013"), None),
		(255, ("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
			"FFFFFFED"), None),
	],
	5: [
		(315, ("4C23A02B586D650D3F7498BE97C5EAFDEC1D01AA27A1AE0421EE5DA5"
			"2BDE5026FE802FF40300001"), None),
		(317, ("1058CA226F60892CF28FC5A0B7F9D039169A61E684C73446D6F339E4"
			"3424BF7E8D512E565DAB2AAB"), None),
	],
	6: [
		(330, ("24C0832E1406555615B5BF00BAF1EE31FECF12A1C4947A0784F27BBE"
			"C8F954D9613523E67A53D5C40AD"), None),
		(354, ("1428C74EA98F0A5315F4B6BA1928ADE1A404A338E6E049BE3926C482"
			"E5DA80FED8491B9470948C8C6AAAB1D"), None),
		(377, ("1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FB"
			"A094800170B5D44300000008508C00000000001"), None),
		(381, ("1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0"
			"F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB"), None),
		(382, ("24009015183F94892D996CC179C6D1666F82CEFBE47879BBA6E58DBE"
			"43002A0609480097801382BE004E000000000013"), None),
		(383, ("5565569564AB6EB5A06DADC41FEA9284A0AD462CF365A511AC31B801"
			"696124F47A8C3F298A64852BDA371D6485AAB0AB"), None),
	],
	# fp_param_set_any() picks B12_446 when FP_QNRES is defined and BN_446
	# otherwise.
	7: [
		(446, ("3CDEE0FB28C5E535200FC34965AAD6400095A4B78A02FE320F75A64B"
			"BAC71602824E6DC3E23ACDEE56EE4528C573B5CC311C0026AAB0AAAB"),
			"B12_446", "defined(FP_QNRES)"),
		(446, ("2400000000000000002400000002D00000000D800000021C00000018"
			"00000000870000000B0400000057C00000015C000000132000000067"),
			"BN_446"),
	],
	8: [
		(455, ("55555955557955572AA00E0F95B49203003F665E3A5B1D56234BD939"
			"54FCB314B8B3DB9994ACE86D1BA6C589556B2AA956AAA00001800002"
			"AB"), None),
		(508, ("C33B72B87E5A44DF420B8A16E4727D4A5524C027B6231A491E008FC1"
			"21F07073D3F6EB93785360E0B1B3D5304D0957E6B5CC3A8F69C137AC"
			"D1CCCF628BC1B1D"), None),
		(509, ("155556FFFF39CA9BFCEDF2B4F9C0ECF6CB8AC8495D187E8C32EA0103"
			"E01090BB626E85BF7C18A0F0CFCB5C6071BAD3D2EE63BD076E8D9300"
			"A13D118DB8BFD2AB"), None),
		(510, ("31BEC371AB26D0A65A1673FA252B4DAAB32E21F17F8B0A6713BA8856"
			"149CDCB6BA09F4BACE3AC5588E97A75A70B54410393DDECB1D3C5517"
			"DD5F62C1A3044101"), None),
		(511, ("65B48E8F740F89BFFC8AB0D15E3E4C4AB42D083AEDC88C425AFBFCC6"
			"9322C9CDA7AAC6C567F35507516730CC1F0B4F25C2721BF457ACA835"
			"1B81B90533C6C87B"),
			"CTIDH-511, the prime selected by fp_param_set_any()."),
	],
	9: [
		(544, ("BB9DFD549299F1C803DDD5D7C05E7CC0373D9B1AC15B47AA5AA84626"
			"F33E58FE66943943049031AE4CA1D2719B3A84FA363BCD2539A5CD02"
			"C6F4B6B645A58C1085E14411"),
				"CP8-544, the Cocks-Pinch prime with embedding degree 8."),
		(569, ("11B4A027E91038F2C99CC114CD71608FE3BB690BDCF4F4BD2649EBC6"
			"50544C328081F9DC91FAF541D2ECA8F0498A59D19DB69EB4976E9752"
			"DC3A7B07CECAA81BBD3F32002E191D3"), None),
		(575, ("553D402AE2D5E4BC392BFDD23348B6A26137D053AA03007122696C9F"
			"B7A0951F7514F41A6C7018715E1D4944218EA2D852064509AC3491BF"
			"86CBB9BA813C985DF1E5CEF00AD97EFB"), None),
	],
	# fp_param_set_any() picks BLS12-P638 when FP_QNRES is defined and
	# KSS18-P638 otherwise. BN-P638 and SG18-P638 are not supported.
	10: [
		(638, ("3CB868653D300B3FE80015554DD25DB0FC01DCDE95D4000000631BBD"
			"421715013955555555529C005C75D6C2AB00000000000AC79600D2AB"
			"AAAAAAAAAAAAAA93EAF3FF000AAAAAAAAAAAAAAABEAB000B"),
			"BLS12-P638", "defined(FP_QNRES)"),
		(638, ("30344028BB5A934E659ABF42A9FC767BBB534653BDD64BE85CC33424"
			"93BEF7B5BD29B9F3F83809B40FBC237576EC5F251ACCD9ACD070D120"
			"DC8DBE9D09E2BBCFFB8F59E264FB7A71B0BE48934E64EB1D"), "KSS18-P638"),
	],
	12: [
		(768, ("FFFFFFE4FF4001423290395E476657BA172EC88A91CFC7D2BA1AF14A"
			"9BC88DBA6A6D9D80470079AE9AD532EA851862BD828EC90E320E3793"
			"31B6221831F61A721429BCDA53E20A8F9FBEDDEE98705380ACE2A128"
			"43C534B1591ADE1200800001"), None),
		(766, ("3FFFB8002607F379C2E122127943E41E89F38FC6E7249EF167D35D38"
			"9C7BD43CDC0F8D8300A6748A4C8C62B406D882C8A2902CAC0A117EAD"
			"04A837318C7897B6C81A3A94170A2E5A211730168CD3106CFCBC4220"
			"020A6592F45D1E791E054605"),
				"AFG16-766, the prime picked for 766 bits. K16_766 is not "
					"supported."),
		(765, ("166A30BEAF4CE221BC5664C6F237BCB4D4A66E04AA631EEA1629227B"
			"B6527E4EFE00400021385D1A7071D6BA0697D5A12C9088558A226AF0"
			"93D3AA2586A9BB7B0140000000000000000000000000000000000000"
			"38223FF01000EFC080000001"), "FM16-765"),
	],
	11: [
		(672, ("9401FF90F28BFFB0C610FB10BF9E0FEFD59211629A7991563C5E468D"
			"43EC9CFE1549FD59C20AB5B9A7CDA7F27A0067B8303EEB4B31555CF4"
			"F24050ED155555CD7FA7A5F8AAAAAAAD47EDE1A6AAAAAAAAB69E6DCB"),
				"CP6-672, the Cocks-Pinch prime with embedding degree 6."),
	],
}

# Primes that are 1 mod 4 with Fp2 in assembly, by FP_PRIME, and q for the
# quadratic non-residue -q that fp_prime_init() picks, so that u^2 = -q. The
# others have Fp2 in assembly only with FP_QNRES, where u^2 = -1.
QNRS = {544: 5}


def names(n, p="Z"):
	return ["%s%d" % (p, i) for i in range(n)]


def refs(xs):
	return ["\\" + x for x in xs]


def args(*xs):
	out = []
	for x in xs:
		out += x if isinstance(x, list) else [x]
	return ", ".join(out)


def macro(name, params, body):
	return [".macro %s %s" % (name, args(params))] + body + [".endm"]


def consts(p):
	"""Returns the limbs, U0 and the constants of fp_mul1_low for p."""
	n = (p.bit_length() + 63) // 64
	limbs = [(p >> (64 * i)) & ((1 << 64) - 1) for i in range(n)]
	u0 = (-pow(p, -1, 1 << 64)) % (1 << 64)
	s = p.bit_length() - 1
	bar = (1 << (p.bit_length() + 63)) // p
	assert bar < (1 << 64)
	return limbs, u0, bar, s % 64

# The license header, shared by all files, with the year of a new file.
LICENSE = '''/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) %s RELIC Authors
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
'''

# The documentation after the license in each file.
DOCS = {
	'macro.s': '''
#include "relic_fp_low.h"

/**
 * @file
 *
 * Implementation of low-level prime field multiplication.
 *
 * @ingroup fp
 */

''',
	'relic_fp_add_low.s': '''
/**
 * @file
 *
 * Implementation of the low-level prime field addition and subtraction
 * functions.
 *
 * @ingroup fp
 */
''',
	'relic_fp_mul_low.s': '''
/**
 * @file
 *
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup fp
 */
''',
	'relic_fp_rdc_low.s': '''
/**
 * @file
 *
 * Implementation of low-level prime field modular reduction.
 *
 * @ingroup fp
 */
''',
	'relic_fp_sqr_low.s': '''
/**
 * @file
 *
 * Implementation of the low-level prime field squaring functions.
 *
 * @ingroup fp
 */
''',
	'relic_fpx_mul_low.s': '''
/**
 * @file
 *
 * Implementation of the low-level quadratic extension field multiplication.
 *
 * @ingroup fpx
 */
''',
	'relic_fpx_sqr_low.s': '''
/**
 * @file
 *
 * Implementation of the low-level quadratic extension field squaring.
 *
 * @ingroup fpx
 */
''',
	'relic_fp_shift_low.s': '''
/**
 * @file
 *
 * Implementation of the low-level prime field shifting functions.
 *
 * @ingroup fp
 */
''',
}

# The macros for addition and subtraction with carries.
CARRY_MACROS = '''.macro ADD1 i j
	movq	8*\\i(%rsi), %r10
	adcq	$0, %r10
	movq	%r10, 8*\\i(%rdi)
	.if \\i - \\j
		ADD1 "(\\i + 1)" \\j
	.endif
.endm

.macro ADDN i j
	movq	8*\\i(%rdx), %r11
	adcq	8*\\i(%rsi), %r11
	movq	%r11, 8*\\i(%rdi)
	.if \\i - \\j
		ADDN "(\\i + 1)" \\j
	.endif
.endm

.macro SUB1 i j
	movq	8*\\i(%rsi),%r10
	sbbq	$0, %r10
	movq	%r10,8*\\i(%rdi)
	.if \\i - \\j
		SUB1 "(\\i + 1)" \\j
	.endif
.endm

.macro SUBN i j
	movq	8*\\i(%rsi), %r8
	sbbq	8*\\i(%rdx), %r8
	movq	%r8, 8*\\i(%rdi)
	.if \\i - \\j
		SUBN "(\\i + 1)" \\j
	.endif
.endm

.macro DBLN i j
	movq	8*\\i(%rsi), %r8
	adcq	%r8, %r8
	movq	%r8, 8*\\i(%rdi)
	.if \\i - \\j
		DBLN "(\\i + 1)" \\j
	.endif
.endm

'''


# The callee-saved registers, in the order they are saved.
CALLEE = ["%r12", "%r13", "%r14", "%r15", "%rbx", "%rbp"]

# All registers but %rsp, caller-saved first so that fewer need saving.
ORDER = ["%r8", "%r9", "%r10", "%r11", "%rax", "%rcx", "%rdx", "%rsi",
	"%rdi"] + CALLEE


def regs(*taken):
	"""The registers in ORDER besides those taken."""
	return [x for x in ORDER if x not in taken]


def saves(regs):
	"""Saves and restores the callee-saved registers that a function uses,
	since only those must be preserved."""
	used = [x for x in CALLEE if x in regs]
	push = ["\tpush\t%s" % x for x in used]
	return (push + [""] if push else [],
		["\tpop\t\t%s" % x for x in reversed(used)] + ["\tret"])


def header(name):
	return LICENSE % datetime.date.today().year + DOCS[name]


def kept_header(path, name):
	"""Returns the license and documentation of an existing file, so that it
	keeps its year, or ours for a new file."""
	if os.path.exists(path):
		src = open(path).read()
		end = src.index(" */\n", src.index("@file")) + 4
		return src[:end] + ("\n" if name == "macro.s" else "")
	return header(name)


def file_head(g):
	return ['#include "relic_fp_low.h"', '#include "macro.s"', "", ".text", ""]


def function(name, regs, body, frame=0, pushdi=False):
	"""A function that saves the callee-saved registers in regs, then %rdi if
	pushdi, and reserves frame bytes of stack."""
	push, pop = saves(regs)
	o = ["cdecl(%s):" % name] + push[:-1]
	if pushdi:
		o.append("\tpush\t%rdi")
	if frame:
		o.append("\tsubq\t$%d, %%rsp" % frame)
	if len(o) > 1 and body[0] != "":
		o.append("")
	o += body + [""]
	if frame:
		o.append("\taddq\t$%d, %%rsp" % frame)
	return o + pop


def prime_block(n):
	"""The constants of the primes supported with n limbs, for macro.s."""
	b = []
	bits = []
	for k, e in enumerate(PRIMES[n]):
		limbs, u0, bar, bars = consts(int(e[1], 16))
		assert len(limbs) == n
		b.append(("#if" if k == 0 else "#elif") + " FP_PRIME == %d" % e[0] +
			(" && " + e[3] if len(e) > 3 else ""))
		for i, l in enumerate(limbs):
			b.append("#define P%d\t0x%016X" % (i, l))
		b.append("#define U0\t0x%016X" % u0)
		b.append("#define BAR\t0x%016X" % bar)
		b.append("#define BARS\t%d" % bars)
		if e[0] in QNRS:
			b.append("#define QNR\t%d" % QNRS[e[0]])
		if str(e[0]) not in bits:
			bits.append(str(e[0]))
	b.append("#else")
	bits.sort(key=int)
	last = bits[-1]
	if len(bits) > 1:
		last = ", ".join(bits[:-1]) + " or " + last
	b.append('#error "x64-asm-%dl supports only FP_PRIME = %s."' % (n, last))
	b.append("#endif")
	return "\n".join(b) + "\n\n"

CDECL = """#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif
"""

NOEXEC = """#if defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif
"""


def macro_s(g, out, guards, defines, parts):
	"""Writes macro.s: the constants of the primes, cdecl, the guards, the note
	for a non-executable stack, the defines and the macros, where guards and
	defines are blocks of lines."""
	path = os.path.join(out, "macro.s")
	text = kept_header(path, "macro.s") + prime_block(g.n) + CDECL + "\n"
	text += "".join(x + "\n" for x in guards) + NOEXEC + "\n"
	text += "".join(x + "\n" for x in defines) + ".text\n\n" + CARRY_MACROS
	text += "\n\n".join("\n".join(x) for x in parts) + "\n"
	open(path, "w").write(text)


def write_files(g, out, files):
	"""Writes the given (name, generator) files, keeping existing headers."""
	for name, fn in files:
		path = os.path.join(out, name)
		head = kept_header(path, name)
		open(path, "w").write(head + "\n" + "\n".join(fn(g)) + "\n")


def mul1(n):
	"""fp_mul1_low(c, a, digit < 2^63): c = a * digit mod p, in constant time.
	q = floor(floor(d / 2^(|p| - 1)) * BAR / 2^64) is at most 2 below
	floor(d / p) for d = a * digit, so d - q * p < 3p, and p is subtracted
	twice, keeping the difference when there is no borrow. The n + 1 words of
	d stay in registers while they fit beside a temporary, with the lowest
	ones on the stack otherwise. q * p is built on the OF chain and added
	complemented on the CF chain, since sbb would clobber OF. The final
	subtractions keep copies in the free registers and back the other words
	up in c, as in FINALC. The quotient reads words n - 1 and n of d. When
	3p < 2^(64n) for every prime, d - q * p is computed modulo 2^(64n), and
	the top word is only needed for q."""
	for e in PRIMES[n]:
		assert (int(e[1], 16).bit_length() - 1) // 64 == n - 1
	mod = all(3 * int(e[1], 16) < 1 << (64 * n) for e in PRIMES[n])
	top = n if mod else n + 1
	pool = regs("%rax", "%rdx", "%rsi")
	s = max(0, n + 2 - len(pool))
	d = [None] * s + pool[:n + 1 - s]
	t2 = pool[n + 1 - s]
	slot = lambda k: "%d(%%rsp)" % (8 + 8 * k)
	o = ["\tmovq\t%rdi, 0(%rsp)"]
	# d = a * digit, with the high halves alternating in %rax and t2. The low
	# word of a spilled product goes through the register of the top word.
	hi = ["%rax", t2]
	for k in range(n):
		lo = d[k] or d[n]
		h = d[n] if k == n - 1 else hi[k % 2]
		o.append("\tmulxq\t%d(%%rsi), %s, %s" % (8 * k, lo, h))
		if k > 0:
			o.append("\t%s\t%s, %s" % ("addq" if k == 1 else "adcq",
				hi[(k - 1) % 2], lo))
		if d[k] is None:
			o.append("\tmovq\t%s, %s" % (lo, slot(k)))
	o += ["\tadcq\t$0, %s" % d[n], "", "\tmovq\t%s, %%rax" % d[n - 1],
		"\tshrdq\t$BARS, %s, %%rax" % d[n], "\tmovq\t$BAR, %rdx",
		"\tmulxq\t%rax, %rax, %rdx", ""]
	# Subtract q * p. When the high halves fit in the free registers, the low
	# halves and then the high halves go in two borrow chains. Otherwise
	# d += ~(q * p) + 1, with the words of q * p on OF and the sum on CF,
	# so that no high half is kept.
	hs = [t2, "%rsi"] + pool[n + 2 - s:]
	if len(hs) >= top - 1:
		for k in range(n):
			hk = hs[k] if k < top - 1 else "%rdx"
			o += ["\tmulxq\tp%d(%%rip), %%rax, %s" % (k, hk),
				"\t%s\t%%rax, %s" % ("subq" if k == 0 else "sbbq", d[k])]
		if not mod:
			o.append("\tsbbq\t$0, %s" % d[n])
		o.append("")
		o += ["\t%s\t%s, %s" % ("subq" if k == 0 else "sbbq", hs[k], d[k + 1])
			for k in range(top - 1)]
	else:
		h = [t2, "%rsi"]
		o += ["\txorq\t%rax, %rax", "\tstc"]
		for k in range(top):
			if k < n:
				o.append("\tmulxq\tp%d(%%rip), %%rax, %s" % (k, h[k % 2]))
				if k > 0:
					o.append("\tadox\t%s, %%rax" % h[(k - 1) % 2])
				w = "%rax"
			else:
				w = h[(n - 1) % 2]
				o += ["\tmovq\t$0, %rax", "\tadox\t%%rax, %s" % w]
			o.append("\tnotq\t%s" % w)
			if d[k] is None:
				o += ["\tadcx\t%s, %s" % (slot(k), w),
					"\tmovq\t%s, %s" % (w, slot(k))]
			else:
				o.append("\tadcx\t%s, %s" % (w, d[k]))
	# Two conditional subtractions of p, with copies for the spilled words,
	# the top word and then the highest words, and the rest backed up in c.
	free = ["%rax", "%rdx", "%rsi", t2] + pool[n + 2 - s:]
	if mod:
		free.append(d[n])
	need = [k for k in range(top) if d[k] is None] + [k for k in
		range(top - 1, s - 1, -1)]
	cp = None
	if len(free) < top:
		cp = free.pop()
	copy = {}
	for k in need:
		if k not in copy and free:
			copy[k] = free.pop(0)
	if cp:
		o.append("\tmovq\t0(%%rsp), %s" % cp)
	o += ["", "\t.rept 2"]
	for k in range(top):
		op = "subq" if k == 0 else "sbbq"
		src = "$0" if k == n else "p%d(%%rip)" % k
		if k in copy:
			o.append("\tmovq\t%s, %s" % (d[k] or slot(k), copy[k]))
			o.append("\t%s\t%s, %s" % (op, src, copy[k]))
		else:
			o.append("\tmovq\t%s, %d(%s)" % (d[k], 8 * k, cp))
			o.append("\t%s\t%s, %s" % (op, src, d[k]))
	for k in range(top):
		if k in copy and d[k] is None:
			o += ["\tcmovc\t%s, %s" % (slot(k), copy[k]),
				"\tmovq\t%s, %s" % (copy[k], slot(k))]
		elif k in copy:
			o.append("\tcmovnc\t%s, %s" % (copy[k], d[k]))
		else:
			o.append("\tcmovc\t%d(%s), %s" % (8 * k, cp, d[k]))
	o.append("\t.endr")
	if not cp:
		cp = copy.pop(top - 1)
		o.append("\tmovq\t0(%%rsp), %s" % cp)
	o.append("")
	for k in range(n):
		if d[k] is None:
			o += ["\tmovq\t%s, %%rax" % slot(k),
				"\tmovq\t%%rax, %d(%s)" % (8 * k, cp)]
		else:
			o.append("\tmovq\t%s, %d(%s)" % (d[k], 8 * k, cp))
	used = set(x for x in CALLEE if any(x in line for line in o))
	return function("fp_mul1_low", used, o, frame=8 + 8 * s)


POOL = regs("%rdx", "%rsi", "%rdi")

CALLER = regs("%rsi", "%rdi")


def add_low(g):
	n = g.n
	full = g.full
	# Besides %rdi, 14 registers hold a result and its copy once the operands
	# are loaded, so small fields reduce without storing and reloading. The
	# addition also needs a carry when p fills the top bit. Caller-saved
	# registers come first, so fewer need saving.
	add_reg = 2 * n + full <= 14
	sub_reg = 2 * n <= 14
	r = POOL[:n]
	spare = ["%rdx", "%rsi"] + [x for x in POOL if x not in r]
	add_extra = spare[:n + full] if add_reg else []
	sub_extra = spare[:n] if sub_reg else []
	carry = spare[n] if add_reg and full else "%rsi"
	o = ['#include "relic_fp_low.h"', '#include "macro.s"', "",
		"#if defined(__APPLE__)", ".section __TEXT,__const", "#else",
		".section .rodata", "#endif", "", ".p2align 3"]
	o += ["p%d: .quad P%d" % (i, i) for i in range(n)] + [""]
	o += [".global "
		"p%d" % i for i in range(n)] + ["", "#if RLC_OPSYS != RLC_WINDOWS", ""]
	o += [".hidden p%d" % i for i in range(n)] + ["", "#endif", "", ".text", ""]
	fns = ["add1", "addn", "addm", "addd", "addc", "sub1", "subn", "subm",
		"subd", "subc", "negm", "dbln", "dblm", "hlvm", "hlvd"]
	o += [".global cdecl(fp_%s_low)" % f for f in fns] + [""]

	def keep_carry():
		if not full:
			return []
		# p fills the top bit, so keep the carry of the sum.
		return [g.iffull(),
			"\tmovq\t$0, %s" % carry, "\tadcq\t$0, %s" % carry, "#endif"]

	def correct(base):
		"""Subtracts p from [carry:r], keeping the difference if it does not
		borrow, and stores the result at base(%rdi)."""
		s = []
		if add_reg:
			c = add_extra
			for i in range(n):
				s.append("\tmovq\t%s, %s" % (r[i], c[i]))
			s.append("\tsubq\tp0(%%rip), %s" % c[0])
			for i in range(1, n):
				s.append("\tsbbq\tp%d(%%rip), %s" % (i, c[i]))
			if full:
				s += [g.iffull(), "\tsbbq\t$0, %s" % carry, "#endif"]
			for i in range(n):
				s.append("\tcmovnc\t%s, %s" % (c[i], r[i]))
			for i in range(n):
				s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
			return s
		for i in range(n):
			s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
		s.append("\tsubq\tp0(%%rip), %s" % r[0])
		for i in range(1, n):
			s.append("\tsbbq\tp%d(%%rip), %s" % (i, r[i]))
		if full:
			s += [g.iffull(), "\tsbbq\t$0, %rsi", "#endif"]
		for i in range(n):
			s.append("\tcmovc\t%d(%%rdi), %s" % (base + 8 * i, r[i]))
		for i in range(n):
			s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
		return s

	def addback(base):
		"""Adds p to the difference in r if it borrowed, and stores the result
		at base(%rdi)."""
		if sub_reg:
			# The mask in c[0] covers the other words before becoming p0 & mask.
			c = sub_extra
			s = ["", "\tsbbq\t%s, %s" % (c[0], c[0])]
			for i in range(1, n):
				s.append("\tmovq\tp%d(%%rip), %s" % (i, c[i]))
				s.append("\tandq\t%s, %s" % (c[0], c[i]))
			s.append("\tandq\tp0(%%rip), %s" % c[0])
			s.append("\taddq\t%s, %s" % (c[0], r[0]))
			for i in range(1, n):
				s.append("\tadcq\t%s, %s" % (c[i], r[i]))
			for i in range(n):
				s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
			return s
		# Without registers for the masked words, SF keeps the borrow while
		# adcx adds p word by word, through %rdx and %rsi in turn.
		s = ["", "\tsbbq\t%rsi, %rsi", "\ttestq\t%rsi, %rsi"]
		for i in range(n):
			t = ("%rdx", "%rsi")[i % 2]
			s += ["\tmovq\t$0, %s" % t, "\tcmovs\tp%d(%%rip), %s" % (i, t),
				"\tadcx\t%s, %s" % (t, r[i])]
		for i in range(n):
			s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
		return s

	# fp_add1_low and fp_addn_low
	o += ["cdecl(fp_add1_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r10",
		"\taddq\t%rdx, %r10", "\tmovq\t%r10, 0(%rdi)", "",
		"\tADD1 1 (RLC_FP_DIGS - 1)", "\tadcq\t$0, %rax", "", "\tret", ""]
	o += ["cdecl(fp_addn_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rdx), %r11",
		"\taddq\t0(%rsi), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tADDN\t1 (RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "", "\tret", ""]
	# fp_addm_low
	o += ["cdecl(fp_addm_low):"] + saves(r + add_extra)[0]
	o.append("\tmovq\t0(%%rdx), %s" % r[0])
	o.append("\taddq\t0(%%rsi), %s" % r[0])
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rdx), %s" % (8 * i, r[i]))
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * i, r[i]))
	o += keep_carry() + [""] + correct(0) + [""]
	o += saves(r + add_extra)[1] + [""]
	# fp_addd_low
	o += ["cdecl(fp_addd_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rdx), %r11",
		"\taddq\t0(%rsi), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tADDN\t1 (2 * RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "\tret", ""]
	# fp_addc_low
	o += ["cdecl(fp_addc_low):"] + saves(r + add_extra)[0]
	o += ["\tmovq\t0(%rdx), "
		"%r11", "\taddq\t0(%rsi), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tADDN\t1 (RLC_FP_DIGS - 1)", ""]
	for i in range(n):
		o.append("\tmovq\t%d(%%rdx), %s" % (8 * (n + i), r[i]))
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * (n + i), r[i]))
	o += keep_carry() + [""] + correct(8 * n) + [""]
	o += saves(r + add_extra)[1] + [""]
	# fp_sub1_low and fp_subn_low
	o += ["cdecl(fp_sub1_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r10",
		"\tsubq\t%rdx, %r10", "\tmovq\t%r10, 0(%rdi)", "",
		"\tSUB1\t1 (RLC_FP_DIGS - 1)", "\tadcq\t$0, %rax", "", "\tret", ""]
	o += ["cdecl(fp_subn_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r11",
		"\tsubq\t0(%rdx), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tSUBN\t1 (RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "", "\tret", ""]
	# fp_subm_low
	o += ["cdecl(fp_subm_low):"] + saves(r + sub_extra)[0]
	o.append("\tmovq\t0(%%rsi), %s" % r[0])
	o.append("\tsubq\t0(%%rdx), %s" % r[0])
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, r[i]))
		o.append("\tsbbq\t%d(%%rdx), %s" % (8 * i, r[i]))
	o += addback(0) + [""] + saves(r + sub_extra)[1] + [""]
	# fp_subd_low
	o += ["cdecl(fp_subd_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r8",
		"\tsubq\t0(%rdx), %r8", "\tmovq\t%r8, 0(%rdi)", "",
		"\tSUBN\t1 (2 * RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "\tret", ""]
	# fp_subc_low
	o += ["cdecl(fp_subc_low):"] + saves(r + sub_extra)[0]
	o += ["\tmovq\t0(%rsi), "
		"%r8", "\tsubq\t0(%rdx), %r8", "\tmovq\t%r8, 0(%rdi)", "",
		"\tSUBN\t1 (RLC_FP_DIGS - 1)", ""]
	for i in range(n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * (n + i), r[i]))
		o.append("\tsbbq\t%d(%%rdx), %s" % (8 * (n + i), r[i]))
	o += addback(8 * n) + [""] + saves(r + sub_extra)[1] + [""]
	# fp_negm_low: c = p - a if a != 0, else 0. Only %rsi is read, so %rdx
	# joins the caller-saved registers.
	nr = CALLER[:n]
	o += ["cdecl(fp_negm_low):"] + saves(nr)[0]
	for i in range(1, n):
		o.append("\txorq\t%s, %s" % (nr[i], nr[i]))
	o.append("\tmovq\t0(%%rsi), %s" % nr[0])
	for i in range(1, n):
		o.append("\torq\t%d(%%rsi), %s" % (8 * i, nr[0]))
	o.append("\ttestq\t%s, %s" % (nr[0], nr[0]))
	for i in range(n):
		o.append("\tcmovnz\tp%d(%%rip), %s" % (i, nr[i]))
	o.append("\tsubq\t0(%%rsi), %s" % nr[0])
	o.append("\tmovq\t%s, 0(%%rdi)" % nr[0])
	for i in range(1, n):
		o.append("\tsbbq\t%d(%%rsi), %s" % (8 * i, nr[i]))
		o.append("\tmovq\t%s, %d(%%rdi)" % (nr[i], 8 * i))
	o += [""] + saves(nr)[1] + [""]
	# fp_dbln_low
	o += ["cdecl(fp_dbln_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r8",
		"\taddq\t%r8, %r8", "\tmovq\t%r8, 0(%rdi)", "",
		"\tDBLN 1 (RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "\tret", ""]
	# fp_dblm_low
	o += ["cdecl(fp_dblm_low):"] + saves(r + add_extra)[0]
	o.append("\tmovq\t0(%%rsi), %s" % r[0])
	o.append("\taddq\t%s, %s" % (r[0], r[0]))
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, r[i]))
		o.append("\tadcq\t%s, %s" % (r[i], r[i]))
	o += keep_carry() + [""] + correct(0) + [""]
	o += saves(r + add_extra)[1] + [""]
	# fp_hlvm_low: c = (a + (a odd ? p : 0)) / 2, with the carry shifted in.
	h = POOL[:n]
	o += ["cdecl(fp_hlvm_low):"] + saves(h)[0] + [
		"\tmovq\t$1, %rdx", "\tandq\t0(%rsi), %rdx", "\tmovq\t$0, %rdx"]
	for i in range(n):
		o.append("\tmovq\t$P%d, %s" % (i, h[i]))
	for i in range(n):
		o.append("\tcmovz\t%%rdx, %s" % h[i])
	o.append("")
	o.append("\taddq\t0(%%rsi), %s" % h[0])
	for i in range(1, n):
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * i, h[i]))
	o.append("")
	for i in reversed(range(n)):
		o.append("\trcrq\t$1, %s" % h[i])
	o.append("")
	for i in range(n):
		o.append("\tmovq\t%s, %d(%%rdi)" % (h[i], 8 * i))
	o += ["\txorq\t%rax, %rax", ""] + saves(h)[1] + [""]
	# fp_hlvd_low: the same over 2n digits, adding p to the low half. Besides
	# %rdi, 14 registers hold digits, with %rsi taking the last digit read, so
	# only the lowest 2n - 14 digits of the high half go through memory.
	lo = POOL[:n]
	hi = (["%rdx"] + POOL[n:] + ["%rsi"])[:n]
	mem = max(0, 2 * n - 14)
	hi = [None] * mem + hi[:n - mem]
	tmp = hi[mem]
	regs = lo + [x for x in hi if x]
	o += ["cdecl(fp_hlvd_low):"] + saves(regs)[0] + [
		"\tmovq\t$1, %s" % tmp, "\tandq\t0(%%rsi), %s" % tmp,
		"\tmovq\t$0, %s" % tmp]
	for i in range(n):
		o.append("\tmovq\t$P%d, %s" % (i, lo[i]))
	for i in range(n):
		o.append("\tcmovz\t%s, %s" % (tmp, lo[i]))
	o.append("")
	o.append("\taddq\t0(%%rsi), %s" % lo[0])
	for i in range(1, n):
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * i, lo[i]))
	for i in range(n):
		d = 8 * (n + i)
		x = hi[i] or tmp
		o.append("\tmovq\t%d(%%rsi), %s" % (d, x))
		o.append("\tadcq\t$0, %s" % x)
		if not hi[i]:
			o.append("\tmovq\t%s, %d(%%rdi)" % (x, d))
	o.append("")
	for i in reversed(range(2 * n)):
		x = lo[i] if i < n else hi[i - n]
		o.append("\trcrq\t$1, %s" % (x or "%d(%%rdi)" % (8 * i)))
	o.append("")
	for i in range(2 * n):
		x = lo[i] if i < n else hi[i - n]
		if x:
			o.append("\tmovq\t%s, %d(%%rdi)" % (x, 8 * i))
	o += [""] + saves(regs)[1]
	return o


def shift_low(g):
	"""Shifts the digits in place from one end, so c may alias a."""
	n = g.n
	if n <= 6:
		return shift_low_regs(g)
	o = file_head(g) + [".global cdecl(fp_rsh1_low)",
		".global cdecl(fp_lsh1_low)", "", "cdecl(fp_rsh1_low):",
		"\tmovq\t0(%rsi), %r8", "\tmovq\t%r8, %rax",
		"\tandq\t$1, %rax"]
	cur, nxt = "%r8", "%r9"
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, nxt))
		o.append("\tshrd\t$1, %s, %s" % (nxt, cur))
		o.append("\tmovq\t%s, %d(%%rdi)" % (cur, 8 * (i - 1)))
		cur, nxt = nxt, cur
	o += ["\tshrq\t$1, "
		"%s" % cur, "\tmovq\t%s, %d(%%rdi)" % (cur, 8 * (n - 1)), "\tret", "",
		"cdecl(fp_lsh1_low):", "\tmovq\t%d(%%rsi), %%r8" % (8 * (n - 1)),
			"\tmovq\t%r8, %rax",
		"\tshrq\t$63, %rax"]
	cur, nxt = "%r8", "%r9"
	for i in range(n - 2, -1, -1):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, nxt))
		o.append("\tshld\t$1, %s, %s" % (nxt, cur))
		o.append("\tmovq\t%s, %d(%%rdi)" % (cur, 8 * (i + 1)))
		cur, nxt = nxt, cur
	o += ["\tshlq\t$1, %s" % cur, "\tmovq\t%s, 0(%%rdi)" % cur, "\tret"]
	return o


def shift_low_regs(g):
	"""Shifts with all digits loaded first, which pipelines better while they
	fit in caller-saved registers. Loading everything first keeps c = a safe."""
	n = g.n
	r = regs("%rax", "%rsi", "%rdi")[:n]
	o = file_head(g) + [".global cdecl(fp_rsh1_low)",
		".global cdecl(fp_lsh1_low)", "", "cdecl(fp_rsh1_low):"]
	for i in range(n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, r[i]))
	o += ["\tmovq\t%s, %%rax" % r[0], "\tandq\t$1, %rax"]
	for i in range(n - 1):
		o.append("\tshrd\t$1, %s, %s" % (r[i + 1], r[i]))
	o.append("\tshrq\t$1, %s" % r[n - 1])
	for i in range(n):
		o.append("\tmovq\t%s, %d(%%rdi)" % (r[i], 8 * i))
	o += ["\tret", "", "cdecl(fp_lsh1_low):"]
	for i in range(n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, r[i]))
	o += ["\tmovq\t%s, %%rax" % r[n - 1], "\tshrq\t$63, %rax"]
	for i in range(n - 1, 0, -1):
		o.append("\tshld\t$1, %s, %s" % (r[i - 1], r[i]))
	o.append("\tshlq\t$1, %s" % r[0])
	for i in range(n):
		o.append("\tmovq\t%s, %d(%%rdi)" % (r[i], 8 * i))
	o.append("\tret")
	return o


# ------------------------------------------------------ design of x64-asm-6l
# Backends from 4 to 12 limbs keep the accumulator and two temporaries, one
# at 12, in registers, with the macros below taking registers as arguments.
# The pointers stay in registers too up to 8 limbs.
# Accumulator and temporaries of the multiplication, in order.
ACC6 = regs("%rax", "%rcx", "%rdx", "%rsi", "%rdi")


class Backend:
	"""A backend for 4 to 12 digits: an accumulator of n + 1 registers and two
	temporaries, one at 12, with the pointers in registers up to 8 digits."""
	def __init__(self, n):
		self.n = n
		# Whether some supported prime fills the top bit of the top limb.
		self.full = any(e[0] == 64 * n for e in PRIMES[n])
		# Squaring keeps a^2 in registers while it fits beside rdx and the
		# two temporaries, and writes c through %rdi while that leaves it free.
		self.sqreg = 2 * n + 3 <= 15
		self.sqrdi = 2 * n + 4 <= 15
		# fp_sqrm_low as an interleaved product of a by itself.
		self.sqrmul = n == 4
		# From 8 digits, %rax is a temporary and T1 gives the zero: the
		# products keep T1 = 0 and use a single temporary, as a row puts each
		# high half in the register that becomes its top word, and a
		# Montgomery step reuses the cancelled low word, taking its carry from
		# an all-ones constant. From 10, MULM uses an adc chain instead of a
		# zero register.
		self.onet = n >= 8
		self.mulmadc = n >= 10
		# From 9 digits, a is copied to the stack, freeing %rsi; at 10, the
		# pointer to c is on the stack too, and stores go through T0.
		self.acopy = n >= 9
		self.cslot = n >= 10
		# At 11, b goes to the stack too, and the reductions keep the pointer
		# to c on the stack, loading it into T0 for the final subtraction.
		self.bcopy = n >= 11
		# At 12, T1 goes too: the zero is in memory, Montgomery steps of the
		# reduction reuse the cancelled low word as well, and there is no Fp2,
		# whose primes are not 3 mod 8. The final subtractions take the top
		# word too, since a value below 2p reaches 2^(64n) when p fills the
		# top bit.
		self.wide = n >= 12
		# Whether some prime has u^2 = -q for q > 1, chosen at assembly time
		# by FP2_QNR. Fp2 then multiplies by q x b1, kept in the scratch, and
		# adds c1 to c0 after squaring, with c0 at %rdi.
		self.qnr = any(e[0] in QNRS for e in PRIMES[n])
		assert not (self.qnr and self.cslot)
		if n <= 7:
			z, t0, t1 = ACC6[:n + 1], ACC6[n + 1], ACC6[n + 2]
		elif n == 8:
			z, t0, t1 = ACC6[:9], "%rbp", "%rax"
		elif n == 9:
			z, t0, t1 = ACC6, "%rsi", "%rax"
		elif n == 10:
			z, t0, t1 = ACC6[:8] + ["%rax", "%rbx", "%rbp"], "%rsi", "%rdi"
		elif n == 11:
			z = ACC6[:8] + ["%rax", "%rbx", "%rbp", "%rcx"]
			t0, t1 = "%rsi", "%rdi"
		else:
			z = ACC6[:8] + ["%rax", "%rbx", "%rbp", "%rcx", "%rdi"]
			t0, t1 = "%rsi", None
		self.z, self.t0, self.t1 = z, t0, t1
		# Registers free at the end of a product, besides the accumulator.
		self.fixed = [x for x in ("%rax", "%rdx", "%rsi", "%rcx")
			if x not in z + [t0, t1]]
		# Register copies of the final subtraction; FINALC keeps the other
		# words at the destination.
		self.m = 1 if self.wide else min(n, 14 - n)
		# The temporaries of a product.
		self.t = [x for x in (t0, t1) if x]

	def iffull(self):
		return "#if FP_PRIME == %d" % (64 * self.n)

	def full_only(self, yes, no=()):
		"""Lines for the prime that fills the top bit, and the others."""
		return [self.iffull()] + yes + (["#else"] + list(no) if no else []) + [
			"#endif"]

	def zr(self):
		"""The zero of MULADD1 and MULRDC1."""
		return "zero(%rip)" if self.wide else "\\T1"

	def tparams(self):
		return ["T0"] if self.wide else ["T0", "T1"]

	def window(self, i):
		"""The n + 1 accumulator registers at step i of a product."""
		n = self.n
		z = refs(names(n + 1))
		return [z[(i + j) % (n + 1)] for j in range(n + 1)]

	def copies(self):
		"""Registers free at the end of a product, for FINALC."""
		n = self.n
		if self.wide:
			return ["%rdx"]
		c = ["\\Z%d" % (n - 1)] + ([] if self.cslot else ["\\T0"]) + ["\\T1"]
		return (c + self.fixed)[:self.m]

	def cparam(self):
		return ["C"] if self.cslot else []

	def cbase(self):
		return "\\T0" if self.cslot else "%rdi"

	def loadc(self):
		return ["\tmovq\t\\C, \\T0"] if self.cslot else []

	def clear(self):
		"""Clears the flags, keeping %rax = 0 when MULADD needs it."""
		if self.wide:
			return "\txorq\t\\T0, \\T0"
		return "\txorq\t\\T1, \\T1" if self.onet else "\txorq\t%rax, %rax"

	def finalc_call(self, values, copies, dest="0(%rdi)", top=None):
		assert len(copies) == self.m
		assert (top is not None) == self.wide
		return "\tFINALC\t%s" % args(values, copies, dest, [top] if top else [])

	def mulm(self):
		"""[Z0:Zn] <- a0 x b for a = 0+A and b = 0+B, with Zn+1 as scratch.
		The adox version also clears %rax and the flags."""
		n = self.n
		z = refs(names(n + 2))
		if self.mulmadc:
			b = ["\tmovq\t0+\\A, %rdx", "\tmulx\t0+\\B, \\Z0, \\Z1"]
			for k in range(1, n):
				b += ["\tmulx\t%d+\\B, %s, %s" % (8 * k, z[n + 1], z[k + 1]),
					"\t%s\t%s, %s" % ("addq" if k == 1 else "adcq", z[n + 1],
						z[k])]
			b.append("\tadcq\t$0, %s" % z[n])
		else:
			b = ["\tmovq\t0+\\A, %rdx", "\tmulx\t0+\\B, \\Z0, \\Z1",
				"\txorq\t%rax, %rax"]
			for k in range(1, n):
				b += ["\tmulx\t%d+\\B, %s, %s" % (8 * k, z[k + 2], z[k + 1]),
					"\tadox\t%s, %s" % (z[k + 2], z[k])]
			b.append("\tadox\t%%rax, %s" % z[n])
		return macro("MULM", ["A", "B"] + names(n + 2), b)

	def muladd(self):
		"""[Z0:Zn] += rdx x m for m = 0+M, with the flags clear, and %rax = 0
		unless T1 provides the zero."""
		n = self.n
		z = refs(names(n + 1))
		b = ["\tmulx\t0+\\M, \\T1, \\T0", "\tadox\t\\T1, \\Z0",
			"\tadox\t\\T0, \\Z1"]
		for k in range(1, n):
			b += ["\tmulx\t%d+\\M, \\T1, \\T0" % (8 * k),
				"\tadcx\t\\T1, %s" % z[k], "\tadox\t\\T0, %s" % z[k + 1]]
		if self.onet:
			b += ["\tmovq\t$0, \\T1", "\tadcx\t\\T1, %s" % z[n]]
		else:
			b.append("\tadcx\t%%rax, %s" % z[n])
		return macro("MULADD", names(n + 1) + ["T0", "T1", "M"], b)

	def mulsub(self):
		"""[Z0:Zn] -= rdx x m for m = 0+M."""
		n = self.n
		z = refs(names(n + 1))
		b = []
		# Odd words, then even words, each a single borrow chain.
		for first in (1, 0):
			ks = list(range(first, n, 2))
			for j, k in enumerate(ks):
				b += ["\tmulx\t%d+\\M, \\T1, \\T0" % (8 * k),
					"\t%s\t\\T1, %s" % ("subq" if j == 0 else "sbbq", z[k]),
					"\tsbbq\t\\T0, %s" % z[k + 1]]
			if ks[-1] + 1 < n:
				b.append("\tsbbq\t$0, %s" % z[n])
		return macro("MULSUB", names(n + 1) + ["T0", "T1", "M"], b)

	def finalc(self):
		"""c <- v - p if no borrow, else v, for c = 0+D and v = [V0:Vn-1].
		The top m words use the copies C0:Cm-1, and the others subtract in
		place, kept at c."""
		n = self.n
		m = self.m
		h = n - m
		v = refs(names(n, "V"))
		c = refs(names(m, "C"))
		at = lambda k: "%d+\\D" % (8 * k)
		x = lambda k: at(k) if k < h else c[k - h]
		b = ["\tmovq\t%s, %s" % (v[k], x(k)) for k in range(n)]
		b += ["\t%s\tp%d(%%rip), %s" % ("subq" if k == 0 else "sbbq", k,
			v[k] if k < h else c[k - h]) for k in range(n)]
		if self.wide:
			b += self.full_only(["\tsbbq\t$0, \\H"])
		b += ["\tcmovc\t%s, %s" % (at(k), v[k]) if k < h else
			"\tcmovc\t%s, %s" % (v[k], c[k - h]) for k in range(n)]
		b += ["\tmovq\t%s, %s" % (v[k] if k < h else c[k - h], at(k))
			for k in range(n)]
		return macro("FINALC", names(n, "V") + names(m, "C") + ["D"] +
			(["H"] if self.wide else []), b)

	def rdcstep(self):
		"""Montgomery step on a window with no word above it:
		[Z1:Zn-1, Z0] <- ([Z0:Zn-1] + (Z0 x u0 mod 2^64) x p)/2^64. The window
		stays below 2^(64n) for p < 2^(64n - 1), so no carry leaves it."""
		n = self.n
		z = refs(names(n))
		b = ["\tmovq\t$U0, %rdx", "\timulq\t\\Z0, %rdx", "\txorq\t\\T0, \\T0",
			"\tmulx\t0+\\P, \\T0, \\T1", "\tadox\t\\T0, \\Z0",
			"\tadox\t\\T1, \\Z1"]
		for k in range(1, n):
			b += ["\tmulx\t%d+\\P, \\T0, \\T1" % (8 * k),
				"\tadcx\t\\T0, %s" % z[k]]
			if k < n - 1:
				b.append("\tadox\t\\T1, %s" % z[k + 1])
		# Z0 is zero here, so this cannot overflow.
		b += ["\tadox\t\\T1, \\Z0", "\tadcq\t$0, \\Z0"]
		return macro("RDCSTEP", names(n) + ["T0", "T1", "P"], b)

	def rdcstep1(self):
		"""RDCSTEP with one temporary: the low word cancels, so its carry is
		Z0 != 0, which adding all-ones to Z0 yields, and Z0 then takes the
		high halves until it becomes the top word. Needs the flags clear."""
		n = self.n
		z = refs(names(n))
		b = ["\tmovq\t$U0, %rdx", "\tmulx\t\\Z0, %rdx, \\T",
			"\tmulx\t0+\\P, \\T, \\T", "\tadcx\tones(%rip), \\Z0",
			"\tadox\t\\T, \\Z1"]
		for k in range(1, n):
			b += ["\tmulx\t%d+\\P, \\T, \\Z0" % (8 * k),
				"\tadcx\t\\T, %s" % z[k]]
			if k < n - 1:
				b.append("\tadox\t\\Z0, %s" % z[k + 1])
		b += ["\tadox\t\\ZR, \\Z0", "\tadcx\t\\ZR, \\Z0"]
		return macro("RDCSTEP", names(n) + ["T", "ZR", "P"], b)

	def rdcn(self):
		"""[Z0:Zn-1] <- [Z0:Zn-1]/2^(64n) mod p, at most p, by n Montgomery
		steps."""
		n = self.n
		z = refs(names(n))
		t = ["\\T0", self.zr()] if self.wide else ["\\T0", "\\T1"]
		b = ["\tRDCSTEP\t%s" % args([z[(i + j) % n] for j in range(n)],
			t, "\\P") for i in range(n)]
		return macro("RDCN", names(n) + self.tparams() + ["P"], b)

	def addh(self):
		"""[Z0:Zn-1] += [H0:Hn-1], registers or memory."""
		n = self.n
		b = ["\t%s\t\\H%d, \\Z%d" % ("addq" if k == 0 else "adcq", k, k)
			for k in range(n)]
		return macro("ADDH", names(n) + names(n, "H"), b)

	def fp_rdcn_low(self):
		"""c <- a/2^(64n) mod p for a = 0+A < pR: reduce the low half to at
		most p, add the high half, which is below p, and subtract p once with
		the copies C0:Cm-1, which may reuse T0, T1, %rdx and the base of A."""
		n = self.n
		z = refs(names(n))
		b = ["\tmovq\t%d+\\A, %s" % (8 * k, z[k]) for k in range(n)]
		if self.wide:
			b.append("\txorq\t\\T0, \\T0")
		b += ["\tRDCN\t%s" % args(z, refs(self.tparams()), "\\P"),
			"\tADDH\t%s" % args(z, ["%d+\\A" % (8 * (n + k))
				for k in range(n)])]
		top = None
		if self.wide:
			# The sum reaches 2^(64n) when p fills the top bit.
			b += self.full_only(["\tmovq\t$0, \\H", "\tadcq\t$0, \\H"])
			top = "\\H"
		if self.bcopy:
			# The pointer to c is at CP, and the copies must not use T0.
			b += ["\tmovq\t\\CP, \\T0", self.finalc_call(z,
				refs(names(self.m, "C")), "0(\\T0)", top)]
		else:
			b.append(self.finalc_call(z, refs(names(self.m, "C")), top=top))
		return macro("FP_RDCN_LOW", ["A"] + names(n) + self.tparams() + ["P"] +
			names(self.m, "C") + (["CP"] if self.bcopy else []) +
			(["H"] if self.wide else []), b)

	def sqrn_reg(self):
		"""[Z0:Z2n-1] <- a^2 with a = 0+A, computing each cross product once.
		The last word Z2n-1 must be the base register of A. Row 0 computes
		[Z1:Zn] <- a0 x [a1:an-1], row r adds ar x [ar+1:an-1] at
		[Z2r+1:Zn+r], and the last pass sets [Z0:Z2n-1] <- 2 x [Z1:Z2n-2] +
		[a0^2:an-1^2]."""
		n = self.n
		z = refs(names(2 * n))
		a = lambda k: "%d+\\A" % (8 * k)
		b = ["\tmovq\t0+\\A, %rdx", "\tmulx\t%s, \\Z1, \\Z2" % a(1)]
		for k in range(2, n):
			b += ["\tmulx\t%s, \\T0, %s" % (a(k), z[k + 1]),
				"\t%s\t\\T0, %s" % ("addq" if k == 2 else "adcq", z[k])]
		b.append("\tadcq\t$0, %s" % z[n])
		for r in range(1, n - 2):
			b += ["", "\tmovq\t%s, %%rdx" % a(r),
				"\txorq\t%s, %s" % (z[n + r], z[n + r])]
			for k in range(r + 1, n):
				b += ["\tmulx\t%s, \\T0, \\T1" % a(k),
					"\tadcx\t\\T0, %s" % z[r + k],
					"\tadox\t\\T1, %s" % z[r + k + 1]]
			b.append("\tadcq\t$0, %s" % z[n + r])
		r = n - 2
		b += ["", "\tmovq\t%s, %%rdx" % a(r),
			"\tmulx\t%s, \\T0, %s" % (a(r + 1), z[2 * r + 2]),
			"\taddq\t\\T0, %s" % z[2 * r + 1], "\tadcq\t$0, %s" % z[2 * r + 2],
			"", "\tmovq\t0+\\A, %rdx", "\tmulx\t%rdx, \\Z0, \\T1",
			"\txorq\t\\T0, \\T0", "\tadcx\t\\Z1, \\Z1", "\tadox\t\\T1, \\Z1"]
		for k in range(1, n):
			b += ["\tmovq\t%s, %%rdx" % a(k), "\tmulx\t%rdx, \\T0, \\T1"]
			if k == n - 1:
				b.append("\tmovq\t$0, %s" % z[2 * n - 1])
			b += ["\tadcx\t%s, %s" % (z[2 * k], z[2 * k]),
				"\tadox\t\\T0, %s" % z[2 * k],
				"\tadcx\t%s, %s" % (z[2 * k + 1], z[2 * k + 1]),
				"\tadox\t\\T1, %s" % z[2 * k + 1]]
		return macro("SQRN", ["A"] + names(2 * n) + ["T0", "T1"], b)

	def fp_sqr_low_reg(self):
		"""c <- a^2 (RDC = 0) or a^2/2^(64n) mod p (RDC = 1), for a = 0+A based
		on Z2n-1. Without sqrdi, it expects c on top of the stack and pops it
		before storing. With sqrmul, RDC = 1 multiplies a by itself, which
		needs %rax and %rdx. Otherwise the low half reduces to at most p and
		the high half is below p."""
		n = self.n
		z = refs(names(2 * n))
		c = "%rdi" if self.sqrdi else "%rdx"
		b = [".if \\RDC != 1", "\tSQRN\t%s" % args("\\A", z, "\\T0", "\\T1")]
		if not self.sqrdi:
			b.append("\tpopq\t%rdx")
		b += ["\tmovq\t%s, %d(%s)" % (z[k], 8 * k, c) for k in range(2 * n)]
		b.append(".else")
		if self.sqrmul:
			b += ["\tMULM\t\\A, \\A, %s" % args(z[:n + 2]),
				"\tFP_MUL_LOW\t\\A, \\A, %s, \\P, 1" % args(z[:n + 3])]
		else:
			b += ["\tSQRN\t%s" % args("\\A", z, "\\T0", "\\T1"),
				"\tRDCN\t%s" % args(z[:n], "\\T0", "\\T1", "\\P"),
				"\tADDH\t%s" % args(z)]
			if not self.sqrdi:
				b.append("\tpopq\t%rdi")
			b.append(self.finalc_call(z[:n], ["\\T1"] + z[n:n + 2] +
				self.fixed[:n - 3]))
		b.append(".endif")
		return macro("FP_SQR_LOW", ["A"] + names(2 * n) + ["T0", "T1", "P",
			"RDC"], b)

	def sqrn_mem(self):
		"""O <- a^2 with a = 0+A, computing each cross product once and keeping
		word j in register Z((j - 1) mod 10). Words whose register a later row
		reuses are stored once final and read back from O by the last pass,
		O <- 2 x [w1:w2n-2] + [a0^2:an-1^2]."""
		n = self.n
		kk = 10
		z = refs(names(kk))
		top = 2 * n - 2
		spill = set(j for j in range(1, top + 1) if j + kk <= top)
		w = lambda j: z[(j - 1) % kk]
		a = lambda k: "%d+\\A" % (8 * k)
		o = lambda j: "%d+\\O" % (8 * j)

		# Beyond kk digits, row 0 needs the registers of w1, and of w2 beyond
		# kk + 1, for its top words, so they are stored as soon as they are
		# final. Row r then needs the register of w(2r + 1) for its top word,
		# which is final after its first product.
		early = set(j for j in (1, 2) if j + kk <= n)
		done = set(early)

		def stores(r):
			"""Words 2r + 1 and 2r + 2 are final after row r."""
			return ["\tmovq\t%s, %s" % (w(j), o(j)) for j in (2 * r + 1,
				2 * r + 2) if j in spill and j not in done]
		b = ["\tmovq\t0+\\A, %rdx", "\tmulx\t%s, %s, %s" % (a(1), w(1), w(2))]
		if 1 in early:
			b.append("\tmovq\t%s, %s" % (w(1), o(1)))
		for k in range(2, n):
			b += ["\tmulx\t%s, \\T0, %s" % (a(k), w(k + 1)),
				"\t%s\t\\T0, %s" % ("addq" if k == 2 else "adcq", w(k))]
			if k == 2 and 2 in early:
				b.append("\tmovq\t%s, %s" % (w(2), o(2)))
		b.append("\tadcq\t$0, %s" % w(n))
		b += stores(0)
		for r in range(1, n - 2):
			mid = w(n + r) == w(2 * r + 1)
			b += ["", "\tmovq\t%s, %%rdx" % a(r), "\txorq\t%s, %s" % (
				("\\T0", "\\T0") if mid else (w(n + r), w(n + r)))]
			for k in range(r + 1, n):
				b += ["\tmulx\t%s, \\T0, \\T1" % a(k),
					"\tadcx\t\\T0, %s" % w(r + k),
					"\tadox\t\\T1, %s" % w(r + k + 1)]
				if mid and k == r + 1:
					b += ["\tmovq\t%s, %s" % (w(2 * r + 1), o(2 * r + 1)),
						"\tmovq\t$0, %s" % w(n + r)]
					done.add(2 * r + 1)
			b.append("\tadcq\t$0, %s" % w(n + r))
			b += stores(r)
		r = n - 2
		b += ["", "\tmovq\t%s, %%rdx" % a(r),
			"\tmulx\t%s, \\T0, %s" % (a(r + 1), w(top)),
			"\taddq\t\\T0, %s" % w(top - 1), "\tadcq\t$0, %s" % w(top), ""]
		for k in range(n):
			b += ["\tmovq\t%s, %%rdx" % a(k), "\tmulx\t%rdx, \\T0, \\T1"]
			if k == 0:
				b += ["\tmovq\t\\T0, %s" % o(0), "\txorq\t\\T0, \\T0"]
			for j in (2 * k, 2 * k + 1):
				if j == 0:
					continue
				r = w(j)
				if j == top + 1:
					r = "%rdx"
					b.append("\tmovq\t$0, %rdx")
				elif j in spill:
					# T0 is free once a0^2 is stored.
					r = "\\T0" if k == 0 else "%rdx"
					b.append("\tmovq\t%s, %s" % (o(j), r))
				b += ["\tadcx\t%s, %s" % (r, r), "\tadox\t%s, %s" % (
					"\\T0" if j % 2 == 0 else "\\T1", r),
					"\tmovq\t%s, %s" % (r, o(j))]
		return macro("SQRN", ["A", "O"] + names(kk) + ["T0", "T1"], b)

	def fp_sqr_low_mem(self):
		"""c <- a^2 (RDC = 0) or a^2/2^(64n) mod p (RDC = 1), for a = 0+A based
		on %rsi, with S holding 2n words."""
		n = self.n
		pool = refs(names(10)) + ["\\T0", "\\T1"]
		cp = []
		if self.wide:
			# One temporary, the copy %rdx and the top word in %rdi.
			pool += ["%rsi", "%rdi"]
			copies = ["%rdx"]
			cp = ["\\C", pool[n + 1]]
			pool = pool[:n + 1]
		elif self.bcopy:
			# The pointer to c is at C, and %rsi and %rdi are free.
			pool += ["%rsi", "%rdi"]
			copies = [pool[n + 1], "%rdx", pool[n + 2]]
			cp = ["\\C"]
		else:
			copies = ([pool[n], pool[n + 1], "%rdx", "%rsi"] + pool[n + 2:])[:n]
		b = [".if \\RDC != 1", "\tSQRN\t%s" % args("\\A", "0(%rdi)",
			refs(names(10)), "\\T0", "\\T1"), ".else",
			"\tSQRN\t%s" % args("\\A", "\\S", refs(names(10)), "\\T0", "\\T1"),
			"\tFP_RDCN_LOW\t%s" % args("\\S", pool[:n + 2], "\\P",
				copies[:self.m], cp), ".endif"]
		return macro("FP_SQR_LOW", ["A"] + names(10) + ["T0", "T1", "P", "RDC",
			"S"] + (["C"] if self.bcopy else []), b)

	def store(self, reg, off):
		if self.cslot:
			return ["\tmovq\t\\C, \\T0", "\tmovq\t%s, %d(\\T0)" % (reg, off)]
		return ["\tmovq\t%s, %d(%%rdi)" % (reg, off)]

	def step_end(self, b, i, clear):
		"""Stores or reduces the low word at step i of a product."""
		w = self.window(i)
		# z <- (z + (z0 x u0 mod 2^64) x p)/2^64 when RDC = 1.
		b += [".if \\RDC != 1"] + self.store(w[0], 8 * i) + [".else"]
		if clear or (i == 0 and self.mulmadc):
			b.append(self.clear())
		if self.onet:
			b.append("\tMULRDC1\t%s" % args(w, "\\T0", self.zr(), "\\P"))
			if self.wide and i < self.n - 1:
				b += self.full_only(["\tmovq\t%s, \\K" % w[0]])
			b.append(".endif")
		else:
			b += ["\tmovq\t$U0, %rdx", "\tmulx\t%s, %%rdx, \\T1" % w[0],
				"\tMULADD\t%s" % args(w, "\\T0", "\\T1", "\\P"), ".endif"]

	def muladd1(self):
		"""[Z0:Zn-1, X] <- [Z0:Zn-1] + rdx x m for m = 0+M, with X the new top
		word, which takes each high half, one temporary and ZR = 0. Needs the
		flags clear."""
		n = self.n
		z = refs(names(n))
		b = ["\tmulx\t0+\\M, \\T, \\X", "\tadox\t\\T, \\Z0",
			"\tadox\t\\X, \\Z1"]
		for k in range(1, n):
			b += ["\tmulx\t%d+\\M, \\T, \\X" % (8 * k),
				"\tadcx\t\\T, %s" % z[k]]
			if k < n - 1:
				b.append("\tadox\t\\X, %s" % z[k + 1])
		if self.wide:
			# The top word of the accumulator, kept at K, goes in with the
			# last carry.
			b += ["\tadox\t\\ZR, \\X"] + self.full_only(["\tadcx\t\\K, \\X"],
				["\tadcx\t\\ZR, \\X"])
		else:
			b += ["\tadox\t\\ZR, \\X", "\tadcx\t\\ZR, \\X"]
		return macro("MULADD1", names(n) + ["X", "T", "ZR", "M"] +
			(["K"] if self.wide else []), b)

	def mulrdc1(self):
		"""[Z1:Zn] <- ([Z0:Zn] + (Z0 x u0 mod 2^64) x p)/2^64 for p = 0+P. The
		low word cancels, so its carry is Z0 != 0, which adding all-ones to
		Z0 yields, and Z0 then serves as the second temporary. Needs the flags
		clear and ZR = 0."""
		n = self.n
		z = refs(names(n + 1))
		b = ["\tmovq\t$U0, %rdx", "\tmulx\t\\Z0, %rdx, \\T",
			"\tmulx\t0+\\P, \\T, \\T", "\tadcx\tones(%rip), \\Z0",
			"\tadox\t\\T, \\Z1"]
		for k in range(1, n):
			b += ["\tmulx\t%d+\\P, \\T, \\Z0" % (8 * k),
				"\tadcx\t\\T, %s" % z[k], "\tadox\t\\Z0, %s" % z[k + 1]]
		b.append("\tadcx\t\\ZR, %s" % z[n])
		if self.wide:
			# A value below 2p reaches 2^(64n), so the carries become the top
			# word in Z0.
			b += self.full_only(["\tmovq\t$0, \\Z0", "\tadox\t\\ZR, \\Z0",
				"\tadcx\t\\ZR, \\Z0"])
		return macro("MULRDC1", names(n + 1) + ["T", "ZR", "P"], b)

	def result(self, b):
		n = self.n
		w = self.window(n)
		b += [".if \\RDC != 1"] + self.loadc() + ["\tmovq\t%s, %d(%s)" % (w[k],
			8 * (n + k), self.cbase()) for k in range(n)] + [".else"]
		b += self.loadc() + [self.finalc_call(w[:n], self.copies(),
			"0(%s)" % self.cbase(), w[n] if self.wide else None), ".endif"]

	def fp_mul_low(self):
		"""c <- a x b (RDC = 0) or a x b/2^(64n) mod p (RDC = 1), after MULM,
		adding ai x b at step i. With cslot, the pointer to c is at C, and
		stores go through T0."""
		n = self.n
		b = ["\txorq\t\\T1, \\T1"] if self.onet and not self.wide else []
		if self.wide:
			b += self.full_only(["\tmovq\t$0, \\K"])
		for i in range(n):
			w = self.window(i)
			if i > 0 and self.onet:
				b += ["", "\txorq\t\\T0, \\T0",
					"\tmovq\t%d+\\A, %%rdx" % (8 * i),
					"\tMULADD1\t%s" % args(w[:n], w[n], "\\T0", self.zr(),
						"\\B", ["\\K"] if self.wide else [])]
			elif i > 0:
				b += ["",
					"\txorq\t%s, %s" % (w[n], w[n]),
					"\tmovq\t%d+\\A, %%rdx" % (8 * i),
					"\tMULADD\t%s" % args(w, "\\T0", "\\T1", "\\B")]
			self.step_end(b, i, False)
		b.append("")
		self.result(b)
		return macro("FP_MUL_LOW", ["A", "B"] + names(n + 1) + self.tparams() +
			["P", "RDC"] + self.cparam() + (["K"] if self.wide else []), b)

	def fp2_mul0_low(self):
		"""c0 <- a0 x b0 - a1 x b1 after MULM, as for FP_MUL_LOW, adding
		a0i x b0 - a1i x b1 at step i, where the unreduced c0 is in
		(-p, 2^(64n)). At the end, p is added if the result is negative, as
		adcx keeps SF. With qnr, b1 is read at B1, which holds q x b1 for
		u^2 = -q, and c0 stays in (-p, 2^(64n)) for qp < 2^(64n)."""
		n = self.n
		b1 = "\\B1" if self.qnr else "%d+\\B" % (8 * n)
		b = ["\tmovq\t%d+\\A, %%rdx" % (8 * n),
			"\tMULSUB\t%s" % args(self.window(0), "\\T0", "\\T1", b1)]
		for i in range(n):
			w = self.window(i)
			if i > 0:
				b += ["",
					"\tmovq\t%d+\\A, %%rdx" % (8 * i), self.clear(),
					"\tMULADD\t%s" % args(w, "\\T0", "\\T1", "\\B"),
					"\tmovq\t%d+\\A, %%rdx" % (8 * (n + i)),
					"\tMULSUB\t%s" % args(w, "\\T0", "\\T1", b1)]
			self.step_end(b, i, True)
			# The top word is signed: extend it into the next one.
			if i < n - 1:
				b += ["\txorq\t%s, %s" % (w[0], w[0]),
					"\tbtq\t\t$63, %s" % w[n], "\tsbbq\t$0, %s" % w[0]]
			else:
				b.append("\ttestq\t%s, %s" % (w[n], w[n]))
		w = self.window(n)
		b.append("")
		for k in range(n):
			t = "\\T0" if k % 2 == 0 else "\\T1"
			b += ["\tmovq\t$0, %s" % t, "\tcmovs\tp%d(%%rip), %s" % (k, t),
				"\tadcx\t%s, %s" % (t, w[k])]
		self.result(b)
		return macro("FP2_MUL0_LOW", ["A", "B"] + (["B1"] if self.qnr else []) +
			names(n + 1) + ["T0", "T1", "P", "RDC"] + self.cparam(), b)

	def fp2_mul1_low(self):
		"""c1 <- a0 x b1 + a1 x b0 after MULM of a0 and b1, as for FP_MUL_LOW,
		adding a0i x b1 + a1i x b0 at step i."""
		n = self.n
		b = ["\tmovq\t%d+\\A, %%rdx" % (8 * n)]
		if self.mulmadc:
			b.append(self.clear())
		b.append("\tMULADD\t%s" % args(self.window(0), "\\T0", "\\T1", "\\B"))
		for i in range(n):
			w = self.window(i)
			if i > 0 and self.onet:
				b += ["", "\txorq\t\\T0, \\T0",
					"\tmovq\t%d+\\A, %%rdx" % (8 * i),
					"\tMULADD1\t%s" % args(w[:n], w[n], "\\T0", "\\T1",
						"%d+\\B" % (8 * n)),
					"\tmovq\t%d+\\A, %%rdx" % (8 * (n + i)),
					"\tMULADD\t%s" % args(w, "\\T0", "\\T1", "\\B")]
			elif i > 0:
				b += ["",
					"\txorq\t%s, %s" % (w[n], w[n]),
					"\tmovq\t%d+\\A, %%rdx" % (8 * i),
					"\tMULADD\t%s" % args(w, "\\T0", "\\T1",
						"%d+\\B" % (8 * n)),
					"\tmovq\t%d+\\A, %%rdx" % (8 * (n + i)),
					"\tMULADD\t%s" % args(w, "\\T0", "\\T1", "\\B")]
			self.step_end(b, i, False)
		b.append("")
		self.result(b)
		return macro("FP2_MUL1_LOW", ["A", "B"] + names(n + 1) + ["T0", "T1",
			"P", "RDC"] + self.cparam(), b)

	def bases(self):
		"""Base registers of the operands of FP2_MUL_LOW."""
		if self.bcopy:
			return []
		return ["%rcx"] if self.acopy else ["%rsi", "%rcx"]

	def fp2_frame(self):
		"""Offsets in the scratch of FP2_MUL_LOW: the pointer to c1 at 0, the
		one to c0 at 8 when c is on the stack, then the base registers that
		FINALC overwrites, then c1."""
		o = 16 if self.cslot else 8
		kept = {}
		for x in self.bases():
			if x in self.copies():
				kept[x] = o
				o += 8
		return kept, o

	def fp2_mul_low(self):
		"""c <- a x b in Fp2 with u^2 = -1, or -q for FP2_QNR = q, for a = 0+A and b = 0+B, with c0 at
		%rdi, or at the pointer in 8+S with cslot, and, for RDC = 0, c1 at the
		pointer in 0+S. For RDC = 1, c1 is at 8n bytes from c0, reduced, and c
		may alias a or b: c1 goes to the scratch space first, since c0 still
		reads a1 and b1. S is the words of fp2_frame plus n of scratch, and n
		more for q x b1 with qnr, which fits n words as qp < 2^(64n)."""
		n = self.n
		z = refs(names(n + 1))
		kept, c1 = self.fp2_frame()
		zz = args(z, "\\T0")
		zt = args(z, "\\T0", "\\T1", "\\P")
		ks = sorted(kept.items(), key=lambda i: i[1])
		c0 = ", 8+\\S" if self.cslot else ""
		c1p = ", 0+\\S" if self.cslot else ""
		qb = c1 + 8 * n

		def mul0(rdc):
			call = "\tFP2_MUL0_LOW\t\\A, \\B, %s, %s, %d%s"
			if not self.qnr:
				return [call.replace("%s, %s", "%s") % (zt, rdc, c0)]
			return ["#ifdef FP2_QNR", call % ("%d+\\S" % qb, zt, rdc, c0),
				"#else", call % ("%d+\\B" % (8 * n), zt, rdc, c0), "#endif"]
		b = []
		if self.qnr:
			# [qb+S] <- q x b1, with the high halves added on the CF chain.
			b += ["#ifdef FP2_QNR", "\tmovq\t$FP2_QNR, %rdx",
				"\tmulx\t%d+\\B, \\Z0, \\Z1" % (8 * n)]
			for k in range(1, n):
				b += ["\tmulx\t%d+\\B, \\T0, %s" % (8 * (n + k), z[k + 1]),
					"\t%s\t\\T0, %s" % ("addq" if k == 1 else "adcq", z[k])]
			b += ["\tmovq\t%s, %d+\\S" % (z[k], qb + 8 * k) for k in range(n)]
			b.append("#endif")
		b += [".if \\RDC != 1", "\tMULM\t\\A, \\B, %s" % zz] + mul0(0)
		if not self.cslot:
			b.append("\tmovq\t0+\\S, %rdi")
		b += ["\tMULM\t\\A, %d+\\B, %s" % (8 * n, zz),
			"\tFP2_MUL1_LOW\t\\A, \\B, %s, 0%s" % (zt, c1p), ".else"]
		b += ["\tmovq\t%s, %d+\\S" % (x, o) for x, o in ks]
		if self.cslot:
			b += ["\tleaq\t%d+\\S, %%rdx" % c1, "\tmovq\t%rdx, 0+\\S"]
		else:
			b += ["\tmovq\t%rdi, 0+\\S", "\tleaq\t%d+\\S, %%rdi" % c1]
		b += ["\tMULM\t\\A, %d+\\B, %s" % (8 * n, zz),
			"\tFP2_MUL1_LOW\t\\A, \\B, %s, 1%s" % (zt, c1p)]
		b += ["\tmovq\t%d+\\S, %s" % (o, x) for x, o in ks]
		if not self.cslot:
			b.append("\tmovq\t0+\\S, %rdi")
		b += ["\tMULM\t\\A, \\B, %s" % zz] + mul0(1)
		c = "%rdi"
		if self.cslot:
			c = "\\T0"
			b.append("\tmovq\t8+\\S, \\T0")
		b += ["\tmovq\t%d+\\S, %s" % (c1 + 8 * k, z[k]) for k in range(n)]
		b += ["\tmovq\t%s, %d(%s)" % (z[k], 8 * (n + k), c) for k in range(n)]
		b.append(".endif")
		return macro("FP2_MUL_LOW", ["A", "B"] + names(n + 1) + ["T0", "T1",
			"P", "RDC", "S"], b)

	def fp2_sqr_low(self):
		"""c <- a^2 in Fp2 with u^2 = -1, for a = 0+A: c0 = (a0 + a1) x
		(a0 - a1 + p), c1 = 2 x a0 x a1, with S holding 3n + 2 words: a0 + a1
		at 0, a0 - a1 + p at 8n, 2 x a0 at 16n and the pointers at 24n. For
		u^2 = -q with FP2_QNR = q, c0 = (a0 + a1) x (a0 + q x (p - a1)) +
		(q - 1)/2 x c1, where a0 + q x (p - a1) takes the place at 8n. With
		cslot, c0 is at the pointer in 24n+8+S and c1 at the one in 24n+S,
		which RDC = 1 reduces. Otherwise, RDC = 0 puts c0 at %rdi and c1 at
		the pointer in 24n+S, and RDC = 1 puts c0 at %rdi and c1 at 8n(%rdi),
		reduced, where c may alias a. c1 goes first: it is the last reader of
		a, and c0 only reads the scratch."""
		n = self.n
		z = refs(names(n + 1))
		t = z[n]
		s0, s1, s2, sp = 0, 8 * n, 16 * n, 24 * n
		b = ["\tmovq\t%d+\\A, %s" % (8 * k, z[k]) for k in range(n)]
		for k in range(n):
			b += ["\tmovq\t%s, %s" % (z[k], t), "\t%s\t%d+\\A, %s" % ("addq"
				if k == 0 else "adcq", 8 * (n + k), t),
				"\tmovq\t%s, %d+\\S" % (t, s0 + 8 * k)]
		for k in range(n):
			b += ["\tmovq\t%s, %s" % (z[k], t), "\t%s\t%s, %s" % ("addq"
				if k == 0 else "adcq", z[k], t),
				"\tmovq\t%s, %d+\\S" % (t, s2 + 8 * k)]
		sub = ["\t%s\t%d+\\A, %s" % ("subq" if k == 0 else "sbbq", 8 * (n + k),
			z[k]) for k in range(n)]
		sub += ["\t%s\t%d+\\P, %s" % ("addq" if k == 0 else "adcq", 8 * k,
			z[k]) for k in range(n)]
		if self.qnr:
			# a0 + q x (p - a1), with the high halves of the products by q in
			# T0 and T1 in turn.
			h = ["\\T0", "\\T1"]
			b += ["#ifdef FP2_QNR"]
			for k in range(n):
				b += ["\tmovq\t%d+\\P, %s" % (8 * k, z[k]),
					"\t%s\t%d+\\A, %s" % ("subq" if k == 0 else "sbbq",
						8 * (n + k), z[k])]
			b += ["\tmovq\t$FP2_QNR, %rdx", "\tmulx\t\\Z0, \\Z0, \\T0"]
			for k in range(1, n):
				b += ["\tmulx\t%s, %s, %s" % (z[k], z[k], h[k % 2]),
					"\t%s\t%s, %s" % ("addq" if k == 1 else "adcq",
						h[(k - 1) % 2], z[k])]
			b += ["\t%s\t%d+\\A, %s" % ("addq" if k == 0 else "adcq", 8 * k,
				z[k]) for k in range(n)]
			b += ["#else"] + sub + ["#endif"]
		else:
			b += sub
		b += ["\tmovq\t%s, %d+\\S" % (z[k], s1 + 8 * k) for k in range(n)]
		zz = args(z, "\\T0")
		zt = args(z, "\\T0", "\\T1", "\\P", "\\RDC")
		b.append("")
		if self.cslot:
			b += ["\tMULM\t%d+\\S, %d+\\A, %s" % (s2, 8 * n, zz),
				"\tFP_MUL_LOW\t%d+\\S, %d+\\A, %s, %d+\\S" % (s2, 8 * n, zt,
					sp),
				"\tMULM\t%d+\\S, %d+\\S, %s" % (s0, s1, zz),
				"\tFP_MUL_LOW\t%d+\\S, %d+\\S, %s, %d+\\S" % (s0, s1, zt,
					sp + 8)]
		else:
			b += [".if \\RDC != 1", "\tmovq\t%%rdi, %d+\\S" % (sp + 8),
				"\tmovq\t%d+\\S, %%rdi" % sp, ".else",
				"\taddq\t$%d, %%rdi" % (8 * n), ".endif",
				"\tMULM\t%d+\\S, %d+\\A, %s" % (s2, 8 * n, zz),
				"\tFP_MUL_LOW\t%d+\\S, %d+\\A, %s" % (s2, 8 * n, zt),
				".if \\RDC != 1", "\tmovq\t%d+\\S, %%rdi" % (sp + 8), ".else",
				"\tsubq\t$%d, %%rdi" % (8 * n), ".endif",
				"\tMULM\t%d+\\S, %d+\\S, %s" % (s0, s1, zz),
				"\tFP_MUL_LOW\t%d+\\S, %d+\\S, %s" % (s0, s1, zt)]
		if self.qnr:
			# c0 += (q - 1)/2 x c1, at %rdi: the 2n digits for RDC = 0, and
			# with a final subtraction per addition for RDC = 1.
			cs = (["\\Z%d" % n, "\\T0", "\\T1"] + self.fixed)[:self.m]
			b += ["#ifdef FP2_QNR", ".if \\RDC != 1",
				"\tmovq\t%d+\\S, \\T0" % sp, ".rept (FP2_QNR - 1) / 2"]
			for k in range(2 * n):
				b += ["\tmovq\t%d(\\T0), %s" % (8 * k, z[k % 2]),
					"\t%s\t%s, %d(%%rdi)" % ("addq" if k == 0 else "adcq",
						z[k % 2], 8 * k)]
			b += [".endr", ".else", ".rept (FP2_QNR - 1) / 2"]
			b += ["\tmovq\t%d(%%rdi), %s" % (8 * k, z[k]) for k in range(n)]
			b += ["\tADDH\t%s" % args(z[:n], ["%d(%%rdi)" % (8 * (n + k))
				for k in range(n)]), self.finalc_call(z[:n], cs), ".endr",
				".endif", "#endif"]
		return macro("FP2_SQR_LOW", ["A"] + names(n + 1) + ["T0", "T1", "P",
			"RDC", "S"], b)

	def parts(self):
		if self.wide:
			return [self.mulm(), self.muladd1(), self.mulrdc1(), self.finalc(),
				self.rdcstep1(), self.rdcn(), self.addh(), self.fp_rdcn_low(),
				self.sqrn_mem(), self.fp_sqr_low_mem(), self.fp_mul_low()]
		parts = [self.mulm(), self.muladd(), self.mulsub(), self.finalc(),
			self.rdcstep(), self.rdcn(), self.addh(), self.fp_rdcn_low()]
		if self.onet:
			parts[2:2] = [self.muladd1(), self.mulrdc1()]
		if self.sqreg:
			parts += [self.sqrn_reg(), self.fp_sqr_low_reg()]
		else:
			parts += [self.sqrn_mem(), self.fp_sqr_low_mem()]
		parts += [self.fp_mul_low(), self.fp2_mul0_low(), self.fp2_mul1_low(),
			self.fp2_mul_low(), self.fp2_sqr_low()]
		return parts


def rdc_regs(g):
	"""Accumulator, temporaries, copies and register of the top word of
	FP_RDCN_LOW for a based on %rsi or %rsp. The copies reuse the
	temporaries, %rdx and %rsi."""
	n = g.n
	r = regs("%rdx", "%rsi", "%rdi")
	if g.wide:
		# One temporary, the copy %rdx, and the top word in %rsi, which A no
		# longer needs.
		r.append("%rdi")
		return r[:n], r[n:n + 1], ["%rdx"], ["%rsi"]
	if g.bcopy:
		# The pointer to c is on the stack, freeing %rdi, and goes to T0.
		r.append("%rdi")
		z, t = r[:n], r[n:n + 2]
		return z, t, [t[1], "%rdx", "%rsi"][:g.m], []
	z, t = r[:n], r[n:n + 2]
	return z, t, (t + ["%rdx", "%rsi"] + r[n + 2:])[:g.m], []


def copy(g, src, dst, words):
	"""Copies words from 0(src) to dst(%rsp) through the accumulator."""
	o = []
	for i in range(0, words, len(g.z)):
		k = range(i, min(words, i + len(g.z)))
		o += ["\tmovq\t%d(%s), %s" % (8 * j, src, g.z[j - i]) for j in k]
		o += ["\tmovq\t%s, %d(%%rsp)" % (g.z[j - i], dst + 8 * j) for j in k]
	return o


def mul_low(g):
	n = g.n
	z, t0 = g.z, g.t0
	# Techniques and code heavily inspired from "Efficient Algorithms for Large
	# Prime Characteristic Fields and Their Application to Bilinear Pairings"
	# by Longa at TCHES'23. fp_muln_low(c, a, b): c = a * b, and
	# fp_mulm_low(c, a, b): c = a * b/R mod p.
	o = file_head(g) + [".global cdecl(fp_mul1_low)",
		".global cdecl(fp_muln_low)", ".global cdecl(fp_mulm_low)", ""]
	o += mul1(g.n) + [""]
	regs = args(z, g.t)
	for name, rdc in (("fp_muln_low", 0), ("fp_mulm_low", 1)):
		b = ["\tmovq\t%rdx, %rcx"]
		a = "0(%rsi)"
		bb = "0(%rcx)"
		frame = 0
		cs = ""
		if g.bcopy:
			# b goes to the stack before a, since %rcx is in the accumulator.
			b = copy(g, "%rdx", 8 * n, n)
			bb = "%d(%%rsp)" % (8 * n)
			frame = 8 * n
		if g.acopy:
			# a goes to the stack, and so does c when the registers run out.
			a = "0(%rsp)"
			b += copy(g, "%rsi", 0, n)
			frame += 8 * n
			if g.cslot:
				cs = ", %d(%%rsp)" % frame
				b.append("\tmovq\t%%rdi, %d(%%rsp)" % frame)
				frame += 8
			if g.wide:
				cs += ", %d(%%rsp)" % frame
				frame += 8
		b += ["", "\tMULM\t%s, %s, %s" % (a, bb, args(z, t0)),
			"\tFP_MUL_LOW\t%s, %s, %s, p0(%%rip), %d%s" % (a, bb, regs, rdc,
				cs)]
		o += function(name, set(z + g.t), b, frame=frame)
		if rdc == 0:
			o.append("")
	return o


def rdc_low(g):
	z, t, c, h = rdc_regs(g)
	# fp_rdcn_low(c, a): c = a/R mod p, for a < pR.
	if g.bcopy:
		return file_head(g) + [".global cdecl(fp_rdcn_low)", ""] + function(
			"fp_rdcn_low", set(z + t + c + h), ["\tmovq\t%rdi, 0(%rsp)",
			"\tFP_RDCN_LOW\t0(%%rsi), %s, p0(%%rip), %s" % (args(z, t),
				args(c, "0(%rsp)", h))], frame=8)
	return file_head(g) + [".global cdecl(fp_rdcn_low)", ""] + function(
		"fp_rdcn_low", set(z + t + c),
		["\tFP_RDCN_LOW\t0(%%rsi), %s, p0(%%rip), %s" % (args(z, t), args(c))])


def sqr_low(g):
	n = g.n
	o = file_head(g) + [".global cdecl(fp_sqrn_low)",
		".global cdecl(fp_sqrm_low)", ""]
	# fp_sqrn_low(c, a): c = a^2, and fp_sqrm_low(c, a): c = a^2/R mod p.
	for name, rdc in (("fp_sqrn_low", 0), ("fp_sqrm_low", 1)):
		if g.sqreg:
			z = ACC6[:2 * n - 1] + ["%rsi"]
			if not g.sqrdi:
				z = ACC6[:2 * n - 2] + ["%rdi", "%rsi"]
			o += function(name, set(z), ["\tFP_SQR_LOW\t0(%%rsi), %s, "
				"p0(%%rip), %d" % (args(z, "%rax", "%rcx"), rdc)],
				pushdi=not g.sqrdi)
		else:
			z = ACC6[:10]
			s = 16 * n * rdc
			b = ["\tFP_SQR_LOW\t0(%%rsi), %s, p0(%%rip), %d, 0(%%rsp)" % (
				args(z, "%rax", "%rcx"), rdc)]
			if g.bcopy:
				b = ["\tmovq\t%%rdi, %d(%%rsp)" % s] * rdc + [b[0] +
					", %d(%%rsp)" % s]
				s += 8 * rdc
				z = z + (["%rsi", "%rdi"] if rdc else [])
			o += function(name, set(z), b, frame=s)
		if rdc == 0:
			o.append("")
	return o


def rdcs(g, cs, c0, c1):
	"""Reduces the products at c0(%rsp) and c1(%rsp) to c and c + 8n, with
	the pointer to c at cs(%rsp)."""
	n = g.n
	rz, rt, rc, _ = rdc_regs(g)
	rr = args(rz, rt, "p0(%rip)", rc)
	if g.bcopy:
		rr += ", %d(%%rsp)" % cs
		return ["\tFP_RDCN_LOW\t%d(%%rsp), %s" % (c0, rr),
			"\tmovq\t%d(%%rsp), %%rdi" % cs, "\taddq\t$%d, %%rdi" % (8 * n),
			"\tmovq\t%%rdi, %d(%%rsp)" % cs,
			"\tFP_RDCN_LOW\t%d(%%rsp), %s" % (c1, rr)]
	return ["\tmovq\t%d(%%rsp), %%rdi" % cs,
		"\tFP_RDCN_LOW\t%d(%%rsp), %s" % (c0, rr),
		"\tmovq\t%d(%%rsp), %%rdi" % cs, "\taddq\t$%d, %%rdi" % (8 * n),
		"\tFP_RDCN_LOW\t%d(%%rsp), %s" % (c1, rr)]


def fpx_mul_low(g):
	n = g.n
	z = g.z
	rz, rt, rc, _ = rdc_regs(g)
	_, cs = g.fp2_frame()
	f = cs + (16 if g.qnr else 8) * n
	regs = args(z, g.t)
	used = set(z + g.t)

	def body(rdc, frame):
		"""Loads the operands of FP2_MUL_LOW, copying a to frame(%rsp), and b
		after it when %rcx is in the accumulator."""
		b = ["\tmovq\t%rdx, %rcx"]
		a, bb = "0(%rcx)", "0(%rsi)"
		if g.bcopy:
			a, bb = "%d(%%rsp)" % frame, "%d(%%rsp)" % (frame + 16 * n)
			b = copy(g, "%rdx", frame + 16 * n, 2 * n)
			b += copy(g, "%rsi", frame, 2 * n)
		elif g.acopy:
			a, bb = "%d(%%rsp)" % frame, "0(%rcx)"
			b += copy(g, "%rsi", frame, 2 * n)
		return b, "\tFP2_MUL_LOW\t%s, %s, %s, p0(%%rip), %d, 0(%%rsp)" % (a, bb,
			regs, rdc)
	ac = 32 * n if g.bcopy else 16 * n if g.acopy else 0
	o = file_head(g) + ["#ifdef FP2_ASM", "", ".global cdecl(fp2_muln_low)",
		""]
	b, call = body(0, f)
	# fp2_muln_low(c, a, b): c = a * b, with c[1] at RLC_DV_STRIDE bytes from
	# c[0]. fp2_mulm_low(c, a, b): c = a * b/R mod p, coefficient-wise,
	# interleaved under FP2_MUL_RDC and otherwise by reducing the product of
	# fp2_muln_low separately.
	o += function("fp2_muln_low", used, ["\tleaq\tRLC_DV_STRIDE(%rdi), %rax",
		"\tmovq\t%rax, 0(%rsp)"] + (["\tmovq\t%rdi, 8(%rsp)"] if g.cslot
		else []) + b + ["", call],
		frame=f + ac)
	o += ["", ".global cdecl(fp2_mulm_low)", "", "#ifdef FP2_MUL_RDC", ""]
	b, call = body(1, f)
	o += function("fp2_mulm_low", used, (["\tmovq\t%rdi, 8(%rsp)"] if
		g.cslot else []) + b + ["", call], frame=f + ac)
	# c goes where the scratch keeps c1 when reducing, which it does not here.
	c0 = f + ac
	c1 = c0 + 16 * n
	b, call = body(0, f)
	if g.cslot:
		ptrs = ["\tmovq\t%%rdi, %d(%%rsp)" % cs,
			"\tleaq\t%d(%%rsp), %%rax" % c0, "\tmovq\t%rax, 8(%rsp)"]
	else:
		ptrs = ["\tmovq\t%%rdi, %d(%%rsp)" % cs,
			"\tleaq\t%d(%%rsp), %%rdi" % c0]
	ptrs += ["\tleaq\t%d(%%rsp), %%rax" % c1, "\tmovq\t%rax, 0(%rsp)"]
	o += ["", "#else", ""]
	o += function("fp2_mulm_low", used | set(rz + rt + rc),
		ptrs + b + ["", call, ""] + rdcs(g, cs, c0, c1),
		frame=c1 + 16 * n)
	return o + ["", "#endif", "", "#endif"]


def fpx_sqr_low(g):
	n = g.n
	z = g.z
	rz, rt, rc, _ = rdc_regs(g)
	f = 24 * n + 16
	sp = 24 * n
	regs = args(z, g.t)
	used = set(z + g.t)
	# From 9 digits, %rsi is a temporary and a is read through %rcx, and
	# from 11, where %rcx is in the accumulator, from a copy after the
	# scratch.
	a = "0(%rcx)" if g.acopy else "0(%rsi)"
	mv = ["\tmovq\t%rsi, %rcx"] if g.acopy else []
	if g.bcopy:
		a = "%d(%%rsp)" % f
		mv = copy(g, "%rsi", f, 2 * n)
		f += 16 * n

	def call(rdc):
		return "\tFP2_SQR_LOW\t%s, %s, p0(%%rip), %d, 0(%%rsp)" % (a, regs, rdc)
	# Techniques and code heavily inspired from "Efficient Algorithms for Large
	# Prime Characteristic Fields and Their Application to Bilinear Pairings"
	# by Longa at TCHES'23. fp2_sqrn_low(c, a): c = a^2, with c[1] at
	# RLC_DV_STRIDE bytes from c[0]. fp2_sqrm_low(c, a): c = a^2/R mod p,
	# coefficient-wise, interleaved under FP2_SQR_RDC and otherwise by
	# reducing the product of fp2_sqrn_low separately.
	o = file_head(g) + ["#ifdef FP2_ASM",
		"", ".global cdecl(fp2_sqrn_low)", ".global cdecl(fp2_sqrm_low)", ""]
	b = ["\tleaq\tRLC_DV_STRIDE(%rdi), %rax", "\tmovq\t%%rax, %d(%%rsp)" % sp]
	if g.cslot:
		b.append("\tmovq\t%%rdi, %d(%%rsp)" % (sp + 8))
	o += function("fp2_sqrn_low", used, b + mv + ["", call(0)], frame=f)
	o += ["", "#ifdef FP2_SQR_RDC", ""]
	b = []
	if g.cslot:
		b = ["\tleaq\t%d(%%rdi), %%rax" % (8 * n),
			"\tmovq\t%%rax, %d(%%rsp)" % sp,
			"\tmovq\t%%rdi, %d(%%rsp)" % (sp + 8)]
	o += function("fp2_sqrm_low", used, b + mv + ["", call(1)], frame=f)
	# The product of fp2_sqrn_low goes after the scratch, with c kept at f.
	c0 = f + 8
	c1 = c0 + 16 * n
	if g.cslot:
		b = ["\tleaq\t%d(%%rsp), %%rax" % c0,
			"\tmovq\t%%rax, %d(%%rsp)" % (sp + 8)]
	else:
		b = ["\tleaq\t%d(%%rsp), %%rdi" % c0]
	b = ["\tmovq\t%%rdi, %d(%%rsp)" % f] + b + ["\tleaq\t%d(%%rsp), %%rax" % c1,
		"\tmovq\t%%rax, %d(%%rsp)" % sp]
	o += ["", "#else", ""]
	o += function("fp2_sqrm_low", used | set(rz + rt + rc),
		b + mv + ["", call(0), ""] + rdcs(g, f, c0, c1),
		frame=c1 + 16 * n)
	return o + ["", "#endif", "", "#endif"]

FILES = [("relic_fp_add_low.s", add_low), ("relic_fp_shift_low.s",
	shift_low), ("relic_fp_mul_low.s", mul_low), ("relic_fp_rdc_low.s",
	rdc_low), ("relic_fp_sqr_low.s", sqr_low), ("relic_fpx_mul_low.s",
	fpx_mul_low), ("relic_fpx_sqr_low.s", fpx_sqr_low)]


def write(n, out):
	"""Writes the backend for n digits to out. FP2_MUL0_LOW with RDC = 1
	keeps the real part as a signed value in (-p, 2p), which only fits n
	digits when 2p < 2^(64n - 1), that is, p < 2^(64n - 2): FP2_MUL_RDC.
	FP2_SQR_LOW with RDC = 1 multiplies by a0 - a1 + p < 2p with interleaved
	reduction, whose intermediate values stay below 2^64 x (3p) and must fit
	n + 1 digits, so it needs 3p < 2^(64n): FP2_SQR_RDC. The Fp2 functions
	read both coordinates from one contiguous vector, hence FP2_ASM only with
	ALLOC = AUTO. For u^2 = -q, an unreduced product stays below pR when
	(3q + 1)p < R, as c0 of a square is below 2(q + 1)p^2 + (q - 1)p^2, and
	the halving of q - 1 needs q odd."""
	g = Backend(n)
	# A Montgomery step leaves (z + m x p)/2^64 < 2^(64n - 64) + p, which
	# stays below 2^(64n) for p < 2^(64n) - 2^(64n - 64). Without the top
	# word, the final subtractions also need p < 2^(64n - 1).
	for e in PRIMES[n]:
		p = int(e[1], 16)
		assert p < (1 << (64 * n)) - (1 << (64 * n - 64))
		assert g.wide or p < 1 << (64 * n - 1)
		if e[0] in QNRS:
			q = QNRS[e[0]]
			assert q % 2 == 1 and (3 * q + 1) * p < 1 << (64 * n)
	guard = "#if %s\n#define %s\n#endif\n"
	guards = [guard % ("P%d < 0x4000000000000000" % (n - 1), "FP2_MUL_RDC"),
		guard % ("P%d < 0x5555555555555555" % (n - 1), "FP2_SQR_RDC"),
		guard % ("defined(FP_QNRES) && RLC_ALLOC == RLC_AUTO", "FP2_ASM")]
	if g.qnr:
		guards[0:0] = [guard % ("!defined(FP_QNRES) && defined(QNR)",
			"FP2_QNR\tQNR")]
		guards[-1] = guard % ("(defined(FP_QNRES) || defined(FP2_QNR)) && "
			"RLC_ALLOC == RLC_AUTO", "FP2_ASM")
	# MULRDC1 reads an all-ones word, and at 12 digits a zero word, local to
	# each object.
	ones = ["#if defined(__APPLE__)\n.section __TEXT,__const\n#else\n"
		".section .rodata\n#endif\n.p2align 3\nones:\t.quad\t-1\n" +
		("zero:\t.quad\t0\n" if g.wide else "")]
	macro_s(g, out, guards if not g.wide else [], ones if g.onet else [],
		g.parts())
	write_files(g, out, [x for x in FILES if not g.wide or "fpx" not in x[0]])


def main():
	if len(sys.argv) != 3:
		sys.exit(__doc__)
	write(int(sys.argv[1]), sys.argv[2])

if __name__ == "__main__":
	main()
