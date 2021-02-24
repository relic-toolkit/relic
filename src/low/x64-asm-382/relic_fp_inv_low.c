/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2017 RELIC Authors
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
 * Implementation of the low-level inversion functions.
 *
 * @&version $Id$
 * @ingroup fp
 */

#include <gmp.h>

#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_invm_low(dig_t *c, const dig_t *a) {
	mp_size_t cn;
	rlc_align dig_t s[RLC_FP_DIGS], t[2 * RLC_FP_DIGS], u[RLC_FP_DIGS + 1];

#if FP_RDC == MONTY
	dv_zero(t + RLC_FP_DIGS, RLC_FP_DIGS);
	dv_copy(t, a, RLC_FP_DIGS);
	fp_rdcn_low(u, t);
#else
	fp_copy(u, a);
#endif

	dv_copy(s, fp_prime_get(), RLC_FP_DIGS);

	mpn_gcdext(t, c, &cn, u, RLC_FP_DIGS, s, RLC_FP_DIGS);
	if (cn < 0) {
		dv_zero(c - cn, RLC_FP_DIGS + cn);
		mpn_sub_n(c, fp_prime_get(), c, RLC_FP_DIGS);
	} else {
		dv_zero(c + cn, RLC_FP_DIGS - cn);
	}

#if FP_RDC == MONTY
	dv_zero(t, RLC_FP_DIGS);
	dv_copy(t + RLC_FP_DIGS, c, RLC_FP_DIGS);
	mpn_tdiv_qr(u, c, 0, t, 2 * RLC_FP_DIGS, fp_prime_get(), RLC_FP_DIGS);
#endif
}

dig_t pre[] = {
	0x1DEBC64EAF0DC434, 0xE48833A08DD9622E, 0x5F2570D387DEAF3C,
	0x6F747359CFA672ED, 0x4C414DE6AE2CFE61, 0X69FE121E110B533
};

#include <x86intrin.h>

/*
 * Compute (a*f+b*g)/2^31. Parameters f and g are provided with an
 * unsigned type, but they are signed integers in the -2^31..+2^31
 * range. Values a, b and d are not field elements, but signed 256-bit
 * integers (i.e. top bit is the sign bit) which are nonnegative (value
 * is between 0 and 2^255-1). The division by 2^31 is assumed to be
 * exact (low j bits of a*f+b*g are dropped). The result is assumed to
 * fit in 256 bits, including the sign bit (truncation is applied on
 * higher bits).
 *
 * If the result turns out to be negative, then it is negated. Returned
 * value is 1 if the result was negated, 0 otherwise.
 */
static inline uint64_t s384_lin_div31_abs(dig_t *d, const dig_t *a, const dig_t *b,
	dig_t f, dig_t g) {
	fp_t ta, tb;
	dig_t sf, sg, d0, d1, d2, d3, d4, d5, t;
	unsigned __int128 z;
	unsigned char cc;

	/*
	 * If f < 0, replace f with -f but keep the sign in sf.
	 * Similarly for g.
	 */
	sf = f >> 63;
	f = (f ^ -sf) + sf;
	sg = g >> 63;
	g = (g ^ -sg) + sg;

	/*
	 * Apply signs sf and sg to a and b, respectively.
	 */
	cc = _addcarry_u64(0, a[0] ^ -sf, sf, (unsigned long long *)&ta[0]);
	cc = _addcarry_u64(cc, a[1] ^ -sf, 0, (unsigned long long *)&ta[1]);
	cc = _addcarry_u64(cc, a[2] ^ -sf, 0, (unsigned long long *)&ta[2]);
	cc = _addcarry_u64(cc, a[3] ^ -sf, 0, (unsigned long long *)&ta[3]);
	cc = _addcarry_u64(cc, a[4] ^ -sf, 0, (unsigned long long *)&ta[4]);
	cc = _addcarry_u64(cc, a[5] ^ -sf, 0, (unsigned long long *)&ta[5]);

	cc = _addcarry_u64(0, b[0] ^ -sg, sg, (unsigned long long *)&tb[0]);
	cc = _addcarry_u64(cc, b[1] ^ -sg, 0, (unsigned long long *)&tb[1]);
	cc = _addcarry_u64(cc, b[2] ^ -sg, 0, (unsigned long long *)&tb[2]);
	cc = _addcarry_u64(cc, b[3] ^ -sg, 0, (unsigned long long *)&tb[3]);
	cc = _addcarry_u64(cc, b[4] ^ -sg, 0, (unsigned long long *)&tb[4]);
	cc = _addcarry_u64(cc, b[5] ^ -sg, 0, (unsigned long long *)&tb[5]);

	/*
	 * Now that f and g are nonnegative, compute a*f+b*g into
	 * d0:d1:d2:d3:t. Since f and g are at most 2^31, we can
	 * add two 128-bit products with no overflow (they are actually
	 * 95 bits each at most).
	 */
	z = (unsigned __int128)ta[0] * (unsigned __int128)f
		+ (unsigned __int128)tb[0] * (unsigned __int128)g;
	d0 = (unsigned long long)z;
	t = (unsigned long long)(z >> 64);
	z = (unsigned __int128)ta[1] * (unsigned __int128)f
		+ (unsigned __int128)tb[1] * (unsigned __int128)g
		+ (unsigned __int128)t;
	d1 = (unsigned long long)z;
	t = (unsigned long long)(z >> 64);
	z = (unsigned __int128)ta[2] * (unsigned __int128)f
		+ (unsigned __int128)tb[2] * (unsigned __int128)g
		+ (unsigned __int128)t;
	d2 = (unsigned long long)z;
	t = (unsigned long long)(z >> 64);
	z = (unsigned __int128)ta[3] * (unsigned __int128)f
		+ (unsigned __int128)tb[3] * (unsigned __int128)g
		+ (unsigned __int128)t;
	d3 = (unsigned long long)z;
	z = (unsigned __int128)ta[4] * (unsigned __int128)f
		+ (unsigned __int128)tb[4] * (unsigned __int128)g
		+ (unsigned __int128)t;
	d4 = (unsigned long long)z;
	z = (unsigned __int128)ta[5] * (unsigned __int128)f
		+ (unsigned __int128)tb[5] * (unsigned __int128)g
		+ (unsigned __int128)t;
	d5 = (unsigned long long)z;
	t = (unsigned long long)(z >> 64);

	/*
	 * Don't forget the signs: if a < 0, then the result is
	 * overestimated by 2^256*f; similarly, if b < 0, then the
	 * result is overestimated by 2^256*g. We thus must subtract
	 * 2^256*(sa*f+sb*g), where sa and sb are the signs of a and b,
	 * respectively.
	 */
	t -= -(unsigned long long)(ta[5] >> 63) & f;
	t -= -(unsigned long long)(tb[5] >> 63) & g;

	/*
	 * Apply the shift.
	 */
	d0 = (d0 >> 31) | (d1 << 33);
	d1 = (d1 >> 31) | (d2 << 33);
	d2 = (d2 >> 31) | (d3 << 33);
	d3 = (d3 >> 31) | (d4 << 33);
	d4 = (d4 >> 31) | (d5 << 33);
	d5 = (d5 >> 31) | (t << 33);

	/*
	 * Perform conditional negation, if the result is negative.
	 */
	t >>= 63;
	cc = _addcarry_u64(0, d0 ^ -t, t, (unsigned long long *)&d[0]);
	cc = _addcarry_u64(cc, d1 ^ -t, 0, (unsigned long long *)&d[1]);
	cc = _addcarry_u64(cc, d2 ^ -t, 0, (unsigned long long *)&d[2]);
	cc = _addcarry_u64(cc, d3 ^ -t, 0, (unsigned long long *)&d[3]);
	cc = _addcarry_u64(cc, d4 ^ -t, 0, (unsigned long long *)&d[4]);
	(void)_addcarry_u64(cc, d3 ^ -t, 0, (unsigned long long *)&d[5]);

	return t;
}

void fp_condneg(dig_t *d, const dig_t *a, int ctl) {
	fp_t t;

	fp_neg(&t, a);
	d[0] = a[0] ^ (-ctl & (a[0] ^ t[0]));
	d[1] = a[1] ^ (-ctl & (a[1] ^ t[1]));
	d[2] = a[2] ^ (-ctl & (a[2] ^ t[2]));
	d[3] = a[3] ^ (-ctl & (a[3] ^ t[3]));
	d[4] = a[4] ^ (-ctl & (a[4] ^ t[4]));
	d[5] = a[5] ^ (-ctl & (a[5] ^ t[5]));
}

/*
 * Compute u*f+v*g (modulo p). Parameters f and g are provided with
 * an unsigned type, but they are signed integers in the -2^62..+2^62 range.
 */
static inline void fp_lin(dig_t *d, const dig_t *u, const dig_t *v, dig_t f, dig_t g) {
	fp_t t, tu, tv;
	dig_t _u[2 * RLC_FP_DIGS] = { 0 }, _v[2 * RLC_FP_DIGS] = { 0 };
	dig_t sf, sg, d0, d1, d2, d3, d4, d5;
	unsigned __int128 z;
	unsigned char cc;

	/*
	 * If f < 0, replace f with -f but keep the sign in sf.
	 * Similarly for g.
	 */
	sf = f >> 63;
	f = (f ^ -sf) + sf;
	sg = g >> 63;
	g = (g ^ -sg) + sg;

	/*
	 * Apply signs sf and sg to u and v.
	 */
	fp_condneg(&tu, u, sf);
	fp_condneg(&tv, v, sg);

	bn_mul1_low(_u, tu, f, RLC_FP_DIGS);
	bn_mul1_low(_v, tv, g, RLC_FP_DIGS);

	_u[RLC_FP_DIGS + 2] = bn_addn_low(_u, _u, _v, RLC_FP_DIGS + 1);
	fp_zero(t);
	dv_zero(_v, 2 * RLC_FP_DIGS);
	dv_copy(_v, fp_prime_get(), RLC_FP_DIGS);
	//bn_divn_low(t, d, _u, RLC_FP_DIGS+2, _v, RLC_FP_DIGS);
	fp_rdc(d, _u);
	fp_mul(d, d, core_get()->conv.dp);
}

/* ================================================================== */
/*
 * Assembly code for the inner loop (generic version, can run for up to
 * 62 iterations).
 *    rax   f0
 *    rbx   g0
 *    rcx   f1
 *    rdx   g1
 *    rsi   xa
 *    rdi   xb
 */
#define INV_INNER \
	/* \
	 * Copy old values into extra registers \
	 *    r10   f0 \
	 *    r11   g0 \
	 *    r12   f1 \
	 *    r13   g1 \
	 *    r14   xa \
	 *    r15   xb \
	 */ \
	"movq	%%rax, %%r10\n\t" \
	"movq	%%rbx, %%r11\n\t" \
	"movq	%%rcx, %%r12\n\t" \
	"movq	%%rdx, %%r13\n\t" \
	"movq	%%rsi, %%r14\n\t" \
	"movq	%%rdi, %%r15\n\t" \
 \
	/* Conditional swap if xa < xb */ \
	"cmpq	%%rdi, %%rsi\n\t" \
	"cmovb	%%r15, %%rsi\n\t" \
	"cmovb	%%r14, %%rdi\n\t" \
	"cmovb	%%r12, %%rax\n\t" \
	"cmovb	%%r10, %%rcx\n\t" \
	"cmovb	%%r13, %%rbx\n\t" \
	"cmovb	%%r11, %%rdx\n\t" \
 \
	/* Subtract xb from xa */ \
	"subq	%%rdi, %%rsi\n\t" \
	"subq	%%rcx, %%rax\n\t" \
	"subq	%%rdx, %%rbx\n\t" \
 \
	/* If xa was even, override the operations above */ \
	"testl	$1, %%r14d\n\t" \
	"cmovz	%%r10, %%rax\n\t" \
	"cmovz	%%r11, %%rbx\n\t" \
	"cmovz	%%r12, %%rcx\n\t" \
	"cmovz	%%r13, %%rdx\n\t" \
	"cmovz	%%r14, %%rsi\n\t" \
	"cmovz	%%r15, %%rdi\n\t" \
 \
	/* Now xa is even; apply shift. */ \
	"shrq	$1, %%rsi\n\t" \
	"addq	%%rcx, %%rcx\n\t" \
	"addq	%%rdx, %%rdx\n\t"

/*
 * Alternate assembly code for the inner loop. This one groups values
 * by pairs and is slightly faster, but it is good only for up to 31
 * iterations.
 *    rax   f0:g0  (f0 = low half, g0 = high half)
 *    rcx   f1:g1
 *    rdx   0x7FFFFFFF7FFFFFFF
 *    rsi   xa
 *    rdi   xb
 */
#define INV_INNER_FAST \
	/* \
	 * Copy old values into extra registers \
	 *    r10   f0:g0 \
	 *    r12   f1:g1 \
	 *    r14   xa \
	 *    r15   xb \
	 */ \
	"movq	%%rax, %%r10\n\t" \
	"movq	%%rcx, %%r12\n\t" \
	"movq	%%rsi, %%r14\n\t" \
	"movq	%%rdi, %%r15\n\t" \
 \
	/* Conditional swap if xa < xb */ \
	"cmpq	%%rdi, %%rsi\n\t" \
	"cmovb	%%r15, %%rsi\n\t" \
	"cmovb	%%r14, %%rdi\n\t" \
	"cmovb	%%r12, %%rax\n\t" \
	"cmovb	%%r10, %%rcx\n\t" \
 \
	/* Subtract xb from xa */ \
	"subq	%%rdi, %%rsi\n\t" \
	"subq	%%rcx, %%rax\n\t" \
	"addq	%%rdx, %%rax\n\t" \
 \
	/* If xa was even, override the operations above */ \
	"testl	$1, %%r14d\n\t" \
	"cmovz	%%r10, %%rax\n\t" \
	"cmovz	%%r12, %%rcx\n\t" \
	"cmovz	%%r14, %%rsi\n\t" \
	"cmovz	%%r15, %%rdi\n\t" \
 \
	/* Now xa is even; apply shift. */ \
	"shrq	$1, %%rsi\n\t" \
	"addq	%%rcx, %%rcx\n\t" \
	"subq	%%rdx, %%rcx\n\t"

/* ================================================================== */

/* see gf25519.h */
void fp_invm_low2(dig_t *d, const dig_t *y) {
	fp_t a, b, u, v, t;
	dig_t f0, f1, g0, g1, xa, xb, nega, negb;
	int i;

	/* Convert a from Montgomery form. */
	fp_copy(t, y);
	fp_rdcn_low(a, t);
	dv_copy(b, fp_prime_get(), RLC_FP_DIGS);
	fp_zero(u);
	u[0] = 1;
	fp_zero(v);

	/*
	 * Generic loop first does 23*31 = 713 iterations.
	 */
	for (i = 0; i < 23; i ++) {
		dig_t m1, m2, m3, m4, m5, tnz1, tnz2, tnz3, tnz4, tnz5;
		dig_t tnzm, tnza, tnzb, snza, snzb;
		dig_t s, sm;
		fp_t na, nb, nu, nv;

		/*
		 * Get approximations of a and b over 64 bits:
		 *  - If len(a) <= 64 and len(b) <= 64, then we just
		 *    use the value (low limb).
		 *  - Otherwise, with n = max(len(a), len(b)), we use:
		 *       (a mod 2^31) + 2^33*(floor(a / 2^(n-33)))
		 *       (b mod 2^31) + 2^33*(floor(b / 2^(n-33)))
		 * I.e. we remove the "middle bits".
		 */
		m5 = a[5] | b[5];
		m4 = a[4] | b[4];
		m3 = a[3] | b[3];
		m2 = a[2] | b[2];
		m1 = a[1] | b[1];
		tnz5 = -((m5 | -m5) >> 63);
		tnz4 = -((m4 | -m4) >> 63) & ~tnz5;
		tnz3 = -((m3 | -m3) >> 63) & ~tnz5 & ~tnz4;
		tnz2 = -((m2 | -m2) >> 63) & ~tnz5 & ~tnz4 & ~tnz3;
		tnz1 = -((m1 | -m1) >> 63) & ~tnz5 & ~tnz4 & ~tnz3 & ~tnz2;
		tnzm = (m5 & tnz5) | (m4 & tnz4) | (m3 & tnz3) | (m2 & tnz2) | (m1 & tnz1);
		tnza = (a[5] & tnz5) | (a[4] & tnz4) | (a[3] & tnz3) | (a[2] & tnz2) | (a[1] & tnz1);
		tnzb = (b[5] & tnz5) | (b[4] & tnz4) | (b[3] & tnz3) | (b[2] & tnz2) | (b[1] & tnz1);
		snza = (a[4] & tnz5) | (a[3] & tnz4) | (a[2] & tnz3) | (a[1] & tnz2) | (a[0] & tnz1);
		snzb = (b[4] & tnz5) | (b[3] & tnz4) | (b[2] & tnz3) | (b[1] & tnz2) | (b[0] & tnz1);

		/*
		 * If both len(a) <= 64 and len(b) <= 64, then:
		 *    tnzm = 0
		 *    tnza = 0, snza = 0, tnzb = 0, snzb = 0
		 *    tnzm = 0
		 * Otherwise:
		 *    tnzm != 0, length yields value of n
		 *    tnza contains the top limb of a, snza the second limb
		 *    tnzb contains the top limb of b, snzb the second limb
		 *
		 * We count the number of leading zero bits in tnzm:
		 *  - If s <= 31, then the top 31 bits can be extracted
		 *    from tnza and tnzb alone.
		 *  - If 32 <= s <= 63, then we need some bits from snza
		 *    as well.
		 *
		 * We rely on the fact shifts don't reveal the shift count
		 * through side channels. This would not have been true on
		 * the Pentium IV, but it is true on all known x86 CPU that
		 * have 64-bit support and implement the LZCNT opcode.
		 */
		s = util_bits_dig(tnzm);
		sm = -((unsigned long long)(31 - s) >> 63);
		tnza ^= sm & (tnza ^ ((tnza << 32) | (snza >> 32)));
		tnzb ^= sm & (tnzb ^ ((tnzb << 32) | (snzb >> 32)));
		s -= 32 & sm;
		tnza <<= s;
		tnzb <<= s;

		/*
		 * At this point:
		 *  - If len(a) <= 64 and len(b) <= 64, then:
		 *       tnza = 0
		 *       tnzb = 0
		 *       tnz1 = tnz2 = tnz3 = 0
		 *  - Otherwise, we need to use the top 33 bits of tnza
		 *    and tnzb in combination with the low 31 bits of
		 *    a.v0 and b.v0, respectively.
		 */
		tnza |= a[0] & ~(tnz1 | tnz2 | tnz3 | tnz4 | tnz5);
		tnzb |= b[0] & ~(tnz1 | tnz2 | tnz3 | tnz4 | tnz5);
		xa = (a[0] & 0x7FFFFFFF) | (tnza & 0xFFFFFFFF80000000);
		xb = (b[0] & 0x7FFFFFFF) | (tnzb & 0xFFFFFFFF80000000);

		/*
		 * We can now run the binary GCD on xa and xb for 31
		 * rounds. We unroll it a bit (two rounds per loop
		 * iteration), it seems to save about 250 cycles in
		 * total on a Coffee Lake core.
		 */

		__asm__ __volatile__ (
			/*
			 * f0 = 1
			 * g0 = 0
			 * f1 = 0
			 * g1 = 1
			 * We add 0x7FFFFFFF to all four values, and
			 * group them by pairs into registers.
			 */
			"movq	$0x7FFFFFFF7FFFFFFF, %%rdx\n\t"
			"movq	$0x7FFFFFFF80000000, %%rax\n\t"
			"movq	$0x800000007FFFFFFF, %%rcx\n\t"

			/*
			 * Do the loop. Tests on a Coffee Lake core seem
			 * to indicate that not unrolling is best here.
			 * Loop counter is in r8.
			 */
			"movl	$31, %%r8d\n\t"
			"0:\n\t"
			INV_INNER_FAST
			"decl	%%r8d\n\t"
			"jnz	0b\n\t"

			/*
			 * Split f0, f1, g0 and g1 into separate variables.
			 */
			"movq	%%rax, %%rbx\n\t"
			"movq	%%rcx, %%rdx\n\t"
			"shrq	$32, %%rbx\n\t"
			"shrq	$32, %%rdx\n\t"
			"orl	%%eax, %%eax\n\t"
			"orl	%%ecx, %%ecx\n\t"
			"subq	$0x7FFFFFFF, %%rax\n\t"
			"subq	$0x7FFFFFFF, %%rbx\n\t"
			"subq	$0x7FFFFFFF, %%rcx\n\t"
			"subq	$0x7FFFFFFF, %%rdx\n\t"

			: "=a" (f0), "=b" (g0), "=c" (f1), "=d" (g1),
			  "=S" (xa), "=D" (xb)
			: "4" (xa), "5" (xb)
			: "cc", "r8", "r10", "r11",
			  "r12", "r13", "r14", "r15" );

		/*
		 * We now need to propagate updates to a, b, u and v.
		 */
		nega = s384_lin_div31_abs(&na, &a, &b, f0, g0);
		negb = s384_lin_div31_abs(&nb, &a, &b, f1, g1);
		f0 = (f0 ^ -nega) + nega;
		g0 = (g0 ^ -nega) + nega;
		f1 = (f1 ^ -negb) + negb;
		g1 = (g1 ^ -negb) + negb;
		fp_lin(nu, u, v, f0, g0);
		fp_lin(nv, u, v, f1, g1);
		fp_copy(a, na);
		fp_copy(b, nb);
		fp_copy(u, nu);
		fp_copy(v, nv);
	}

	/*
	 * At that point, if y is invertible, then the final GCD is 1,
	 * and len(a) + len(b) <= 45, so it is known that the values
	 * fully fit in a single register each. We can do the remaining
	 * 44 iterations in one go (they are exact, no approximation
	 * here). In fact, we can content ourselves with 43 iterations,
	 * because when arriving at the last iteration, we know that a = 0
	 * or 1 and b = 1 (the final state of the algorithm is that a = 0
	 * and b is the GCD of y and q), so there would be no swap. Since
	 * we only care about the update factors f1 and g1, we can simply
	 * avoid the final iteration.
	 *
	 * The update values f1 and g1, for v, will be up to 2^43 (in
	 * absolute value) but this is supported by gf_lin().
	 *
	 * If y is not invertible, then b does not necessarily fit in a
	 * single word. Thus, an extra verification step with a
	 * multiplication is performed, to check that the inverse is
	 * really an inverse. This step is not needed if the modulus p
	 * is prime, because, in that case, a non-invertible y can only
	 * be zero, in which case a = 0 and v = 0 throughout, which is
	 * the expected result.
	 */
	xa = a[0];
	xb = b[0];

	__asm__ __volatile__ (
		/* Set f0, g0, f1 and g1. */
		"movl	$1, %%eax\n\t"
		"xorl	%%ebx, %%ebx\n\t"
		"xorl	%%ecx, %%ecx\n\t"
		"movl	$1, %%edx\n\t"

		/* Do 47 iterations. We need to use the generic code
		   with one update factor per register, since we do
		   more than 31 iterations. Unrolling two iterations
		   in the loop appears to save a few cycles. */
		"movl	$23, %%r8d\n\t"
		"0:\n\t"
		INV_INNER
		INV_INNER
		"decl	%%r8d\n\t"
		"jnz	0b\n\t"
		INV_INNER

		: "=a" (f0), "=b" (g0), "=c" (f1), "=d" (g1),
		  "=S" (xa), "=D" (xb)
		: "4" (xa), "5" (xb)
		: "cc", "r8", "r10", "r11",
		  "r12", "r13", "r14", "r15" );

	fp_lin(v, u, v, f1, g1);

	/*
	 * Result is correct if source operand was invertible, i.e.
	 * distinct from zero (since all non-zero values are invertible
	 * modulo a prime integer); the inverse is then also non-zero.
	 * If the source was zero, then the result is zero as well. We
	 * can thus test d instead of a.
	 */
	fp_mul(d, v, pre);
}
