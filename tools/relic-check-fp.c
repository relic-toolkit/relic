/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Differential test of the low-level prime field functions against GMP, for
 * checking a new arithmetic backend. Every function of relic_fp_low.h that an
 * x64-asm-Nl backend exports is compared on random and edge-case inputs, and
 * so are the Fp2 functions when FP_QNRES is defined, as u^2 = -1 then.
 *
 * Build it against a static library of the backend, for example:
 *   cmake -B build -DARITH=x64-asm-12l -DFP_PRIME=768 -DBN_PRECI=2048 \
 *     -DTESTS=0 -DBENCH=0 -DSHLIB=off && cmake --build build -t relic_s
 *   gcc -O1 -Iinclude -Iinclude/low -Ibuild/include tools/relic-check-fp.c \
 *     build/lib/librelic_s.a -lgmp -o check-fp && ./check-fp
 */

#include <stdio.h>
#include <string.h>
#include <gmp.h>

#include "relic.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

#define N	RLC_FP_DIGS

static mpz_t P, R, T, U, V;
static int fails = 0;
static gmp_randstate_t rs;

static void get(mpz_t z, const dig_t *a, int n) {
	mpz_import(z, n, -1, sizeof(dig_t), 0, 0, a);
}

static void put(dig_t *a, const mpz_t z, int n) {
	size_t cnt = 0;
	memset(a, 0, n * sizeof(dig_t));
	mpz_export(a, &cnt, -1, sizeof(dig_t), 0, 0, z);
}

static void check(const char *name, const dig_t *got, const mpz_t want, int n) {
	mpz_t g;
	mpz_init(g);
	get(g, got, n);
	if (mpz_cmp(g, want) != 0) {
		if (fails < 20) {
			gmp_printf("FAIL %s\n  got  %Zx\n  want %Zx\n", name, g, want);
		}
		fails++;
	}
	mpz_clear(g);
}

static void checkd(const char *name, dig_t got, dig_t want) {
	if (got != want) {
		if (fails < 20) {
			printf("FAIL %s carry got %lx want %lx\n", name, (unsigned long)got,
					(unsigned long)want);
		}
		fails++;
	}
}

#if defined(FP_QNRES)
/* Checks an unreduced result: congruent to want mod p and below pR. */
static void checkc(const char *name, const dig_t *got, const mpz_t want,
		const mpz_t pr) {
	mpz_t g, w;
	mpz_inits(g, w, NULL);
	get(g, got, 2 * N);
	mpz_mod(w, want, P);
	mpz_mod(T, g, P);
	if (mpz_cmp(T, w) != 0 || mpz_cmp(g, pr) >= 0) {
		if (fails < 20) {
			gmp_printf("FAIL %s\n  got  %Zx\n  want %Zx mod p, below pR\n",
					name, g, w);
		}
		fails++;
	}
	mpz_clears(g, w, NULL);
}
#endif

/* Random element in [0, bound), or an edge case depending on k. */
static void elem(mpz_t z, const mpz_t bound, int k) {
	switch (k % 8) {
		case 0: mpz_set_ui(z, 0); break;
		case 1: mpz_set_ui(z, 1); break;
		case 2: mpz_sub_ui(z, bound, 1); break;
		case 3: mpz_sub_ui(z, bound, 2); break;
		default: mpz_urandomm(z, rs, bound); break;
	}
}

int main(void) {
	dig_t a[2 * N], b[2 * N], c[2 * N], e[2 * N], d, w;
	mpz_t x, y, z, B1, B2, PR;
	int iters = 20000;

	core_init();
	if (fp_param_set_any() != RLC_OK) {
		printf("no prime\n");
		return 2;
	}
	gmp_randinit_default(rs);
	gmp_randseed_ui(rs, 12345);
	mpz_inits(P, R, T, U, V, x, y, z, B1, B2, PR, NULL);
	get(P, fp_prime_get(), N);
	mpz_ui_pow_ui(B1, 2, 64 * N);
	mpz_ui_pow_ui(B2, 2, 128 * N);
	mpz_set(R, B1);
	mpz_mul(PR, P, R);
	mpz_invert(U, R, P);

	for (int k = 0; k < iters; k++) {
		/* Unreduced operations on N and 2N digits. */
		elem(x, B1, k); elem(y, B1, k / 8);
		put(a, x, N); put(b, y, N);
		mpz_add(z, x, y);
		d = fp_addn_low(c, a, b);
		mpz_mod(T, z, B1); check("addn", c, T, N);
		checkd("addn", d, mpz_cmp(z, B1) >= 0);
		mpz_sub(z, x, y);
		d = fp_subn_low(c, a, b);
		mpz_mod(T, z, B1); check("subn", c, T, N);
		checkd("subn", d, mpz_sgn(z) < 0);
		w = (k & 1) ? (dig_t)-1 : (dig_t)k;
		mpz_add_ui(z, x, w);
		d = fp_add1_low(c, a, w);
		mpz_mod(T, z, B1); check("add1", c, T, N);
		checkd("add1", d, mpz_cmp(z, B1) >= 0);
		mpz_sub_ui(z, x, w);
		d = fp_sub1_low(c, a, w);
		mpz_mod(T, z, B1); check("sub1", c, T, N);
		checkd("sub1", d, mpz_sgn(z) < 0);
		mpz_mul_2exp(z, x, 1);
		d = fp_dbln_low(c, a);
		mpz_mod(T, z, B1); check("dbln", c, T, N);
		checkd("dbln", d, mpz_cmp(z, B1) >= 0);
		memcpy(c, a, sizeof(dig_t) * N);
		d = fp_rsh1_low(c, c);
		mpz_fdiv_q_2exp(T, x, 1); check("rsh1", c, T, N);
		checkd("rsh1", d, mpz_odd_p(x));
		d = fp_lsh1_low(c, a);
		mpz_mul_2exp(T, x, 1); mpz_mod(T, T, B1); check("lsh1", c, T, N);
		checkd("lsh1", d, mpz_tstbit(x, 64 * N - 1));
		mpz_mul(T, x, y);
		fp_muln_low(c, a, b); check("muln", c, T, 2 * N);
		mpz_mul(T, x, x);
		fp_sqrn_low(c, a); check("sqrn", c, T, 2 * N);
		elem(x, B2, k); elem(y, B2, k / 8);
		put(a, x, 2 * N); put(b, y, 2 * N);
		mpz_add(z, x, y);
		d = fp_addd_low(c, a, b);
		mpz_mod(T, z, B2); check("addd", c, T, 2 * N);
		checkd("addd", d, mpz_cmp(z, B2) >= 0);
		mpz_sub(z, x, y);
		d = fp_subd_low(c, a, b);
		mpz_mod(T, z, B2); check("subd", c, T, 2 * N);
		checkd("subd", d, mpz_sgn(z) < 0);

		/* Modular operations on reduced inputs. */
		elem(x, P, k); elem(y, P, k / 8);
		put(a, x, N); put(b, y, N);
		mpz_add(T, x, y); mpz_mod(T, T, P);
		fp_addm_low(c, a, b); check("addm", c, T, N);
		mpz_sub(T, x, y); mpz_mod(T, T, P);
		fp_subm_low(c, a, b); check("subm", c, T, N);
		mpz_neg(T, x); mpz_mod(T, T, P);
		fp_negm_low(c, a); check("negm", c, T, N);
		mpz_mul_2exp(T, x, 1); mpz_mod(T, T, P);
		fp_dblm_low(c, a); check("dblm", c, T, N);
		mpz_set_ui(z, 2); mpz_invert(z, z, P);
		mpz_mul(T, x, z); mpz_mod(T, T, P);
		fp_hlvm_low(c, a); check("hlvm", c, T, N);
		w = (dig_t)(k * 0x9E3779B97F4A7C15ULL) >> 1;
		mpz_mul_ui(T, x, w); mpz_mod(T, T, P);
		fp_mul1_low(c, a, w); check("mul1", c, T, N);
		mpz_mul(T, x, y); mpz_mul(T, T, U); mpz_mod(T, T, P);
		fp_mulm_low(c, a, b); check("mulm", c, T, N);
		mpz_mul(T, x, x); mpz_mul(T, T, U); mpz_mod(T, T, P);
		fp_sqrm_low(c, a); check("sqrm", c, T, N);

#if defined(FP_QNRES)
		/* Quadratic extension with u^2 = -1, whose functions the Fp2 assembly
		 * of a backend replaces. FP_QNRES only fits primes 3 mod 4. */
		if (mpz_fdiv_ui(P, 4) == 3) {
			fp2_t a2, b2, c2;
			dv2_t d2;
			mpz_t x1, y1, re, im;

			mpz_inits(x1, y1, re, im, NULL);
			elem(x1, P, k / 3); elem(y1, P, k / 5);
			put(a2[0], x, N); put(a2[1], x1, N);
			put(b2[0], y, N); put(b2[1], y1, N);
			/* (x + x1 u)(y + y1 u) = (x y - x1 y1) + (x y1 + x1 y) u. */
			mpz_mul(re, x, y); mpz_submul(re, x1, y1);
			mpz_mul(im, x, y1); mpz_addmul(im, x1, y);
			fp2_muln_low(d2, a2, b2);
			checkc("fp2_muln[0]", d2[0], re, PR);
			checkc("fp2_muln[1]", d2[1], im, PR);
			fp2_mulm_low(c2, a2, b2);
			mpz_mul(T, re, U); mpz_mod(T, T, P);
			check("fp2_mulm[0]", c2[0], T, N);
			mpz_mul(T, im, U); mpz_mod(T, T, P);
			check("fp2_mulm[1]", c2[1], T, N);
			/* (x + x1 u)^2 = (x^2 - x1^2) + 2 x x1 u. */
			mpz_mul(re, x, x); mpz_submul(re, x1, x1);
			mpz_mul(im, x, x1); mpz_mul_2exp(im, im, 1);
			fp2_sqrn_low(d2, a2);
			checkc("fp2_sqrn[0]", d2[0], re, PR);
			checkc("fp2_sqrn[1]", d2[1], im, PR);
			fp2_sqrm_low(c2, a2);
			mpz_mul(T, re, U); mpz_mod(T, T, P);
			check("fp2_sqrm[0]", c2[0], T, N);
			mpz_mul(T, im, U); mpz_mod(T, T, P);
			check("fp2_sqrm[1]", c2[1], T, N);
			mpz_clears(x1, y1, re, im, NULL);
		}
#endif

		/* Operations on double-precision values below pR. */
		elem(x, PR, k); elem(y, PR, k / 8);
		put(a, x, 2 * N); put(b, y, 2 * N);
		mpz_mul(T, x, U); mpz_mod(T, T, P);
		/* Out of place, on a copy that it may overwrite, and in place. */
		memcpy(e, a, sizeof(dig_t) * 2 * N);
		fp_rdcn_low(c, e); check("rdcn", c, T, N);
		memcpy(c, a, sizeof(dig_t) * 2 * N);
		fp_rdcn_low(c, c); check("rdcn in place", c, T, N);
		mpz_add(T, x, y);
		if (mpz_cmp(T, PR) >= 0) {
			mpz_sub(T, T, PR);
		}
		fp_addc_low(c, a, b); check("addc", c, T, 2 * N);
		mpz_sub(T, x, y);
		if (mpz_sgn(T) < 0) {
			mpz_add(T, T, PR);
		}
		fp_subc_low(c, a, b); check("subc", c, T, 2 * N);
		/* hlvd halves an even value or the value plus p. */
		mpz_set(z, x);
		if (mpz_odd_p(z)) {
			mpz_add(z, z, P);
		}
		mpz_fdiv_q_2exp(T, z, 1);
		fp_hlvd_low(c, a); check("hlvd", c, T, 2 * N);
	}
#if defined(FP_QNRES)
	if (mpz_fdiv_ui(P, 4) != 3) {
		printf("FP_QNRES is set but p is not 3 mod 4: Fp2 not checked.\n");
	}
#endif
	printf("FP_PRIME=%d N=%d: %d iterations, %d failures\n", FP_PRIME,
			(int)N, iters, fails);
	core_clean();
	return fails != 0;
}
