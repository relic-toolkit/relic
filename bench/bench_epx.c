/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Benchmarks for elliptic curves defined over extensions of prime fields.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

/**
 * Defines the benchmarks for an elliptic curve over an extension field:
 * memory, utilities, arithmetic, multiplication methods and hashing.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_BENCH_EPX(C, F)												\
static void bench_##C##_memory(void) {										\
	C##_t a[BENCH];															\
																			\
	BENCH_FEW(#C "_null", C##_null(a[i]), 1);								\
																			\
	BENCH_FEW(#C "_new", C##_new(a[i]), 1);									\
	for (int i = 0; i < BENCH; i++) {										\
		C##_free(a[i]);														\
	}																		\
																			\
	for (int i = 0; i < BENCH; i++) {										\
		C##_new(a[i]);														\
	}																		\
	BENCH_FEW(#C "_free", C##_free(a[i]), 1);								\
																			\
	(void)a;																\
}																			\
																			\
static void bench_##C##_util(void) {										\
	C##_t p, q, t[2];														\
	uint8_t bin[2 * (sizeof(F##_t) / sizeof(fp_t)) * RLC_FP_BYTES + 1];		\
	int l;																	\
																			\
	C##_null(p);															\
	C##_null(q);															\
	C##_null(t[0]);															\
	C##_null(t[1]);															\
																			\
	C##_new(p);																\
	C##_new(q);																\
	C##_new(t[0]);															\
	C##_new(t[1]);															\
																			\
	BENCH_RUN(#C "_is_infty") {												\
		C##_rand(p);														\
		BENCH_ADD(C##_is_infty(p));											\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_set_infty") {											\
		C##_rand(p);														\
		BENCH_ADD(C##_set_infty(p));										\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_copy") {													\
		C##_rand(p);														\
		C##_rand(q);														\
		BENCH_ADD(C##_copy(p, q));											\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_cmp") {													\
		C##_rand(p);														\
		C##_dbl(p, p);														\
		C##_rand(q);														\
		C##_dbl(q, q);														\
		BENCH_ADD(C##_cmp(p, q));											\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_norm") {													\
		C##_rand(p);														\
		C##_dbl(p, p);														\
		BENCH_ADD(C##_norm(p, p));											\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_norm_sim (2)") {											\
		C##_rand(t[0]);														\
		C##_rand(t[1]);														\
		C##_dbl(t[0], t[0]);												\
		C##_dbl(t[1], t[1]);												\
		BENCH_ADD(C##_norm_sim(t, t, 2));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_cmp (1 norm)") {											\
		C##_rand(p);														\
		C##_dbl(p, p);														\
		C##_rand(q);														\
		BENCH_ADD(C##_cmp(p, q));											\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_cmp (2 norm)") {											\
		C##_rand(p);														\
		C##_rand(q);														\
		BENCH_ADD(C##_cmp(p, q));											\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_rand") {													\
		BENCH_ADD(C##_rand(p));												\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_blind") {												\
		BENCH_ADD(C##_blind(p, p));											\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_on_curve") {												\
		C##_rand(p);														\
		BENCH_ADD(C##_on_curve(p));											\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_size_bin (0)") {											\
		C##_rand(p);														\
		BENCH_ADD(C##_size_bin(p, 0));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_size_bin (1)") {											\
		C##_rand(p);														\
		BENCH_ADD(C##_size_bin(p, 1));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_write_bin (0)") {										\
		C##_rand(p);														\
		l = C##_size_bin(p, 0);												\
		BENCH_ADD(C##_write_bin(bin, l, p, 0));								\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_write_bin (1)") {										\
		C##_rand(p);														\
		l = C##_size_bin(p, 1);												\
		BENCH_ADD(C##_write_bin(bin, l, p, 1));								\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_read_bin (0)") {											\
		C##_rand(p);														\
		l = C##_size_bin(p, 0);												\
		C##_write_bin(bin, l, p, 0);										\
		BENCH_ADD(C##_read_bin(p, bin, l));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_read_bin (1)") {											\
		C##_rand(p);														\
		l = C##_size_bin(p, 1);												\
		C##_write_bin(bin, l, p, 1);										\
		BENCH_ADD(C##_read_bin(p, bin, l));									\
	} BENCH_END;															\
																			\
	C##_free(p);															\
	C##_free(q);															\
	C##_free(t[0]);															\
	C##_free(t[1]);															\
}																			\
																			\
static void bench_##C##_arith(void) {										\
	C##_t p, q, r, t[RLC_EPX_TABLE_MAX];									\
	bn_t k, n, l[2];														\
	F##_t s;																\
																			\
	C##_null(p);															\
	C##_null(q);															\
	C##_null(r);															\
	bn_null(k);																\
	bn_null(n);																\
	F##_null(s);															\
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {							\
		C##_null(t[i]);														\
	}																		\
																			\
	C##_new(p);																\
	C##_new(q);																\
	C##_new(r);																\
	bn_new(k);																\
	bn_new(n);																\
	bn_new(l[0]);															\
	bn_new(l[1]);															\
	F##_new(s);																\
																			\
	C##_curve_get_ord(n);													\
																			\
	BENCH_RUN(#C "_add") {													\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add(p, p, q);													\
		C##_rand(q);														\
		C##_rand(p);														\
		C##_add(q, q, p);													\
		BENCH_ADD(C##_add(r, p, q));										\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_add_basic") {											\
		C##_rand(p);														\
		C##_rand(q);														\
		BENCH_ADD(C##_add_basic(r, p, q));									\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_add_slp_basic") {										\
		C##_rand(p);														\
		C##_rand(q);														\
		BENCH_ADD(C##_add_slp_basic(r, s, p, q));							\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_add_projc") {											\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add_projc(p, p, q);												\
		C##_rand(q);														\
		C##_rand(p);														\
		C##_add_projc(q, q, p);												\
		BENCH_ADD(C##_add_projc(r, p, q));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_add_projc (z2 = 1)") {									\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add_projc(p, p, q);												\
		C##_rand(q);														\
		C##_norm(q, q);														\
		BENCH_ADD(C##_add_projc(r, p, q));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_add_projc (z1,z2 = 1)") {								\
		C##_rand(p);														\
		C##_norm(p, p);														\
		C##_rand(q);														\
		C##_norm(q, q);														\
		BENCH_ADD(C##_add_projc(r, p, q));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_add_jacob") {											\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add_jacob(p, p, q);												\
		C##_rand(q);														\
		C##_rand(p);														\
		C##_add_jacob(q, q, p);												\
		BENCH_ADD(C##_add_jacob(r, p, q));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_add_jacob (z2 = 1)") {									\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add_jacob(p, p, q);												\
		C##_rand(q);														\
		C##_norm(q, q);														\
		BENCH_ADD(C##_add_jacob(r, p, q));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_add_jacob (z1,z2 = 1)") {								\
		C##_rand(p);														\
		C##_norm(p, p);														\
		C##_rand(q);														\
		C##_norm(q, q);														\
		BENCH_ADD(C##_add_jacob(r, p, q));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_sub") {													\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add(p, p, q);													\
		C##_rand(q);														\
		C##_rand(p);														\
		C##_add(q, q, p);													\
		BENCH_ADD(C##_sub(r, p, q));										\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_dbl") {													\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add(p, p, q);													\
		BENCH_ADD(C##_dbl(r, p));											\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_dbl_basic") {											\
		C##_rand(p);														\
		BENCH_ADD(C##_dbl_basic(r, p));										\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_dbl_slp_basic") {										\
		C##_rand(p);														\
		BENCH_ADD(C##_dbl_slp_basic(r, s, p));								\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_dbl_projc") {											\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add_projc(p, p, q);												\
		BENCH_ADD(C##_dbl_projc(r, p));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_dbl_projc (z1 = 1)") {									\
		C##_rand(p);														\
		C##_norm(p, p);														\
		BENCH_ADD(C##_dbl_projc(r, p));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_dbl_jacob") {											\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add_jacob(p, p, q);												\
		BENCH_ADD(C##_dbl_jacob(r, p));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_dbl_jacob (z1 = 1)") {									\
		C##_rand(p);														\
		C##_norm(p, p);														\
		BENCH_ADD(C##_dbl_jacob(r, p));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_neg") {													\
		C##_rand(p);														\
		C##_rand(q);														\
		C##_add(p, p, q);													\
		BENCH_ADD(C##_neg(r, p));											\
	}																		\
	BENCH_END;																\
																			\
	BENCH_RUN(#C "_mul") {													\
		bn_rand_mod(k, n);													\
		BENCH_ADD(C##_mul(q, p, k));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_basic") {											\
		bn_rand_mod(k, n);													\
		BENCH_ADD(C##_mul_basic(q, p, k));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_monty") {											\
		bn_rand_mod(k, n);													\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_monty(q, p, k));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_lwnaf") {											\
		bn_rand_mod(k, n);													\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_lwnaf(q, p, k));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_lwreg") {											\
		bn_rand_mod(k, n);													\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_lwreg(q, p, k));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_gen") {												\
		bn_rand_mod(k, n);													\
		BENCH_ADD(C##_mul_gen(q, k));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_cof") {												\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_cof(q, p));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_dig") {												\
		bn_rand(k, RLC_POS, RLC_DIG);										\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_dig(q, p, k->dp[0]));								\
	}																		\
	BENCH_END;																\
																			\
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {							\
		C##_new(t[i]);														\
	}																		\
																			\
	BENCH_RUN(#C "_mul_pre") {												\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_pre(t, p));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_fix") {												\
		bn_rand_mod(k, n);													\
		C##_rand(p);														\
		C##_mul_pre(t, p);													\
		BENCH_ADD(C##_mul_fix(q, t, k));									\
	} BENCH_END;															\
																			\
	for (int i = 0; i < RLC_EPX_TABLE_MAX; i++) {							\
		C##_free(t[i]);														\
	}																		\
																			\
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {							\
		C##_new(t[i]);														\
	}																		\
	BENCH_RUN(#C "_mul_pre_basic") {										\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_pre_basic(t, p));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_fix_basic") {										\
		bn_rand_mod(k, n);													\
		C##_rand(p);														\
		C##_mul_pre_basic(t, p);											\
		BENCH_ADD(C##_mul_fix_basic(q, t, k));								\
	} BENCH_END;															\
	for (int i = 0; i < RLC_EPX_TABLE_BASIC; i++) {							\
		C##_free(t[i]);														\
	}																		\
																			\
	for (int i = 0; i < RLC_EPX_TABLE_LWREG; i++) {							\
		C##_new(t[i]);														\
	}																		\
	BENCH_RUN(#C "_mul_pre_lwreg") {										\
		C##_rand(p);														\
		BENCH_ADD(C##_mul_pre_lwreg(t, p));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_fix_lwreg") {										\
		bn_rand_mod(k, n);													\
		C##_rand(p);														\
		C##_mul_pre_lwreg(t, p);											\
		BENCH_ADD(C##_mul_fix_lwreg(q, t, k));								\
	} BENCH_END;															\
	for (int i = 0; i < RLC_EPX_TABLE_LWREG; i++) {							\
		C##_free(t[i]);														\
	}																		\
																			\
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {							\
		C##_new(t[i]);														\
	}																		\
	BENCH_RUN(#C "_mul_pre_combd") {										\
		BENCH_ADD(C##_mul_pre_combd(t, p));									\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_fix_combd") {										\
		bn_rand_mod(k, n);													\
		C##_mul_pre_combd(t, p);											\
		BENCH_ADD(C##_mul_fix_combd(q, t, k));								\
	} BENCH_END;															\
	for (int i = 0; i < RLC_EPX_TABLE_COMBD; i++) {							\
		C##_free(t[i]);														\
	}																		\
																			\
	BENCH_RUN(#C "_mul_sim") {												\
		bn_rand_mod(l[0], n);												\
		bn_rand_mod(l[1], n);												\
		C##_rand(p);														\
		C##_rand(q);														\
		BENCH_ADD(C##_mul_sim(r, p, l[0], q, l[1]));						\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_mul_sim_gen") {											\
		bn_rand_mod(l[0], n);												\
		bn_rand_mod(l[1], n);												\
		C##_rand(q);														\
		BENCH_ADD(C##_mul_sim_gen(r, l[0], q, l[1]));						\
	} BENCH_END;															\
																			\
	for (int i = 0; i < 2; i++) {											\
		C##_new(t[i]);														\
	}																		\
																			\
	BENCH_RUN(#C "_mul_sim_lot (2)") {										\
		bn_rand_mod(l[0], n);												\
		bn_rand_mod(l[1], n);												\
		C##_rand(t[0]);														\
		C##_rand(t[1]);														\
		BENCH_ADD(C##_mul_sim_lot(r, t, l, 2));								\
	} BENCH_END;															\
																			\
	for (int i = 0; i < 2; i++) {											\
		C##_free(t[i]);														\
	}																		\
																			\
	BENCH_RUN(#C "_frb") {													\
		C##_rand(q);														\
		BENCH_ADD(C##_frb(r, q, 1));										\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_psi") {													\
		C##_rand(q);														\
		BENCH_ADD(C##_psi(r, q));											\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_map") {													\
		uint8_t msg[5];														\
		rand_bytes(msg, 5);													\
		BENCH_ADD(C##_map(p, msg, 5));										\
	} BENCH_END;															\
																			\
	C##_free(p);															\
	C##_free(q);															\
	C##_free(r);															\
	BENCH_RUN(#C "_pck") {													\
		C##_rand(p);														\
		BENCH_ADD(C##_pck(q, p));											\
	} BENCH_END;															\
																			\
	BENCH_RUN(#C "_upk") {													\
		C##_rand(p);														\
		BENCH_ADD(C##_upk(q, p));											\
	} BENCH_END;															\
																			\
	bn_free(k);																\
	bn_free(n);																\
	bn_free(l[0]);															\
	bn_free(l[1]);															\
	F##_free(s);															\
}

TMPL_BENCH_EPX(ep2, fp2)

TMPL_BENCH_EPX(ep3, fp3)

TMPL_BENCH_EPX(ep4, fp4)

TMPL_BENCH_EPX(ep8, fp8)

TMPL_BENCH_EPX(ep9, fp9)

static void arith2(void) {
	ep2_t p, q;
	bn_t k, n;

	ep2_null_all(p, q);
	bn_null_all(k, n);

	ep2_new_all(p, q);
	bn_new_all(k, n);
	ep2_curve_get_ord(n);

	BENCH_RUN("ep2_tpl_projc") {
		ep2_rand(p);
		BENCH_ADD(ep2_tpl_projc(q, p));
	} BENCH_END;

	BENCH_RUN("ep2_tpl_jacob") {
		ep2_rand(p);
		BENCH_ADD(ep2_tpl_jacob(q, p));
	} BENCH_END;

	BENCH_RUN("ep2_map_basic") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep2_map_basic(p, msg, 5));
	} BENCH_END;

	BENCH_RUN("ep2_map_sswum") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep2_map_sswum(p, msg, 5));
	} BENCH_END;

	BENCH_RUN("ep2_map_swift") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep2_map_swift(p, msg, 5));
	} BENCH_END;

	ep2_free_all(p, q);
	bn_free_all(k, n);
}

int main(void) {
	int r0, r1, r2, r3, r4;
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the EPX module:", 0);

	if (ep_param_set_any_pairf() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	if ((r0 = ep2_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		bench_ep2_memory();
		bench_ep2_util();

		util_banner("Arithmetic:", 1);
		bench_ep2_arith();
		arith2();
	}

	if ((r1 = ep3_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		bench_ep3_memory();
		bench_ep3_util();

		util_banner("Arithmetic:", 1);
		bench_ep3_arith();
	}

	if ((r2 = ep4_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		bench_ep4_memory();
		bench_ep4_util();

		util_banner("Arithmetic:", 1);
		bench_ep4_arith();
	}

	if ((r3 = ep8_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		bench_ep8_memory();
		bench_ep8_util();

		util_banner("Arithmetic:", 1);
		bench_ep8_arith();
	}

	if ((r4 = ep9_curve_is_twist())) {
		ep_param_print();

		util_banner("Utilities:", 1);
		bench_ep9_memory();
		bench_ep9_util();

		util_banner("Arithmetic:", 1);
		bench_ep9_arith();
	}

	if (!r0 && !r2 && !r1 && !r3 && !r4) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

	core_clean();
	return 0;
}
