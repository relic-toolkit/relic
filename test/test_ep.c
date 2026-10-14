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
 * Tests for arithmetic on prime elliptic curves.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

#if ARCH == AVR || ARCH == MSP || ARCH == ARM
#define SIM_LOT		4
#else
/* Enough points to reach the bucket method. */
#define SIM_LOT		40
#endif

static int memory(void) {
	err_t e = ERR_CAUGHT;
	int code = RLC_ERR;
	ep_t a;

	ep_null(a);

	RLC_TRY {
		TEST_CASE("memory can be allocated") {
			ep_new(a);
			ep_free(a);
		} TEST_END;
	} RLC_CATCH(e) {
		switch (e) {
			case ERR_NO_MEMORY:
				util_print("FATAL ERROR!\n");
				RLC_ERROR(end);
				break;
		}
	}
	(void)a;
	code = RLC_OK;
  end:
	return code;
}

static int util(void) {
	int l, r, code = RLC_ERR;
	ep_t a, b, c, t[3];
	uint8_t bin[2 * RLC_FP_BYTES + 1];

	ep_null(a);
	ep_null(b);
	ep_null(c);
	for (int j = 0; j < 3; j++) {
		ep_null(t[j]);
	}

	RLC_TRY {
		ep_new(a);
		ep_new(b);
		ep_new(c);
		for (int j = 0; j < 3; j++) {
			ep_new(t[j]);
		}

		TEST_CASE("copy and comparison are consistent") {
			ep_rand(a);
			ep_rand(b);
			ep_rand(c);
			/* Compare points in affine coordinates. */
			if (ep_cmp(a, c) != RLC_EQ) {
				ep_copy(c, a);
				TEST_ASSERT(ep_cmp(c, a) == RLC_EQ, end);
			}
			if (ep_cmp(b, c) != RLC_EQ) {
				ep_copy(c, b);
				TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
			}
			/* Compare with one point in projective. */
			ep_dbl(c, a);
			ep_norm(c, c);
			ep_dbl(a, a);
			TEST_ASSERT(ep_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep_cmp(a, c) == RLC_EQ, end);
			/* Compare with two points in projective. */
			ep_dbl(c, c);
			ep_dbl(a, a);
			TEST_ASSERT(ep_cmp(c, a) == RLC_EQ, end);
			TEST_ASSERT(ep_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("negation and comparison are consistent") {
			ep_rand(a);
			ep_neg(b, a);
			TEST_ASSERT(ep_cmp(a, b) != RLC_EQ, end);
			ep_neg(b, b);
			TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
			/* Compare with infinity. */
			ep_neg(b, a);
			ep_add(a, a, b);
			ep_set_infty(b);
			TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to random and comparison are consistent") {
			ep_rand(a);
			ep_set_infty(c);
			TEST_ASSERT(ep_cmp(a, c) != RLC_EQ, end);
			TEST_ASSERT(ep_cmp(c, a) != RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("assignment to infinity and infinity test are consistent") {
			ep_set_infty(a);
			TEST_ASSERT(ep_is_infty(a), end);
		}
		TEST_END;

		TEST_CASE("validity test is correct") {
			ep_set_infty(a);
			TEST_ASSERT(ep_on_curve(a), end);
			ep_rand(a);
			TEST_ASSERT(ep_on_curve(a), end);
			fp_rand(a->x);
			TEST_ASSERT(!ep_on_curve(a), end);
		}
		TEST_END;

		TEST_CASE("blinding is consistent") {
			ep_rand(a);
			ep_rand(b);
			ep_blind(b, a);
			TEST_ASSERT(ep_on_curve(b), end);
			TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
			ep_blind(a, a);
			TEST_ASSERT(ep_on_curve(a), end);
			TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("simultaneous normalization is correct") {
			ep_rand(a);
			ep_dbl(t[0], a);
			ep_set_infty(t[1]);
			ep_rand(b);
			ep_dbl(t[2], b);
			ep_dbl(a, a);
			ep_dbl(b, b);
			ep_norm_sim(t, (const ep_t *)t, 3);
			TEST_ASSERT(ep_cmp(t[0], a) == RLC_EQ, end);
			TEST_ASSERT(ep_is_infty(t[1]), end);
			TEST_ASSERT(ep_cmp(t[2], b) == RLC_EQ, end);
			TEST_ASSERT(t[0]->coord == BASIC && t[2]->coord == BASIC, end);
		} TEST_END;

#if FP_PRIME == 256
		if (ep_param_get() == NIST_P256) {
			TEST_ONCE("compressed points follow sec1 (p-256)") {
				/* The generator has an odd y-coordinate, so its prefix is 03. */
				uint8_t g[33] = {
					0x03, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8,
					0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D,
					0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
					0x98, 0xC2, 0x96
				};
				ep_curve_get_gen(a);
				TEST_ASSERT(ep_size_bin(a, 1) == sizeof(g), end);
				ep_write_bin(bin, sizeof(g), a, 1);
				TEST_ASSERT(memcmp(bin, g, sizeof(g)) == 0, end);
				TEST_ASSERT(ep_read_bin(b, g, sizeof(g)) == RLC_OK, end);
				TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
			} TEST_END;
		}
#endif

		TEST_CASE("reading and writing a point are consistent") {
			for (int j = 0; j < 2; j++) {
				ep_set_infty(a);
				l = ep_size_bin(a, j);
				ep_write_bin(bin, l, a, j);
				TEST_ASSERT(ep_read_bin(b, bin, l) == RLC_OK, end);
				TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
				ep_rand(a);
				l = ep_size_bin(a, j);
				ep_write_bin(bin, l, a, j);
				TEST_ASSERT(ep_read_bin(b, bin, l) == RLC_OK, end);
				TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
				ep_rand(a);
				ep_dbl(a, a);
				l = ep_size_bin(a, j);
				ep_norm(a, a);
				ep_write_bin(bin, l, a, j);
				TEST_ASSERT(ep_read_bin(b, bin, l) == RLC_OK, end);
				TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
			}
		}
		TEST_END;

		TEST_CASE("reading an invalid point fails") {
			for (int j = 0; j < 5; j++) {
				ep_rand(a);
				l = ep_size_bin(a, 0);
				ep_write_bin(bin, l, a, 0);
				switch (j) {
					case 0:
						/* An invalid tag. */
						bin[0] = 5;
						break;
					case 1:
						/* A point off the curve. */
						bin[l - 1] ^= 1;
						break;
					case 2:
						/* A coordinate that is not reduced modulo p. */
						memset(bin + 1, 0xFF, RLC_FP_BYTES);
						break;
					case 3:
						/* A compressed x-coordinate with no point. */
						do {
							fp_rand(a->x);
							ep_rhs(c->x, a->x);
						} while (fp_is_sqr(c->x));
						bin[0] = 2;
						fp_write_bin(bin + 1, RLC_FP_BYTES, a->x);
						l = RLC_FP_BYTES + 1;
						break;
					default:
						/* A single byte other than the point at infinity. */
						bin[0] = 1;
						l = 1;
						break;
				}
				r = RLC_ERR;
				TEST_ERR(r = ep_read_bin(b, bin, l));
				TEST_ASSERT(r == RLC_ERR && err_get_code() == RLC_ERR, end);
			}
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(a);
	ep_free(b);
	ep_free(c);
	for (int j = 0; j < 3; j++) {
		ep_free(t[j]);
	}
	return code;
}

static int addition(void) {
	int code = RLC_ERR;
	ep_t a, b, c, d, e;

	ep_null(a);
	ep_null(b);
	ep_null(c);
	ep_null(d);
	ep_null(e);

	RLC_TRY {
		ep_new(a);
		ep_new(b);
		ep_new(c);
		ep_new(d);
		ep_new(e);

		TEST_CASE("point addition is commutative") {
			ep_rand(a);
			ep_rand(b);
			ep_add(d, a, b);
			ep_add(e, b, a);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition is associative") {
			ep_rand(a);
			ep_rand(b);
			ep_rand(c);
			ep_add(d, a, b);
			ep_add(d, d, c);
			ep_add(e, b, c);
			ep_add(e, e, a);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has identity") {
			ep_rand(a);
			ep_set_infty(d);
			ep_add(e, a, d);
			TEST_ASSERT(ep_cmp(a, e) == RLC_EQ, end);
			ep_add(e, d, a);
			TEST_ASSERT(ep_cmp(a, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition has inverse") {
			ep_rand(a);
			ep_neg(d, a);
			ep_add(e, a, d);
			TEST_ASSERT(ep_is_infty(e), end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point addition in affine coordinates is correct") {
			ep_rand(a);
			ep_rand(b);
			ep_add(d, a, b);
			ep_add_basic(e, a, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point addition in projective coordinates is correct") {
			ep_rand(a);
			ep_rand(b);
			ep_rand(c);
			ep_add_projc(a, a, b);
			ep_add_projc(b, b, c);
			/* a and b in projective coordinates. */
			ep_add_projc(d, a, b);
			/* normalize before mixing coordinates. */
			ep_norm(a, a);
			ep_norm(b, b);
			ep_add(e, a, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition with the output aliasing an operand is correct") {
			ep_rand(a);
			ep_rand(b);
			ep_rand(c);
			/* a and b in projective coordinates. */
			ep_add_projc(a, a, c);
			ep_add_projc(b, b, c);
			ep_add_projc(d, a, b);
			ep_copy(e, b);
			ep_add_projc(e, a, e);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
			ep_copy(e, a);
			ep_add_projc(e, e, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point arithmetic in projective coordinates is complete") {
			ep_rand(a);
			ep_dbl_projc(a, a);
			ep_neg(b, a);
			/* c is the point at infinity in projective coordinates. */
			ep_add_projc(c, a, b);
			TEST_ASSERT(c->coord == PROJC && ep_is_infty(c), end);
			ep_add_projc(d, c, a);
			TEST_ASSERT(ep_cmp(d, a) == RLC_EQ, end);
			ep_norm(e, a);
			ep_add_projc(d, c, e);
			TEST_ASSERT(ep_cmp(d, a) == RLC_EQ, end);
			ep_add_projc(d, a, c);
			TEST_ASSERT(ep_cmp(d, a) == RLC_EQ, end);
			ep_dbl_projc(d, c);
			TEST_ASSERT(ep_is_infty(d), end);
			ep_tpl_projc(d, c);
			TEST_ASSERT(ep_is_infty(d), end);
			/* The same for the canonical representation (0 : 1 : 0). */
			ep_set_infty(c);
			ep_add_projc(d, c, a);
			TEST_ASSERT(ep_cmp(d, a) == RLC_EQ, end);
			ep_add_projc(d, e, c);
			TEST_ASSERT(ep_cmp(d, a) == RLC_EQ, end);
			ep_add_projc(d, c, c);
			TEST_ASSERT(ep_is_infty(d), end);
			ep_dbl_projc(d, c);
			TEST_ASSERT(ep_is_infty(d), end);
			ep_tpl_projc(d, c);
			TEST_ASSERT(ep_is_infty(d), end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {
			ep_rand(a);
			ep_rand(b);
			/* a in projective, b in affine coordinates. */
			ep_add_projc(a, a, b);
			ep_add_projc(d, a, b);
			/* a in affine coordinates. */
			ep_norm(a, a);
			ep_add(e, a, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {
			ep_rand(a);
			ep_rand(b);
			/* a and b in affine coordinates. */
			ep_add(d, a, b);
			ep_add_projc(e, a, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == JACOB || !defined(STRIP)
		TEST_CASE("point addition in jacobian coordinates is correct") {
			ep_rand(a);
			ep_rand(b);
			ep_rand(c);
			ep_add_jacob(a, a, b);
			ep_add_jacob(b, b, c);
			/* a and b in projective coordinates. */
			ep_add_jacob(d, a, b);
			ep_norm(a, a);
			ep_norm(b, b);
			ep_add(e, a, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z2 = 1) is correct") {
			ep_rand(a);
			ep_rand(b);
			/* a in projective, b in affine coordinates. */
			ep_add_jacob(a, a, b);
			ep_add_jacob(d, a, b);
			/* a in affine coordinates. */
			ep_norm(a, a);
			ep_add(e, a, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point addition in mixed coordinates (z1,z2 = 1) is correct") {
			ep_rand(a);
			ep_rand(b);
			ep_norm(a, a);
			ep_norm(b, b);
			/* a and b in affine coordinates. */
			ep_add(d, a, b);
			ep_add_jacob(e, a, b);
			TEST_ASSERT(ep_cmp(d, e) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(a);
	ep_free(b);
	ep_free(c);
	ep_free(d);
	ep_free(e);
	return code;
}

static int subtraction(void) {
	int code = RLC_ERR;
	ep_t a, b, c, d;

	ep_null(a);
	ep_null(b);
	ep_null(c);
	ep_null(d);

	RLC_TRY {
		ep_new(a);
		ep_new(b);
		ep_new(c);
		ep_new(d);

		TEST_CASE("point subtraction is anti-commutative") {
			ep_rand(a);
			ep_rand(b);
			ep_sub(c, a, b);
			ep_sub(d, b, a);
			ep_neg(d, d);
			TEST_ASSERT(ep_cmp(c, d) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has identity") {
			ep_rand(a);
			ep_set_infty(c);
			ep_sub(d, a, c);
			TEST_ASSERT(ep_cmp(d, a) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("point subtraction has inverse") {
			ep_rand(a);
			ep_sub(c, a, a);
			TEST_ASSERT(ep_is_infty(c), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(a);
	ep_free(b);
	ep_free(c);
	ep_free(d);
	return code;
}

static int doubling(void) {
	int code = RLC_ERR;
	ep_t a, b, c;
	fp_t s0, s1;

	ep_null(a);
	ep_null(b);
	ep_null(c);
	fp_null(s0);
	fp_null(s1);

	RLC_TRY {
		ep_new(a);
		ep_new(b);
		ep_new(c);
		fp_new(s0);
		fp_new(s1);

		TEST_CASE("point doubling is correct") {
			ep_rand(a);
			ep_add(b, a, a);
			ep_dbl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point doubling in affine coordinates is correct") {
			ep_rand(a);
			ep_dbl(b, a);
			ep_dbl_basic(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
			/* Adding a point to itself gives the doubling and its slope. */
			ep_norm(a, a);
			ep_add_slp_basic(b, s0, a, a);
			ep_dbl_slp_basic(c, s1, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
			TEST_ASSERT(fp_cmp(s0, s1) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point doubling in projective coordinates is correct") {
			ep_rand(a);
			/* a in projective coordinates. */
			ep_dbl_projc(a, a);
			ep_dbl_projc(b, a);
			ep_norm(a, a);
			ep_dbl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {
			ep_rand(a);
			ep_dbl_projc(b, a);
			ep_norm(b, b);
			ep_dbl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == JACOB || !defined(STRIP)
		TEST_CASE("point doubling in jacobian coordinates is correct") {
			ep_rand(a);
			/* a in projective coordinates. */
			ep_dbl_jacob(a, a);
			ep_dbl_jacob(b, a);
			ep_norm(a, a);
			ep_dbl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point doubling in mixed coordinates (z1 = 1) is correct") {
			ep_rand(a);
			ep_dbl_jacob(b, a);
			ep_norm(b, b);
			ep_dbl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(a);
	ep_free(b);
	ep_free(c);
	fp_free(s0);
	fp_free(s1);
	return code;
}

static int tripling(void) {
	int code = RLC_ERR;
	ep_t a, b, c;

	ep_null(a);
	ep_null(b);
	ep_null(c);

	RLC_TRY {
		ep_new(a);
		ep_new(b);
		ep_new(c);

		TEST_CASE("point tripling is correct") {
			ep_curve_get_gen(a);
			ep_dbl(b, a);
			ep_add(b, b, a);
			ep_tpl(c, a);
			ep_norm(b, b);
			ep_norm(c, c);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

#if EP_ADD == BASIC || !defined(STRIP)
		TEST_CASE("point tripling in affine coordinates is correct") {
			ep_rand(a);
			ep_tpl(b, a);
			ep_tpl_basic(c, a);
			ep_norm(b, b);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == PROJC || !defined(STRIP)
		TEST_CASE("point tripling in projective coordinates is correct") {
			ep_rand(a);
			/* a in projective coordinates. */
			ep_tpl_projc(a, a);
			ep_tpl_projc(b, a);
			ep_norm(a, a);
			ep_tpl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
			/* The same in place, on a point in projective coordinates. */
			ep_dbl_projc(a, a);
			ep_tpl_projc(b, a);
			ep_tpl_projc(a, a);
			TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point tripling in mixed coordinates (z1 = 1) is correct") {
			ep_rand(a);
			ep_tpl_projc(b, a);
			ep_norm(b, b);
			ep_tpl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_ADD == JACOB || !defined(STRIP)
		TEST_CASE("point tripling in jacobian coordinates is correct") {
			ep_rand(a);
			/* a in projective coordinates. */
			ep_tpl_jacob(a, a);
			ep_tpl_jacob(b, a);
			ep_norm(a, a);
			ep_tpl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("point tripling in mixed coordinates (z1 = 1) is correct") {
			ep_rand(a);
			ep_tpl_jacob(b, a);
			ep_norm(b, b);
			ep_tpl(c, a);
			TEST_ASSERT(ep_cmp(b, c) == RLC_EQ, end);
		} TEST_END;
#endif
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(a);
	ep_free(b);
	ep_free(c);
	return code;
}

static int endomorphism(void) {
	int code = RLC_ERR;
	bn_t l, n, v1[3], v2[3];
	ep_t a, b, c;

	bn_null(l);
	bn_null(n);
	ep_null(a);
	ep_null(b);
	ep_null(c);

	for (int k = 0; k < 3; k++) {
		bn_null(v1[k]);
		bn_null(v2[k]);
	}

	RLC_TRY {
		bn_new(l);
		bn_new(n);
		ep_new(a);
		ep_new(b);
		ep_new(c);

		for (int k = 0; k < 3; k++) {
			bn_new(v1[k]);
			bn_new(v2[k]);
		}

		if (ep_curve_is_endom()) {
			/* Recover lambda parameter. */
			for (size_t i = 0; i < 3; i++) {
				bn_copy(v1[i], &(core_get()->ep_v1[i]));
				bn_copy(v2[i], &(core_get()->ep_v2[i]));
			}
			ep_curve_get_ord(v2[0]);
			if (bn_cmp_dig(v1[2], 1) == RLC_EQ) {
				bn_gcd_ext(v1[0], v2[1], NULL, v1[1], v2[0]);
			} else {
				bn_gcd_ext(v1[0], v2[1], NULL, v1[2], v2[0]);
			}
			if (bn_sign(v2[1]) == RLC_NEG) {
				/* Negate modulo r. */
				bn_add(v2[1], v2[0], v2[1]);
			}
			bn_mul(v1[0], v2[1], v1[1]);
			bn_mod(l, v1[0], v2[0]);

			TEST_CASE("endomorphism is correct") {
				/* Test if \psi(P) = [l]P. */
				ep_rand(a);
				ep_psi(b, a);
				ep_mul(c, a, l);
				ep_neg(a, b);
				TEST_ASSERT(ep_cmp(b, c) == RLC_EQ ||
					ep_cmp(a, c) == RLC_EQ, end);
			}
			TEST_END;

			TEST_CASE("endomorphism in affine coordinates is correct") {
				ep_rand(a);
				ep_psi(b, a);
				ep_mul(c, a, l);
				ep_neg(a, b);
				TEST_ASSERT(ep_cmp(b, c) == RLC_EQ ||
					ep_cmp(a, c) == RLC_EQ, end);
			}
			TEST_END;

#if EP_ADD == PROJC || !defined(STRIP)
			TEST_CASE("endomorphism in projective coordinates is correct") {
				ep_rand(a);
				ep_dbl_projc(a, a);
				ep_psi(b, a);
				ep_norm(a, a);
				ep_mul(c, a, l);
				ep_neg(a, b);
			}
			TEST_END;
#endif

#if EP_ADD == JACOB || !defined(STRIP)
			TEST_CASE("endomorphism in jacobian coordinates is correct") {
				ep_rand(a);
				ep_dbl_jacob(a, a);
				ep_psi(b, a);
				ep_norm(a, a);
				ep_mul(c, a, l);
				ep_neg(a, b);
				TEST_ASSERT(ep_cmp(b, c) == RLC_EQ ||
					ep_cmp(a, c) == RLC_EQ, end);
			}
			TEST_END;
#endif
		}
	(void)a;
	(void)b;
	(void)c;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(l);
	bn_free(n);
	ep_free(a);
	ep_free(b);
	ep_free(c);
	for (int k = 0; k < 3; k++) {
		bn_free(v1[k]);
		bn_free(v2[k]);
	}

	return code;
}

static int multiplication(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep_t p, q, r;

	bn_null(n);
	bn_null(k);
	ep_null(p);
	ep_null(q);
	ep_null(r);

	RLC_TRY {
		bn_new(n);
		bn_new(k);
		ep_new(p);
		ep_new(q);
		ep_new(r);

		ep_curve_get_gen(p);
		ep_curve_get_ord(n);

		TEST_ONCE("generator has the right order") {
			TEST_ASSERT(ep_on_curve(p), end);
			/* The basic method does not reduce the scalar modulo n. */
			ep_mul_basic(r, p, n);
			TEST_ASSERT(ep_is_infty(r) == 1, end);
		} TEST_END;

		TEST_CASE("cofactor multiplication is correct") {
			ep_rand(q);
			ep_set_infty(r);
			ep_mul_cof(r, q);
			ep_mul_cof(q, q);
			TEST_ASSERT(ep_cmp(r, q) == RLC_EQ, end);
			TEST_ASSERT(ep_on_curve(r), end);
		} TEST_END;

		TEST_CASE("generator multiplication is correct") {
			bn_zero(k);
			ep_mul_gen(r, k);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_gen(r, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul(q, p, k);
			ep_mul_gen(r, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_gen(r, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_gen(q, k);
			/* Add a multiple of n beyond the bit length of the field. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_gen(r, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		} TEST_END;

#if EP_MUL == BASIC || !defined(STRIP)
		TEST_CASE("binary point multiplication is correct") {
			bn_zero(k);
			ep_mul_basic(r, p, k);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_basic(r, p, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			ep_rand(p);
			ep_mul_basic(r, p, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_rand_mod(k, n);
			ep_mul(q, p, k);
			ep_mul_basic(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_basic(r, p, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_basic(q, p, k);
			/* Add a multiple of n beyond the bit length of the field. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_basic(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
#endif

#if EP_MUL == MONTY || !defined(STRIP)
		TEST_CASE("montgomery ladder point multiplication is correct") {
			bn_zero(k);
			ep_mul_monty(r, p, k);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_monty(r, p, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			ep_rand(p);
			ep_mul_monty(r, p, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_rand_mod(k, n);
			ep_mul(q, p, k);
			ep_mul_monty(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_monty(r, p, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_monty(q, p, k);
			/* Add a multiple of n beyond the bit length of the field. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_monty(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == LWNAF || !defined(STRIP)
		TEST_CASE("left-to-right w-naf point multiplication is correct") {
			bn_zero(k);
			ep_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			ep_rand(p);
			ep_mul_lwnaf(r, p, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_rand_mod(k, n);
			ep_mul(q, p, k);
			ep_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_lwnaf(r, p, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_lwnaf(q, p, k);
			/* Add a multiple of n beyond the bit length of the field. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_lwnaf(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

#if EP_MUL == LWREG || !defined(STRIP)
		TEST_CASE("left-to-right regular point multiplication is correct") {
			bn_zero(k);
			ep_mul_lwreg(r, p, k);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_lwreg(r, p, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			ep_rand(p);
			ep_mul_lwreg(r, p, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_rand_mod(k, n);
			ep_mul(q, p, k);
			ep_mul_lwreg(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_lwreg(r, p, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_lwreg(q, p, k);
			/* Add a multiple of n beyond the bit length of the field. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_lwreg(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
#endif

		TEST_CASE("point multiplication by digit is correct") {
			ep_mul_dig(r, p, 0);
			TEST_ASSERT(ep_is_infty(r), end);
			ep_mul_dig(r, p, 1);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			bn_rand(k, RLC_POS, RLC_DIG);
			ep_mul(q, p, k);
			ep_mul_dig(r, p, k->dp[0]);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	bn_free(k);
	ep_free(p);
	ep_free(q);
	ep_free(r);
	return code;
}

static int fixed(void) {
	int code = RLC_ERR;
	bn_t n, k;
	ep_t p, q, r, t[RLC_EP_TABLE_MAX];

	bn_null(n);
	bn_null(k);
	ep_null(p);
	ep_null(q);
	ep_null(r);

	for (int i = 0; i < RLC_EP_TABLE_MAX; i++) {
		ep_null(t[i]);
	}

	RLC_TRY {
		ep_new(p);
		ep_new(q);
		ep_new(r);
		bn_new(n);
		bn_new(k);

		ep_curve_get_gen(p);
		ep_curve_get_ord(n);

		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep_new(t[i]);
		}
		TEST_CASE("fixed point multiplication is correct") {
			ep_rand(p);
			ep_mul_pre(t, p);
			bn_zero(k);
			ep_mul_fix(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_is_infty(r), end);
			ep_mul_fix(r, (const ep_t *)t, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_fix(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul(q, p, k);
			ep_mul_fix(q, (const ep_t *)t, k);
			ep_mul(r, p, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_fix(r, (const ep_t *)t, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_fix(q, (const ep_t *)t, k);
			/* Add a multiple of n beyond the bit length of the table. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_fix(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			ep_free(t[i]);
		}

#if EP_FIX == BASIC || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep_new(t[i]);
		}
		TEST_CASE("single-table comb fixed point multiplication is correct") {
			ep_rand(p);
			ep_mul_pre_basic(t, p);
			bn_zero(k);
			ep_mul_fix_basic(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_is_infty(r), end);
			ep_mul_fix_basic(r, (const ep_t *)t, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_fix_basic(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul(r, p, k);
			ep_mul_fix_basic(q, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_fix_basic(r, (const ep_t *)t, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_fix_basic(q, (const ep_t *)t, k);
			/* Add a multiple of n beyond the bit length of the table. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_fix_basic(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_BASIC; i++) {
			ep_free(t[i]);
		}
#endif

#if EP_FIX == LWREG || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_LWREG; i++) {
			ep_new(t[i]);
		}
		TEST_CASE("regular signed comb fixed point multiplication is correct") {
			ep_rand(p);
			ep_mul_pre_lwreg(t, p);
			bn_zero(k);
			ep_mul_fix_lwreg(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_is_infty(r), end);
			ep_mul_fix_lwreg(r, (const ep_t *)t, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_fix_lwreg(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul(r, p, k);
			ep_mul_fix_lwreg(q, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_fix_lwreg(r, (const ep_t *)t, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_fix_lwreg(q, (const ep_t *)t, k);
			/* Add a multiple of n beyond the bit length of the table. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_fix_lwreg(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_LWREG; i++) {
			ep_free(t[i]);
		}
#endif

#if EP_FIX == COMBD || !defined(STRIP)
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep_new(t[i]);
		}
		TEST_CASE("double-table comb fixed point multiplication is correct") {
			ep_rand(p);
			ep_mul_pre_combd(t, p);
			bn_zero(k);
			ep_mul_fix_combd(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_is_infty(r), end);
			ep_mul_fix_combd(r, (const ep_t *)t, n);
			TEST_ASSERT(ep_is_infty(r), end);
			bn_set_dig(k, 1);
			ep_mul_fix_combd(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(p, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul(r, p, k);
			ep_mul_fix_combd(q, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_neg(k, k);
			ep_mul_fix_combd(r, (const ep_t *)t, k);
			ep_neg(r, r);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
			bn_rand_mod(k, n);
			ep_mul_fix_combd(q, (const ep_t *)t, k);
			/* Add a multiple of n beyond the bit length of the table. */
			bn_lsh(n, n, RLC_DIG);
			bn_add(k, k, n);
			bn_rsh(n, n, RLC_DIG);
			ep_mul_fix_combd(r, (const ep_t *)t, k);
			TEST_ASSERT(ep_cmp(q, r) == RLC_EQ, end);
		} TEST_END;
		for (int i = 0; i < RLC_EP_TABLE_COMBD; i++) {
			ep_free(t[i]);
		}
#endif

	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(p);
	ep_free(q);
	ep_free(r);
	bn_free(n);
	bn_free(k);
	return code;
}

static int simultaneous(void) {
	int code = RLC_ERR;
	bn_t n, k[SIM_LOT + 1];
	ep_t p[SIM_LOT + 1], r;

	bn_null(n);
	ep_null(r);
	for (int i = 0; i <= SIM_LOT; i++) {
		bn_null(k[i]);
		ep_null(p[i]);
	}

	RLC_TRY {
		bn_new(n);
		ep_new(r);
		for (int i = 0; i <= SIM_LOT; i++) {
			bn_new(k[i]);
			ep_new(p[i]);
		}

		ep_curve_get_gen(p[0]);
		ep_curve_get_ord(n);

		TEST_CASE("simultaneous point multiplication is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep_mul(p[1], p[0], k[1]);
			ep_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep_mul(p[1], p[0], k[0]);
			ep_mul_sim(r, p[0], k[0], p[0], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep_mul(p[0], p[0], k[0]);
			ep_mul(p[1], p[1], k[1]);
			ep_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep_mul(p[0], p[0], k[0]);
			ep_mul(p[1], p[1], k[1]);
			ep_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep_mul(p[0], p[0], k[0]);
			ep_mul(p[1], p[1], k[1]);
			ep_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			bn_add(k[0], k[0], n);
			bn_add(k[1], k[1], n);
			ep_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep_mul(p[0], p[0], k[0]);
			ep_mul(p[1], p[1], k[1]);
			ep_add(p[1], p[1], p[0]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			ep_mul_sim(r, p[0], k[0], p[1], k[1]);
			ep_mul_sim_lot(p[1], p, k, 2);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("simultaneous multiplication with generator is correct") {
			bn_zero(k[0]);
			bn_rand_mod(k[1], n);
			ep_mul(p[1], p[0], k[1]);
			ep_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_zero(k[1]);
			ep_mul_gen(p[1], k[0]);
			ep_mul_sim_gen(r, k[0], p[0], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			ep_mul_sim_gen(r, k[0], p[1], k[1]);
			ep_curve_get_gen(p[0]);
			ep_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[0], k[0]);
			ep_mul_sim_gen(r, k[0], p[1], k[1]);
			ep_curve_get_gen(p[0]);
			ep_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_neg(k[1], k[1]);
			ep_mul_sim_gen(r, k[0], p[1], k[1]);
			ep_curve_get_gen(p[0]);
			ep_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
			bn_rand_mod(k[0], n);
			bn_rand_mod(k[1], n);
			bn_add(k[0], k[0], n);
			bn_add(k[1], k[1], n);
			ep_mul_sim_gen(r, k[0], p[1], k[1]);
			ep_curve_get_gen(p[0]);
			ep_mul_sim(p[1], p[0], k[0], p[1], k[1]);
			TEST_ASSERT(ep_cmp(p[1], r) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("many simultaneous point multiplications are correct") {
			ep_set_infty(r);
			ep_mul_sim_lot(p[SIM_LOT], p, k, 0);
			TEST_ASSERT(ep_cmp(p[SIM_LOT], r) == RLC_EQ, end);
			for (int j = 0; j < SIM_LOT; j++) {
				bn_rand_mod(k[j], n);
				ep_rand(p[j]);
				ep_mul(p[SIM_LOT], p[j], k[j]);
				ep_add(r, r, p[SIM_LOT]);
				ep_mul_sim_lot(p[SIM_LOT], p, k, j + 1);
				TEST_ASSERT(ep_cmp(p[SIM_LOT], r) == RLC_EQ, end);
			}
			ep_mul(p[SIM_LOT], p[0], k[0]);
			ep_sub(r, r, p[SIM_LOT]);
			bn_zero(k[0]);
			ep_mul_sim_lot(p[SIM_LOT], p, k, SIM_LOT);
			TEST_ASSERT(ep_cmp(p[SIM_LOT], r) == RLC_EQ, end);
			ep_mul(p[SIM_LOT], p[1], k[1]);
			ep_sub(r, r, p[SIM_LOT]);
			ep_sub(r, r, p[SIM_LOT]);
			bn_neg(k[1], k[1]);
			ep_mul_sim_lot(p[SIM_LOT], p, k, SIM_LOT);
			TEST_ASSERT(ep_cmp(p[SIM_LOT], r) == RLC_EQ, end);
			bn_add(k[2], k[2], n);
			ep_mul_sim_lot(p[SIM_LOT], p, k, SIM_LOT);
			TEST_ASSERT(ep_cmp(p[SIM_LOT], r) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("simultaneous multiplication by digits is correct") {
			dig_t d[2];
			rand_bytes((uint8_t *)d, sizeof(d));
			ep_rand(p[0]);
			ep_rand(p[1]);
			ep_mul_sim_dig(r, p, d, 2);
			ep_mul_dig(p[2], p[0], d[0]);
			ep_mul_dig(p[3], p[1], d[1]);
			ep_add(p[2], p[2], p[3]);
			TEST_ASSERT(ep_cmp(r, p[2]) == RLC_EQ, end);
			ep_mul_sim_dig(r, p, d, 0);
			TEST_ASSERT(ep_is_infty(r), end);
		} TEST_END;
	}
	RLC_CATCH_ANY {
		util_print("FATAL ERROR!\n");
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
	for (int i = 0; i <= SIM_LOT; i++) {
		bn_free(k[i]);
		ep_free(p[i]);
	}
	ep_free(r);
	return code;
}

static int compression(void) {
	int code = RLC_ERR;
	ep_t a, b, c;

	ep_null(a);
	ep_null(b);
	ep_null(c);

	RLC_TRY {
		ep_new(a);
		ep_new(b);
		ep_new(c);

		TEST_CASE("point compression is correct") {
			ep_rand(a);
			ep_pck(b, a);
			TEST_ASSERT(ep_upk(c, b) == 1, end);
			TEST_ASSERT(ep_cmp(a, c) == RLC_EQ, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(a);
	ep_free(b);
	ep_free(c);
	return code;
}

static int hashing(void) {
	int code = RLC_ERR;
	ep_t a, b;
	bn_t n;
	/* Allocate buffer with plenty of room. */
	uint8_t msg[4 * RLC_FP_BYTES];

	ep_null(a);
	ep_null(b);
	bn_null(n);

	RLC_TRY {
		ep_new(a);
		ep_new(b);
		bn_new(n);

		ep_curve_get_ord(n);

		TEST_CASE("point hashing is correct") {
			rand_bytes(msg, ep_map_rnd_size());
			ep_map(a, msg, ep_map_rnd_size());
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 0, end);
			/* Hashing is deterministic. */
			ep_map(b, msg, ep_map_rnd_size());
			TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
			ep_mul_basic(a, a, n);
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 1, end);
			ep_map_rnd(a, msg, ep_map_rnd_size());
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 0, end);
			ep_mul_basic(a, a, n);
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 1, end);
		}
		TEST_END;

#if EP_MAP == BASIC || !defined(STRIP)
		TEST_CASE("basic point hashing is correct") {
			rand_bytes(msg, ep_map_rnd_size());
			ep_map_basic(a, msg, ep_map_rnd_size());
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 0, end);
			ep_mul_basic(a, a, n);
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 1, end);
		}
		TEST_END;
#endif

#if EP_MAP == SSWUM || !defined(STRIP)
		TEST_CASE("simplified SWU point hashing is correct") {
			rand_bytes(msg, ep_map_rnd_size());
			ep_map_sswum(a, msg, ep_map_rnd_size());
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 0, end);
			ep_mul_basic(a, a, n);
			TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 1, end);
		}
		TEST_END;

		TEST_CASE("point hashing with a domain separation tag is correct") {
			rand_bytes(msg, ep_map_rnd_size());
			ep_map_dst(a, msg, ep_map_rnd_size(), (const uint8_t *)RLC_DSTAG,
					strlen(RLC_DSTAG));
			ep_map_sswum(b, msg, ep_map_rnd_size());
			TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
			ep_map_dst(b, msg, ep_map_rnd_size(), (const uint8_t *)"TAG", 3);
			TEST_ASSERT(ep_cmp(a, b) != RLC_EQ, end);
			TEST_ASSERT(ep_on_curve(b) && ep_is_infty(b) == 0, end);
			ep_mul_basic(b, b, n);
			TEST_ASSERT(ep_on_curve(b) && ep_is_infty(b) == 1, end);
		}
		TEST_END;
#endif

#if EP_MAP == SSWUM && (FP_PRIME == 256 || FP_PRIME == 384 || FP_PRIME == 521)
		/* Test vectors from RFC 9380, Appendix J, for messages "" and "abc". */
#if FP_PRIME == 256
		const int id = NIST_P256;
		const char *dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
		const char *v[4] = {
			"2C15230B26DBC6FC9A37051158C95B79656E17A1A920B11394CA91C44247D3E4",
			"8A7A74985CC5C776CDFE4B1F19884970453912E9D31528C060BE9AB5C43E8415",
			"0BB8B87485551AA43ED54F009230450B492FEAD5F1CC91658775DAC4A3388A0F",
			"5C41B3D0731A27A7B14BC0BF0CCDED2D8751F83493404C84A88E71FFD424212E"
		};
#define XMD		md_xmd_sh256
#elif FP_PRIME == 384
		const int id = NIST_P384;
		const char *dst = "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_";
		const char *v[4] = {
			"EB9FE1B4F4E14E7140803C1D99D0A93CD823D2B024040F9C067A8ECA1F5A2EEA"
			"C9AD604973527A356F3FA3AEFF0E4D83",
			"0C21708CFF382B7F4643C07B105C2EAEC2CEAD93A917D825601E63C8F21F6ABD"
			"9ABC22C93C2BED6F235954B25048BB1A",
			"E02FC1A5F44A7519419DD314E29863F30DF55A514DA2D655775A81D413003C4D"
			"4E7FD59AF0826DFAAD4200AC6F60ABE1",
			"01F638D04D98677D65BEF99AEF1A12A70A4CBB9270EC55248C04530D8BC1F8F9"
			"0F8A6A859A7C1F1DDCCEDF8F96D675F6"
		};
#define XMD		md_xmd_sh384
#else
		const int id = NIST_P521;
		const char *dst = "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_RO_";
		const char *v[4] = {
			"00FD767CEBB2452030358D0E9CF907F525F50920C8F607889A6A35680727F64F"
			"4D66B161FAFEB2654BEA0D35086BEC0A10B30B14ADEF3556ED9F7F1BC23CECC9"
			"C088",
			"0169BA78D8D851E930680322596E39C78F4FE31B97E57629EF6460DDD68F8763"
			"FD7BD767A4E94A80D3D21A3C2EE98347E024FC73EE1C27166DC3FE5EEEF782BE"
			"411D",
			"002F89A1677B28054B50D15E1F81ED6669B5A2158211118EBDEF8A6EFC77F8CC"
			"AA528F698214E4340155ABC1FA08F8F613EF14A043717503D57E267D57155CF7"
			"84A4",
			"010E0BE5DC8E753DA8CE51091908B72396D3DEED14AE166F66D8EBF0A4E7059E"
			"AD169EA4BEAD0232E9B700DD380B316E9361CFDBA55A08C73545563A80966ECB"
			"B86D"
		};
#define XMD		md_xmd_sh512
#endif
		if (ep_param_get() == id) {
			TEST_ONCE("point hashing follows rfc 9380") {
				for (int j = 0; j < 2; j++) {
					XMD(msg, ep_map_rnd_size(), (const uint8_t *)"abc",
							3 * j, (const uint8_t *)dst, strlen(dst));
					ep_map_rnd(a, msg, ep_map_rnd_size());
					fp_read_str(b->x, v[2 * j], strlen(v[2 * j]), 16);
					fp_read_str(b->y, v[2 * j + 1], strlen(v[2 * j + 1]), 16);
					fp_set_dig(b->z, 1);
					b->coord = BASIC;
					TEST_ASSERT(ep_cmp(a, b) == RLC_EQ, end);
				}
			} TEST_END;
		}
#undef XMD
#endif

		if (!ep_curve_is_super()) {
			if (ep_curve_opt_a() == RLC_ZERO || ep_curve_opt_b() == RLC_ZERO) {
#if EP_MAP == SWIFT || !defined(STRIP)
				TEST_CASE("swift point hashing is correct") {
					rand_bytes(msg, ep_map_rnd_size());
					ep_map_swift(a, msg, ep_map_rnd_size());
					TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 0, end);
					ep_mul_basic(a, a, n);
					TEST_ASSERT(ep_on_curve(a) && ep_is_infty(a) == 1, end);
				}
				TEST_END;
#endif
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	ep_free(a);
	ep_free(b);
	bn_free(n);
	return code;
}

int test(void) {
	ep_param_print();

	util_banner("Utilities:", 1);

	if (memory() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (util() != RLC_OK) {
		return RLC_ERR;
	}

	util_banner("Arithmetic:", 1);

	if (addition() != RLC_OK) {
		return RLC_ERR;
	}

	if (subtraction() != RLC_OK) {
		return RLC_ERR;
	}

	if (doubling() != RLC_OK) {
		return RLC_ERR;
	}

	if (tripling() != RLC_OK) {
		return RLC_ERR;
	}

	if (endomorphism() != RLC_OK) {
		return RLC_ERR;
	}

	if (multiplication() != RLC_OK) {
		return RLC_ERR;
	}

	if (fixed() != RLC_OK) {
		return RLC_ERR;
	}

	if (simultaneous() != RLC_OK) {
		return RLC_ERR;
	}

	if (compression() != RLC_OK) {
		return RLC_ERR;
	}

	if (hashing() != RLC_OK) {
		return RLC_ERR;
	}

	return RLC_OK;
}

int main(void) {
	int r0 = RLC_ERR, r1 = RLC_ERR, r2 = RLC_ERR, r3 = RLC_ERR;
	int c0 = 0, c1 = 0, c2 = 0, c3 = 0;

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the EP module:", 0);

	r0 = ep_param_set_any_plain();
	if (r0 == RLC_OK) {
		c0 = ep_param_get();
		if (test() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	r1 = ep_param_set_any_endom();
	if (r1 == RLC_OK) {
		c1 = ep_param_get();
		if (c1 != c0) {
			if (test() != RLC_OK) {
				core_clean();
				return 1;
			}
		}
	}

	r2 = ep_param_set_any_pairf();
	if (r2 == RLC_OK) {
		c2 = ep_param_get();
		if (c2 != c1) {
			if (test() != RLC_OK) {
				core_clean();
				return 1;
			}
		}
	}

	r3 = ep_param_set_any_super();
	if (r3 == RLC_OK) {
		c3 = ep_param_get();
		if (c3 != c2) {
			if (test() != RLC_OK) {
				core_clean();
				return 1;
			}
		}
	}

	if (r0 == RLC_ERR && r1 == RLC_ERR && r2 == RLC_ERR && r3 == RLC_ERR) {
		if (ep_param_set_any() == RLC_ERR) {
			RLC_THROW(ERR_NO_CURVE);
			core_clean();
			return 0;
		} else {
			if (test() != RLC_OK) {
				core_clean();
				return 1;
			}
		}
	}

	(void)c0;
	(void)c1;
	(void)c2;
	(void)c3;

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
