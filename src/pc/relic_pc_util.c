/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2013 RELIC Authors
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
 * Implementation of pairing computation utilities.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Internal macro to map GT function to basic FPX implementation. The final
 * exponentiation from the pairing is used to move element to subgroup.
 *
 * @param[out] A 				- the element to assign.
 */
#define gt_rand_imp(A)			RLC_CAT(RLC_GT_LOWER, rand)(A)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void gt_rand(gt_t a) {
	gt_rand_imp(a);
#if FP_PRIME < 1536
#if FP_PRIME == 575
	pp_exp_k48(a, a);
#elif FP_PRIME == 315 || FP_PRIME == 317 || FP_PRIME == 509
	pp_exp_k24(a, a);
#elif FP_PRIME == 330 || FP_PRIME == 765 || FP_PRIME == 766
	pp_exp_k16(a, a);
#elif FP_PRIME == 508 || FP_PRIME == 768 || FP_PRIME == 638 && !defined(FP_QNRES)
	pp_exp_k18(a, a);
#else
	pp_exp_k12(a, a);
#endif
#else
#if FP_PRIME == 1536
	pp_exp_k2(a, a);
#else
	pp_exp_k1(a, a);
#endif
#endif
}

void gt_get_gen(gt_t g) {
    gt_copy(g, core_get()->gt_g);
}

int g1_is_valid(const g1_t a) {
	bn_t n, t;
	g1_t u, v, w;
	size_t l0, l1, r = 0;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1];

	if (g1_is_infty(a)) {
		return 0;
	}

	bn_null(n);
	bn_null(t);
	g1_null(u);
	g1_null(v);
	g1_null(w);

	RLC_TRY {
		bn_new(n);
		bn_new(t);
		g1_new(u);
		g1_new(v);
		g1_new(w);

		ep_curve_get_cof(n);
		if (bn_cmp_dig(n, 1) == RLC_EQ) {
			/* If curve has prime order, simpler to check if point on curve. */
			r = g1_on_curve(a);
		} else {
			fp_prime_get_par(n);
			switch (ep_curve_is_pairf()) {
#if defined(EP_ENDOM)
				/* Formulas from "Co-factor clearing and subgroup membership
				 * testing on pairing-friendly curves" by El Housni, Guillevic,
				 * Piellard. https://eprint.iacr.org/2022/352.pdf */
				case EP_B12:
				case EP_B24:
				case EP_B48:
					/* Check [\psi(P) == [z^2 - 1]P. */
					bn_sqr(n, n);
					if (ep_curve_is_pairf() == EP_B24) {
						/* Check [\psi(P) == [z^4 - 1]P. */
						bn_sqr(n, n);
					}
					if (ep_curve_is_pairf() == EP_B48) {
						/* Check [\psi(P) == [z^8 - 1]P. */
						bn_sqr(n, n);
						bn_sqr(n, n);
					}
					bn_sub_dig(n, n, 1);
					g1_mul_any(u, a, n);
					ep_psi(v, a);
					r = g1_on_curve(a) && (g1_cmp(v, u) == RLC_EQ);
					break;
				/* if (u % 2) == 0, check (u**4)*\psi(P) == P
    		 	* else check (u**4-1)//2 * (\psi(P) - P) == P */
				case EP_N16:
					bn_sqr(n, n);
					bn_sqr(n, n);
					ep_psi(u, a);
					if (!bn_is_even(n)) {
						bn_sub_dig(n, n, 1);
						bn_hlv(n, n);
						g1_sub(u, u, a);
						g1_norm(u, u);
					}
					g1_mul_any(u, u, n);
					r = g1_on_curve(a) && (g1_cmp(u, a) == RLC_EQ);
					break;
				/* Formulas from "Fast Subgroup Membership Testings on Pairing-
				 * friendly Curves" by Yu Dai, Kaizhan Lin, Chang-An Zhao,
				 * Zijian Zhou. https://eprint.iacr.org/2022/348.pdf */
				case EP_K16:
				    /* If u = 25 or 45 mod 70 then a1 = ((u//5)**4 + 5)//14
					 * is an integer by definition. */
					bn_div_dig(n, n, 5);
					bn_sqr(n, n);
					bn_sqr(n, n);
					bn_add_dig(n, n, 5);
					bn_div_dig(n, n, 14);
					bn_mul_dig(n, n, 17);
					bn_neg(n, n);
					bn_add_dig(n, n, 6);
					/* Compute P1 = a1*P. */
					g1_mul_any(w, a, n);
					/* Compute \psi([17]P1) - [31]P1 */
					g1_dbl(u, w);
					g1_dbl(u, u);
					g1_dbl(u, u);
					g1_dbl(v, u);
					g1_add(u, v, w);
					g1_dbl(v, v);
					g1_sub(v, v, w);
					ep_psi(u, u);
					g1_add(u, u, v);
					g1_neg(u, u);
					r = g1_on_curve(a) && (g1_cmp(u, a) == RLC_EQ);
					break;
				case EP_FM16:
					/* Check that P == (u**4)*\phi(P). */
					g1_mul_any(u, a, n);
					g1_mul_any(u, u, n);
					g1_mul_any(u, u, n);
					g1_mul_any(u, u, n);
					ep_psi(u, u);
					r = g1_on_curve(a) && (g1_cmp(u, a) == RLC_EQ);
					break;
				case EP_K18:
					/* Check that [a_0]P + [a_1]\psi(P)) == O, for
					 * a_0 = 19a_1 + 1, a_1 = (x/7)^3 */
					bn_div_dig(n, n, 7);
					bn_sqr(t, n);
					bn_mul(n, n, t);
					bn_mul_dig(t, n, 19);
					bn_add_dig(t, t, 1);
					ep_psi(v, a);

					l0 = l1 = RLC_FP_BITS + 1;
					bn_rec_naf(naf0, &l0, t, 2);
					bn_rec_naf(naf1, &l1, n, 2);

					ep_copy(u, a);
					for (int i = RLC_MAX(l0, l1) - 2; i >= 0; i--) {
						g1_dbl(u, u);
						if (naf0[i] > 0) {
							g1_add(u, u, a);
						}
						if (naf0[i] < 0) {
							g1_sub(u, u, a);
						}
						if (naf1[i] > 0) {
							g1_add(u, u, v);
						}
						if (naf1[i] < 0) {
							g1_sub(u, u, v);
						}
					}
					if (bn_sign(n) == RLC_NEG) {
						g1_neg(u, u);
					}
					r = g1_on_curve(a) && g1_is_infty(u);
					break;
				case EP_FM18:
					/* Check that [u^3 - 1]P == \psi(P). */
					ep_psi(u, a);
					bn_sqr(t, n);
					bn_mul(t, t, n);
					bn_sub_dig(t, t, 1);
					g1_mul_any(v, a, t);
					r = g1_on_curve(a) && (g1_cmp(u, v) == RLC_EQ);
					break;
				case EP_SG18:
					/* Check that [9u^3+2]\psi(P) == -P. */
					/* Apply \psi twice to get the other beta. */
					ep_psi(u, a);
					ep_psi(u, u);
					g1_mul_any(v, u, n);
					g1_mul_any(v, v, n);
					g1_mul_any(v, v, n);
					g1_mul_dig(v, v, 9);
					g1_dbl(u, u);
					g1_add(v, v, u);
					g1_norm(v, v);
					g1_neg(v, v);
					r = g1_on_curve(a) && (g1_cmp(a, v) == RLC_EQ);
					break;
#endif
				default:
					pc_get_ord(n);
					bn_sub_dig(n, n, 1);
					/* Otherwise, check order explicitly. */
					g1_mul_any(u, a, n);
					g1_neg(u, u);
					r = g1_on_curve(a) && (g1_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(t);
		g1_free(u);
		g1_free(v);
		g1_free(w);
	}

	return r;
}

int g2_is_valid(const g2_t a) {
	g2_t s, t, u, v, w;
	bn_t n;
	dig_t rem;
	int r = 0;

#if FP_PRIME >= 1536
	return g1_is_valid(a);
#else

	if (g2_is_infty(a)) {
		return 0;
	}

	bn_null(n);
	g2_null(s);
	g2_null(t);
	g2_null(u);
	g2_null(v);
	g2_null(w);

	RLC_TRY {
		bn_new(n);
		g2_new(s);
		g2_new(t);
		g2_new(u);
		g2_new(v);
		g2_new(w);

		fp_prime_get_par(n);
		switch (ep_curve_is_pairf()) {
#if defined(EP_ENDOM)
			/* Formulas from "Co-factor clearing and subgroup membership
			* testing on pairing-friendly curves" by El Housni, Guillevic,
			* Piellard. https://eprint.iacr.org/2022/352.pdf */
			case EP_B12:
			case EP_B24:
			case EP_B48:
				if (core_get()->ep_id == B12_383) {
					/* Since p mod n = r, we can check instead that
					* psi^4(P) + P == \psi^2(P). */
					g2_frb(u, a, 4);
					g2_add(u, u, a);
					g2_frb(v, a, 2);
				} else {
				/* Check \psi(P) == [z]P. */
					fp_prime_get_par(n);
					g2_mul_any(u, a, n);
					g2_frb(v, a, 1);
				}
				r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
				break;
			/* Formulas from "Fast Subgroup Membership Testings for G1,
			 * G2 and GT on Pairing-friendly Curves" by Dai et al.
			 * https://eprint.iacr.org/2022/348.pdf */
			case EP_BN:
				/*Check that [z+1]P+[z]\psi(P)+[z]\psi^2(P)=[2z]\psi^3(P)*/
				g2_mul_any(u, a, n);
				g2_frb(v, u, 1);
				g2_add(u, u, a);
				g2_add(u, u, v);
				g2_frb(v, v, 1);
				g2_add(u, u, v);
				g2_frb(v, v, 1);
                g2_dbl(v, v);
				r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
				break;
			/* If u is even, check that [u*p^3]P = P
			 * else check [p^5]P = [u]P. */
			case EP_N16:
				g2_mul_any(u, a, n);
				if (bn_is_even(n)) {
					g2_frb(v, u, 3);
					g2_copy(u, a);
				} else {
					g2_frb(v, a, 5);
				}
				r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
				break;
			/* Formulas from "Fast Subgroup Membership Testings for G1,
			 * G2 and GT on Pairing-friendly Curves" by Dai et al.
			 * https://eprint.iacr.org/2022/348.pdf
			 * Paper has u = 45 mod 70, we ran their code for u = 25 mod 70. */
			case EP_K16:
				bn_mod_dig(&rem, n, 70);
				if (rem == 45) {
					bn_neg(n, n);
				}
				/* Compute s = (\pm u - 25)/70. */
				bn_sub_dig(n, n, 25);
				bn_div_dig(n, n, 70);
				/* [11s+4, 9s+3, 3s+1, -(3s+1), -13*u-5, -7*u-3, u, -11s-4] */
				/* or [11s+4, -9s-3, 3s+1, 3s+1, -13*u-5, 7*u+3, u, 11s+4]. */
				g2_mul_any(u, a, n);	/* u = a^s*/
				g2_frb(w, u, 6);
				g2_dbl(s, u);
				g2_add(v, s, a);
				g2_add(t, v, u);		/* t = a^(3s + 1) */
				g2_copy(u, v);			/* u = a^(2s + 1)*/
				g2_frb(v, t, 2);
				g2_add(w, w, v);
				g2_frb(v, t, 3);
				if (rem == 45) {
					g2_add(w, w, v);
				} else {
					g2_sub(w, w, v);
				}
				g2_dbl(v, t);
				g2_add(t, t, v);		/* t = a^(9s + 3). */
				g2_frb(v, t, 1);
				if (rem == 45) {
					g2_neg(v, v);
				}
				g2_add(w, w, v);
				g2_sub(s, t, s);		/* s = a^(7s + 3). */
				g2_frb(v, s, 5);
				if (rem == 45) {
					g2_add(w, w, v);
				} else {
					g2_sub(w, w, v);
				}
				g2_add(t, t, u);		/* t = a^(11s + 4). */
				g2_add(w, w, t);
				g2_frb(v, t, 7);
				if (rem == 45) {
					g2_add(w, w, v);
				} else {
					g2_sub(w, w, v);
				}
				g2_add(t, t, u);		/* t = a^(13s + 5). */
				g2_frb(t, t, 4);
				r = g2_on_curve(a) && (g2_cmp(w, t) == RLC_EQ);
				break;
			case EP_FM16:
				/* Check that u*Q == psi(Q). */
				g2_mul_any(u, a, n);
				g2_frb(v, a, 1);
				r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
				break;
			case EP_K18:
				/* Check that P + u*psi2P + 2*psi3P == \mathcal{O}. */
				g2_frb(u, a, 2);
				g2_frb(v, u, 1);
				g2_dbl(v, v);
				g2_mul_any(u, u, n);
				g2_add(v, v, u);
				g2_neg(u, v);
				r = g2_on_curve(a) && (g2_cmp(u, a) == RLC_EQ);
				break;
			case EP_FM18:
				/* Check that Q == -u*\psi^2(Q). */
				bn_neg(n, n);
				g2_mul_any(u, a, n);
				g2_frb(u, u, 2);
				r = g2_on_curve(a) && (g2_cmp(u, a) == RLC_EQ);
				break;
			case EP_SG18:
				/* Check that 3u*P + 2\psi^2(P) == \psi^5P] and [3]P \eq O. */
				bn_mul_dig(n, n, 3);
				g2_mul_any(u, a, n);
				r = g2_is_infty(a) == 0;
				g2_frb(v, a, 2);
				g2_add(u, u, v);
				g2_add(u, u, v);
				g2_frb(v, a, 5);
				r &= g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
				break;
#endif
			default:
				pc_get_ord(n);
				bn_sub_dig(n, n, 1);
				/* Otherwise, check order explicitly. */
				g2_mul_any(u, a, n);
				g2_neg(u, u);
				r = g2_on_curve(a) && (g2_cmp(u, a) == RLC_EQ);
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		g2_free(s);
		g2_free(t);
		g2_free(u);
		g2_free(v);
		g2_free(w);
	}

	return r;
#endif
}

int gt_is_valid(const gt_t a) {
	bn_t n;
	gt_t s, t, u, v, w;
	int l, r = 0;
	const int *b;
	dig_t rem;

	if (gt_is_unity(a)) {
		return 0;
	}

	bn_null(n);
	gt_null(s);
	gt_null(t);
	gt_null(u);
	gt_null(v);
	gt_null(w);

	RLC_TRY {
		bn_new(n);
		gt_new(s);
		gt_new(t);
		gt_new(u);
		gt_new(v);
		gt_new(w);

		fp_prime_get_par(n);
		b = fp_prime_get_par_sps(&l);
		switch (ep_curve_is_pairf()) {
			/* Formulas from "Families of SNARK-friendly 2-chains of
			 * elliptic curves" by Housni and Guillevic.
			 * https://eprint.iacr.org/2021/1359.pdf */
			case EP_B12:
				if (core_get()->ep_id == B12_383) {
					/* GT-strong, so test for cyclotomic only. */
					r = 1;
				} else {
					/* Check that a^u = a^p. */
					gt_frb(u, a, 1);
					fp12_exp_cyc_sps((void *)v, (void *)a, b, l, bn_sign(n));
					r = (gt_cmp(u, v) == RLC_EQ);
				}
				r &= fp12_test_cyc((void *)a);
				break;
			case EP_B24:
				/* Check that a^u = a^p. */
				gt_frb(u, a, 1);
				fp24_exp_cyc_sps((void *)v, (void *)a, b, l, bn_sign(n));
				r = (gt_cmp(u, v) == RLC_EQ);
				r &= fp24_test_cyc((void *)a);
				break;
			case EP_B48:
				/* Check that a^u = a^p. */
				gt_frb(u, a, 1);
				fp48_exp_cyc_sps((void *)v, (void *)a, b, l, bn_sign(n));
				r = (gt_cmp(u, v) == RLC_EQ);
				r &= fp48_test_cyc((void *)a);
				break;
			/* Formulas from "Fast Subgroup Membership Testings for G1,
			 * G2 and GT on Pairing-friendly Curves" by Dai et al.
			 * https://eprint.iacr.org/2022/348.pdf */
			case EP_BN:
				/*Check that [z+1]P+[z]\psi(P)+[z]\psi^2(P)=[2z]\psi^3(P)*/
				fp12_exp_cyc_sps((void *)u, (void *)a, b, l, bn_sign(n));
				gt_frb(v, u, 1);
				gt_mul(u, u, a);
				gt_mul(u, u, v);
				gt_frb(v, v, 1);
				gt_mul(u, u, v);
				gt_frb(v, v, 1);
				gt_sqr(v, v);
				r = (gt_cmp(u, v) == RLC_EQ);
				r &= fp12_test_cyc((void *)a);
				break;
			/* If u is even, check that [u*p^3]P = P
			 * else check [p^5]P = [u]P. */
			case EP_N16:
				fp_prime_get_par(n);
				gt_exp(u, a, n);
				if (bn_is_even(n)) {
					gt_frb(v, u, 3);
					gt_copy(u, a);
				} else {
					gt_frb(v, a, 5);
				}
				r = (gt_cmp(u, v) == RLC_EQ);
				r &= fp16_test_cyc((void *)a);
				break;
			case EP_K16:
				fp_prime_get_par(n);
				bn_mod_dig(&rem, n, 70);
				if (rem == 45) {
					bn_neg(n, n);
				}
				/* Compute s = (u - 25)/70. */
				bn_sub_dig(n, n, 25);
				bn_div_dig(n, n, 70);
				/* Vectors for u = 25 or 45 mod 70 below, respectively:     */
				/* [11s+4, 9s+3, 3s+1, -(3s+1), -13*u-5, -7*u-3, u, -11s-4] */
				/* or [11s+4, -9s-3, 3s+1, 3s+1, -13*u-5, 7*u+3, u, 11s+4]. */
				gt_exp(u, a, n);	/* u = a^s*/
				gt_frb(w, u, 6);
				gt_sqr(s, u);
				gt_mul(v, s, a);
				gt_mul(t, v, u);		/* t = a^(3s + 1) */
				gt_copy(u, v);			/* u = a^(2s + 1)*/
				gt_frb(v, t, 2);
				gt_mul(w, w, v);
				gt_frb(v, t, 3);
				if (rem != 45) {
					gt_inv(v, v);
				}
				gt_mul(w, w, v);
				gt_sqr(v, t);
				gt_mul(t, t, v);		/* t = a^(9s + 3). */
				gt_frb(v, t, 1);
				if (rem == 45) {
					gt_inv(v, v);
				}
				gt_mul(w, w, v);
				gt_inv(s, s);
				gt_mul(s, t, s);		/* s = a^(7s + 3). */
				gt_frb(v, s, 5);
				if (rem != 45) {
					gt_inv(v, v);
				}
				gt_mul(w, w, v);
				gt_mul(t, t, u);		/* t = a^(11s + 4). */
				gt_mul(w, w, t);
				gt_frb(v, t, 7);
				if (rem != 45) {
					gt_inv(v, v);
				}
				gt_mul(w, w, v);
				gt_mul(t, t, u);		/* t = a^(13s + 5). */
				gt_frb(t, t, 4);
				r = (gt_cmp(w, t) == RLC_EQ);
				r &= fp16_test_cyc((void *)a);
				break;
			case EP_FM16:
				/* Check that u*Q == psi(Q). */
				fp_prime_get_par(n);
				gt_exp(u, a, n);
				gt_frb(v, a, 1);
				r = (gt_cmp(u, v) == RLC_EQ);
				r &= fp16_test_cyc((void *)a);
				break;
			case EP_K18:
				/* Check that P + u*psi2P + 2*psi3P == \mathcal{O}. */
				gt_frb(u, a, 2);
				gt_frb(v, u, 1);
				gt_sqr(v, v);
				fp18_exp_cyc_sps((void *)u, (void *)u, b, l, bn_sign(n));
				gt_mul(v, v, u);
				gt_inv(u, v);
				r = (gt_cmp(u, a) == RLC_EQ);
				r &= fp18_test_cyc((void *)a);
				break;
			case EP_FM18:
				/* Check that Q == -u*\psi^2(Q). */
				bn_neg(n, n);
				gt_exp(u, a, n);
				gt_frb(u, u, 2);
				r = (gt_cmp(u, a) == RLC_EQ);
				r &= fp18_test_cyc((void *)a);
				break;
			case EP_SG18:
				/* Check that 3u*P + 2\psi^2(P) == \psi^5P] and [3]P \eq O. */
				fp_prime_get_par(n);
				bn_mul_dig(n, n, 3);
				gt_exp(u, a, n);
				r = gt_is_unity(a) == 0;
				gt_frb(v, a, 2);
				gt_mul(u, u, v);
				gt_mul(u, u, v);
				gt_frb(v, a, 5);
				r &= fp18_test_cyc((void *)a);
			default:
				/* Common case. */
				pc_get_ord(n);
				bn_sub_dig(n, n, 1);
				gt_exp(u, a, n);
				gt_inv(u, u);
				r = (gt_cmp(u, a) == RLC_EQ);
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		gt_free(s);
		gt_free(t);
		gt_free(u);
		gt_free(v);
		gt_free(w);
	}

	return r;
}
