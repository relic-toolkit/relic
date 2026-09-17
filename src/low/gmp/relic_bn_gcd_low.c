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
 * or <https://www.apache.org/licenses/>
 */

/**
 * @file
 *
 * Implementation of the low-level multiple precision integer greatest common
 * divisor functions.
 *
 * @ingroup bn
 */

#include <gmp.h>

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

size_t bn_gcdn_low(dig_t *c, dig_t *a, size_t sa, dig_t *b, size_t sb) {
	return mpn_gcd((mp_ptr)c, (mp_ptr)a, sa, (mp_ptr)b, sb);
}
 
size_t bn_gcde_low(dig_t *c, dig_t *d, int *sd, dig_t *a, size_t sa,
		dig_t *b, size_t sb) {
	mp_size_t sn;
	size_t r;

	/*
	 * Not (mp_size_t *)sd: mpn_gcdext writes an mp_size_t, which is a long,
	 * while dis_t tracks WSIZE. The two coincide only for a 64-bit WSIZE on
	 * LP64. With a 32-bit WSIZE the callee writes eight bytes into a four-byte
	 * object, and under LLP64 it writes four into eight and leaves the rest
	 * indeterminate, which breaks the sign of the cofactor.
	 */
	r = mpn_gcdext((mp_ptr)c, (mp_ptr)d, &sn, (mp_ptr)a, sa, (mp_ptr)b, sb);
	*sd = sn;
	return r;
}

/*
 * mpn_hgcd2 and the two matrix helpers are gmp-impl.h material: exported from
 * libgmp and stable across the 6.x series, but not a supported interface.
 */
struct hgcd_matrix1 {
	mp_limb_t u[2][2];
};

__GMP_DECLSPEC int __gmpn_hgcd2(mp_limb_t, mp_limb_t, mp_limb_t, mp_limb_t,
		struct hgcd_matrix1 *);
/* Sets (r;b) = M^-1 (a;b). */
__GMP_DECLSPEC mp_size_t __gmpn_matrix22_mul1_inverse_vector(
		const struct hgcd_matrix1 *, mp_ptr, mp_srcptr, mp_ptr, mp_size_t);
/* Sets (r;b) = (a;b) M. Needs room for n + 1 limbs. */
__GMP_DECLSPEC mp_size_t __gmpn_hgcd_mul_matrix1_vector(
		const struct hgcd_matrix1 *, mp_ptr, mp_srcptr, mp_ptr, mp_size_t);

/* gmp-impl.h and longlong.h are not installed; local equivalents. */
#define GP_NORM(p, n)	while ((n) > 0 && (p)[(n) - 1] == 0) (n)--
#define GP_COPY(d, s, n)	do { \
		mp_size_t _i; \
		for (_i = 0; _i < (mp_size_t)(n); _i++) (d)[_i] = (s)[_i]; \
	} while (0)
#define GP_CLZ(c, x)	((c) = __builtin_clzll((unsigned long long)(x)))

/* rp <- rp + qp * sp, returning the new limb count. */
static mp_size_t gcdh_addmul(mp_ptr rp, mp_srcptr qp, mp_size_t qn,
		mp_srcptr sp, mp_size_t n, mp_ptr tp) {
	mp_limb_t cy;

	if (qn == 1) {
		cy = (qp[0] == 1 ? mpn_add_n(rp, rp, sp, n)
				: mpn_addmul_1(rp, sp, n, qp[0]));
	} else {
		mp_size_t sn = n, tn;
		GP_NORM(sp, sn);
		if (sn == 0) {
			return n;
		}
		if (qn > sn) {
			mpn_mul(tp, qp, qn, sp, sn);
		} else {
			mpn_mul(tp, sp, sn, qp, qn);
		}
		tn = sn + qn;
		tn -= (tp[tn - 1] == 0);
		if (tn >= n) {
			cy = mpn_add(rp, tp, tn, rp, n);
			n = tn;
		} else {
			cy = mpn_add(rp, rp, n, tp, tn);
		}
	}
	rp[n] = cy;
	return n + (cy != 0);
}

/*
 * Partial GCD driven by repeated mpn_hgcd2 rather than one mpn_hgcd followed by
 * a Lehmer loop at the bn_t level.
 *
 * mpn_hgcd2 reduces the top two limbs in registers and commits a whole batch of
 * euclidean steps per full-precision matrix application, so its cost per batch
 * barely grows with the operands while the batch covers proportionally more of
 * the reduction. That is what makes the difference widen with discriminant
 * size. When it declines -- a top limb below 2, so the ratio is too skewed for
 * the two-limb window -- one division or one subtraction is done instead,
 * exactly the cases mpn_hgcd2 documents.
 *
 * On entry a and b hold size limbs each; on return the reduced pair is in
 * place, the cofactors are in u00..u11 with *sm limbs, and the return value is
 * the new limb count. Each of a, b and the four cofactors needs size + 1 limbs.
 */
size_t bn_gcdh_low(dig_t *u00, dig_t *u01, dig_t *u10, dig_t *u11, size_t *sm,
		dig_t *a, dig_t *b, size_t size, size_t target) {
	struct hgcd_matrix1 M;
	mp_size_t n = (mp_size_t)size, un = 1, vn = 1;
	mp_ptr ap = (mp_ptr)a, bp = (mp_ptr)b;
	mp_ptr v00 = (mp_ptr)u00, v01 = (mp_ptr)u01;
	mp_ptr v10 = (mp_ptr)u10, v11 = (mp_ptr)u11;
	mp_ptr t0 = RLC_ALLOCA(dig_t, 4 * (size + 2));
	mp_ptr t1 = t0 + 2 * (size + 2), t2 = t1 + size + 2;

	dv_zero((dig_t *)v00, size + 1);
	dv_zero((dig_t *)v01, size + 1);
	dv_zero((dig_t *)v10, size + 1);
	dv_zero((dig_t *)v11, size + 1);
	v00[0] = 1;
	v11[0] = 1;

	while (n > (mp_size_t)target && n >= 2) {
		mp_limb_t mask = ap[n - 1] | bp[n - 1];
		mp_limb_t ah, al, bh, bl;

		if (mask == 0) {
			n--;
			continue;
		}
		if (mask & ((mp_limb_t)1 << (GMP_NUMB_BITS - 1))) {
			ah = ap[n - 1]; al = ap[n - 2];
			bh = bp[n - 1]; bl = bp[n - 2];
		} else {
			int sh;
			GP_CLZ(sh, mask);
			ah = (ap[n - 1] << sh) | (ap[n - 2] >> (GMP_NUMB_BITS - sh));
			bh = (bp[n - 1] << sh) | (bp[n - 2] >> (GMP_NUMB_BITS - sh));
			if (n > 2) {
				al = (ap[n - 2] << sh) | (ap[n - 3] >> (GMP_NUMB_BITS - sh));
				bl = (bp[n - 2] << sh) | (bp[n - 3] >> (GMP_NUMB_BITS - sh));
			} else {
				al = ap[n - 2] << sh;
				bl = bp[n - 2] << sh;
			}
		}

		if (__gmpn_hgcd2(ah, al, bh, bl, &M)) {
			n = __gmpn_matrix22_mul1_inverse_vector(&M, t0, ap, bp, n);
			GP_COPY(ap, t0, n);
			vn = __gmpn_hgcd_mul_matrix1_vector(&M, t0, v00, v01, vn);
			GP_COPY(v00, t0, vn);
			un = __gmpn_hgcd_mul_matrix1_vector(&M, t0, v10, v11, un);
			GP_COPY(v10, t0, un);
		} else if (bp[n - 1] < 2 && mpn_cmp(ap, bp, n) > 0) {
			mp_size_t bn = n, qn;
			GP_NORM(bp, bn);
			if (bn == 0) {
				break;
			}
			/* bn_divn_low normalizes both operands, so the divisor is copied */
			GP_COPY(t2, bp, bn);
			mpn_tdiv_qr(t1, ap, 0, ap, n, t2, bn);
			qn = n - bn + 1;
			GP_NORM(t1, qn);
			n = bn;
			if (qn > 0) {
				vn = gcdh_addmul(v01, t1, qn, v00, vn, t0);
				un = gcdh_addmul(v11, t1, qn, v10, un, t0);
			}
		} else if (ap[n - 1] < 2 && mpn_cmp(bp, ap, n) > 0) {
			mp_size_t an = n, qn;
			GP_NORM(ap, an);
			if (an == 0) {
				break;
			}
			GP_COPY(t2, ap, an);
			mpn_tdiv_qr(t1, bp, 0, bp, n, t2, an);
			qn = n - an + 1;
			GP_NORM(t1, qn);
			n = an;
			if (qn > 0) {
				vn = gcdh_addmul(v00, t1, qn, v01, vn, t0);
				un = gcdh_addmul(v10, t1, qn, v11, un, t0);
			}
		} else {
			/* a and b too close for the window: one subtraction */
			if (mpn_cmp(ap, bp, n) < 0) {
				mpn_sub_n(bp, bp, ap, n);
				v00[vn] = mpn_add_n(v00, v00, v01, vn);
				vn += (v00[vn] > 0);
				v10[un] = mpn_add_n(v10, v10, v11, un);
				un += (v10[un] > 0);
			} else {
				mpn_sub_n(ap, ap, bp, n);
				v01[vn] = mpn_add_n(v01, v00, v01, vn);
				vn += (v01[vn] > 0);
				v11[un] = mpn_add_n(v11, v10, v11, un);
				un += (v11[un] > 0);
			}
		}
		if (n == 0) {
			break;
		}
	}

	/*
	 * The rows can end at different lengths but one size is reported, so the
	 * shorter is zero-padded: the caller reads *sm digits from all four.
	 */
	{
		mp_size_t mx = (un > vn ? un : vn), i;
		for (i = vn; i < mx; i++) {
			v00[i] = 0;
			v01[i] = 0;
		}
		for (i = un; i < mx; i++) {
			v10[i] = 0;
			v11[i] = 0;
		}
		un = mx;
	}
	*sm = (size_t)un;
	return (size_t)n;
}
