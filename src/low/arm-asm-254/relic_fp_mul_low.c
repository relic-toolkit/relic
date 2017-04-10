#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

dig_t fp_mula_low(dig_t *c, const dig_t *a, dig_t digit) {
        int i;
        dig_t carry;
        dbl_t r;

        carry = 0;
        for (i = 0; i < FP_DIGS; i++, a++, c++) {
                /* Multiply the digit *tmpa by b and accumulate with the previous
                 * result in the same columns and the propagated carry. */
                r = (dbl_t)(*c) + (dbl_t)(*a) * (dbl_t)(digit) + (dbl_t)(carry);
                /* Increment the column and assign the result. */
                *c = (dig_t)r;
                /* Update the carry. */
                carry = (dig_t)(r >> (dbl_t)FP_DIGIT);
        }
        return carry;
}

void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	uint32_t d[10];
	fp_muln_low(d, a, b);
	fp_rdcn_low(c, d);
}
