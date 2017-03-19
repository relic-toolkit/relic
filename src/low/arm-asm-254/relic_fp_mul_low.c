#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

void fp_mulm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	uint32_t d[10];
	fp_muln_low(d, a, b);
	fp_rdcn_low(c, d);
}
