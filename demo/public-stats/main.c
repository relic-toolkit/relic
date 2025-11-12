/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Benchmarks for cryptographic protocols.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "csv.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define STATES 		19
#define GROUPS		3
#define DAYS 		180
#define FACTOR		(1000000)
#define FIXED		((uint64_t)100000)
#define DATABASE	"COVID19-Spain"
#define BEG_2018	"27/03/2018"
#define END_2018	"23/09/2018"
#define BEG_2019	"27/03/2019"
#define END_2019	"23/09/2019"
#define BEG_2020	"2020-03-27"
#define END_2020	"2020-09-23"

/* First value is population in each of the autonomous communities in 2020. */
const uint64_t populations[STATES] = {
	8405294, 1316064, 1024381, 1176627, 2188626, 580997, 2410819,
	2030807, 7516544, 4948411, 1067272, 2699299, 6587711, 1479098, 646197,
	2172591, 312719, 84913, 84667
};

/* Total population per age group in 2019. */
const uint64_t pyramid[GROUPS] = { 37643844, 4482743, 4566276 };

const char *acronyms[STATES] = {
	"AN", "AR", "AS", "IB", "CN", "CB", "CL", "CM", "CT", "VC",
	"EX", "GA", "MD", "MC", "NC", "PV", "RI", "CE", "ML"
};

const char *acs[STATES] = {
	"Andalusia", "Aragón", "Asturias", "Balearics", "Canary Islands",
	"Cantabria", "Castile & León", "Castile-La Mancha", "Catalonia",
	"Valencia", "Extremadura", "Galicia", "Madrid", "Murcia",
	"Navarre", "Basque Country", "La Rioja", "Ceuta", "Melilla"
};

/* Population pyramids for autonomous communities, taken from countryeconomy.com */
const double pyramids[STATES][GROUPS] = {
	{15.86 + 66.98, 9.06, 17.16 - 9.06},
	{14.12 + 64.23, 10.26, 21.65 - 10.26},
	{10.97 + 63.37, 12.82, 25.66 - 12.82},
	{14.89 + 69.29, 8.62, 15.82 - 8.62},
	{13.20 + 70.57, 8.91, 16.22 - 8.91},
	{13.29 + 64.81, 11.11, 21.90 - 11.11},
	{11.94 + 62.83, 11.41, 25.23 - 11.41},
	{15.11 + 65.91, 8.80, 18.99 - 8.80},
	{15.53 + 65.36, 9.69, 19.12 - 9.69},
	{14.87 + 65.62, 10.15, 19.51 - 10.15},
	{13.66 + 65.70, 9.78, 20.64 - 9.78},
	{11.87 + 62.96, 11.90, 25.16 - 11.90},
	{15.48 + 66.66, 9.13, 18.86 - 9.13},
	{17.18 + 67.04, 8.19, 15.78 - 8.19},
	{15.51 + 64.69, 9.88, 19.80 - 9.88},
	{13.20 + 70.57, 8.91, 16.22 - 8.91},
	{11.87 + 62.96, 11.90, 25.16 - 11.90},
	{20.42 + 67.57, 6.58, 12.02 - 6.58},
	{15.48 + 66.66, 9.13, 17.86 - 9.13},
	//{80.55, 9.59, 9.77} //Spain
};

/* Read data from CSV in a given time interval. */
void read_region(g1_t s[], char *l[], bn_t m[], int *counter,
		uint64_t metric[3], const char *file, int region, char *start,
		char *end, g1_t t1, g1_t p1, bn_t sk1, bn_t sk2, g1_t pk1, g2_t pk2,
		g1_t pk3) {
	FILE *stream = fopen(file, "r");
	int found = 0;
	char line[1024];
	char str[3];
	char label[100] = { 0 };
	dig_t n;
	uint64_t acc[3] = { 0 };

	sprintf(str, "%d", region);
	while (fgets(line, 1024, stream)) {
		if (strstr(line, start) != NULL) {
			found = 1;
		}
		if (strstr(line, end) != NULL) {
			found = 0;
		}
		char **tmp = parse_csv(line);
		char **ptr = tmp;

		if (found && !strcmp(ptr[0], "ccaa") && !strcmp(ptr[2], str) &&
				!strcmp(ptr[5], "todos") && strcmp(ptr[7], "todos")) {
			n = round(atof(ptr[9]));
			if (strcmp(ptr[6], "menos_65") == 0) {
				//printf("< 65 = %s\n", ptr[9]);
				metric[0] += n;
			}
			if (strcmp(ptr[6], "65_74") == 0) {
				//printf("65-74 = %s\n", ptr[9]);
				metric[1] += n;
			}
			if (strcmp(ptr[6], "mas_74") == 0) {
				//printf("> 74 = %s\n", ptr[9]);
				metric[2] += n;
			}

			bn_set_dig(m[*counter], n);
			l[*counter] = strdup(ptr[8]);
			cp_smklhs_sig(s[*counter], m[*counter], DATABASE, acs[region - 1],
				l[*counter], t1, p1, sk1, sk2, pk1, pk2, pk3);
			(*counter)++;
		}

		free_csv_line(tmp);
	}
	fclose(stream);
}

int main(int argc, char *argv[]) {
	uint64_t baseline[GROUPS] = { 0, 0, 0 };
	uint64_t mortality[GROUPS] = { 0, 0, 0 };
	uint64_t expected[GROUPS] = { 0, 0, 0 };
	uint64_t observed[STATES][GROUPS];
	uint64_t ratios[STATES][GROUPS];
	dig_t ft[STATES];
	bn_t y1, y2, res, t[STATES], sk1[STATES], sk2[STATES], m[STATES][3 * GROUPS * DAYS];
	g1_t t1, p1, sig, sigs[STATES][3 * GROUPS * DAYS], cs[STATES], pk1[STATES], pk3[STATES];
	g2_t t2, p2, pk2[STATES];
	ec_t u, ps1, ps2, ls1[STATES], rs1[STATES], ls2[STATES], rs2[STATES];
	char *l[STATES][3 * GROUPS * DAYS];
	dig_t *f[STATES];
	size_t flen[STATES];
	int counter;
	uint64_t total;
	uint64_t excess;

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (pc_param_set_any() != RLC_OK) {
		core_clean;
		return 1;
	}

	RLC_TRY {
		/* Initialize and generate keys for signers. */
		bn_null(res);
		bn_new(res);
		bn_null(y1);
		bn_null(y2);	
		bn_new(y1);
		bn_new(y2);
		g1_null(u);
		g1_new(u);
		g1_null(t1);
		g1_null(p1);
		g1_new(t1);
		g1_new(p1);
		g1_null(sig);
		g1_new(sig);
		g2_null(t2);
		g2_null(p2);
		g2_new(t2);
		g2_new(p2);
		for (int i = 0; i < STATES; i++) {
			f[i] = RLC_ALLOCA(dig_t, 2 * GROUPS * DAYS);
			bn_null(t[i]);
			bn_new(t[i]);
			bn_null(sk1[i]);
			bn_null(sk2[i]);
			bn_new(sk1[i]);
			bn_new(sk2[i]);
			g1_null(cs[i]);
			g1_new(cs[i]);
			g1_null(pk1[i]);
			g1_new(pk1[i]);
			g2_null(pk2[i]);
			g2_new(pk2[i]);
			g1_null(pk3[i]);
			g1_new(pk3[i]);
			cp_smklhs_gen(sk1[i], sk2[i], pk1[i], pk2[i], pk3[i]);
			for (int j = 0; j < GROUPS; j++) {
				for (int k = 0; k < 3 * DAYS; k++) {
					bn_null(m[i][j * 3 * DAYS + k]);
					bn_new(m[i][j * 3 * DAYS + k]);
					g1_null(sigs[i][j * 3 * DAYS + k]);
					g1_new(sigs[i][j * 3 * DAYS + k]);
					l[i][j * 3 * DAYS + k] = NULL;
				}
			}
		}

		/* Compute current population of every age group in each autonomous community. */
		for (int i = 0; i < STATES; i++) {
			for (int j = 0; j < GROUPS; j++) {
				ratios[i][j] = pyramids[i][j] / 100.0 * populations[i];
			}
		}

		cp_smklhs_set(u, t1, p1, t2, p2);
		for (int i = 0; i < STATES; i++) {
			counter = 0;
			observed[i][0] = observed[i][1] = observed[i][2] = 0;
			read_region(sigs[i], l[i], m[i], &counter, baseline,
					"data_04_13.csv", i + 1, BEG_2018, END_2018, t1, p1, sk1[i],
					sk2[i], pk1[i], pk2[i], pk3[i]);
			read_region(sigs[i], l[i], m[i], &counter, baseline,
					"data_04_13.csv", i + 1, BEG_2019, END_2019, t1, p1, sk1[i],
					sk2[i], pk1[i], pk2[i], pk3[i]);
			read_region(sigs[i], l[i], m[i], &counter, observed[i], "data.csv",
					i + 1, BEG_2020, END_2020, t1, p1, sk1[i],
					sk2[i], pk1[i], pk2[i], pk3[i]);
		}

		for (int j = 0; j < GROUPS; j++) {
			mortality[j] = FIXED * FACTOR / (2 * pyramid[j]) * baseline[j];
		}

		total = excess = 0;
		for (int i = 0; i < STATES; i++) {
			printf("%s -- %s:\n", acronyms[i], acs[i]);

			for (int j = 0; j < GROUPS; j++) {
				expected[j] = (FIXED * ratios[i][j]/(2*pyramid[j])) * baseline[j];
				//expected[j] = mortality[j] * ratios[i][j] / (FIXED * FACTOR);
			}

			printf("\texpected : %lu %lu %lu\n", expected[0], expected[1],
					expected[2]);
			printf("\tobserved : %lu %lu %lu\n", observed[i][0], observed[i][1],
					observed[i][2]);

			printf("\ttotal expected: %lu\n",
					expected[0] + expected[1] + expected[2]);
			printf("\ttotal observed: %lu\n",
					observed[i][0] + observed[i][1] + observed[i][2]);

			total += (expected[0] + expected[1] + expected[2]);
			excess += (observed[i][0] + observed[i][1] + observed[i][2]);
		}

		util_banner("Plaintext computation:", 1);

		printf("Baseline : %6lu %6lu %6lu\n", baseline[0] / 2, baseline[1] / 2,
				baseline[2] / 2);
		printf("Demograph: %6lu %6lu %6lu\n", pyramid[0] / FACTOR,
				pyramid[1] / FACTOR, pyramid[2] / FACTOR);
		printf("Mortality: %6lu %6lu %6lu\n", mortality[0] / FIXED,
				mortality[1] / FIXED, mortality[2] / FIXED);
		printf("Total Expected: %6lu\n", total / FIXED);
		printf("Total Observed: %6lu\n", excess);

		util_banner("Authenticated computation:", 1);

		bn_zero(res);
		g1_set_infty(p1);
		for (int i = 0; i < STATES; i++) {
			flen[i] = 2 * GROUPS * DAYS;
			for (int j = 0; j < GROUPS; j++) {
				total = 0;
				for (int k = 0; k < STATES; k++) {
					total += FIXED * ratios[k][j] / (2 * pyramid[j]);
				}
				for (int k = 0; k < DAYS; k++) {
					f[i][j * DAYS + k] = f[i][j * DAYS + GROUPS * DAYS + k] =
							total;
				}
			}
			cp_mklhs_fun(t[i], m[i], f[i], 2 * GROUPS * DAYS);
			bn_add(res, res, t[i]);
		}

		cp_smklhs_evl(sig, y1, ps1, ls1, rs1, y2, ps2, ls2, rs2,
				(const g1_t **)sigs, t, u, (const dig_t **)f,
				(const size_t *)flen, pk1, pk2, pk3, STATES);

		assert(cp_smklhs_ver(sig, res, y1, ps1, ls1, rs1, y2, ps2, ls2,
				rs2, u, DATABASE, acs, (const char **)l[0], (const dig_t **)f,
				(const size_t *)flen, pk1, pk2, pk3, t2, p2, STATES));

		printf("Total Expected: %6lu\n", res->dp[0] / FIXED);

		BENCH_ONE("Time elapsed", cp_smklhs_ver(sig, res, y1, ps1, ls1, rs1, y2,
			ps2, ls2, rs2, u, DATABASE, acs, (const char **)l[0],
			(const dig_t **)f, (const size_t *)flen, pk1, pk2, pk3, t2, p2,
			STATES), 1);

		bn_zero(res);
		for (int i = 0; i < STATES; i++) {
			flen[i] = GROUPS * DAYS;
			for (int j = 0; j < GROUPS; j++) {
				for (int k = 0; k < DAYS; k++) {
					f[i][j * DAYS + k] = 1;
				}
			}
			cp_mklhs_fun(t[i], &m[i][2 * GROUPS * DAYS], f[i], GROUPS * DAYS);
			bn_add(res, res, t[i]);
		}

		cp_smklhs_evl(sig, y1, ps1, ls1, rs1, y2, ps2, ls2, rs2,
				(const g1_t **)sigs, t, u, (const dig_t **)f,
				(const size_t *)flen, pk1, pk2, pk3, STATES);

		assert(cp_smklhs_ver(sig, res, y1, ps1, ls1, rs1, y2, ps2, ls2,
			rs2, u, DATABASE, acs, (const char **)&l[0][2 * GROUPS * DAYS],
			(const dig_t **)f, (const size_t *)flen, pk1, pk2, pk3, t2, p2,
			STATES));

		printf("Total Observed: %6lu\n", res->dp[0]);
		
		BENCH_ONE("Time elapsed", cp_smklhs_ver(sig, res, y1, ps1, ls1, rs1, y2,
			ps2, ls2, rs2, u, DATABASE, acs, 
			(const char **)&l[0][2 * GROUPS * DAYS], (const dig_t **)f,
			(const size_t *)flen, pk1, pk2, pk3, t2, p2, STATES), 1);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(res);
		bn_free(y1);
		bn_free(y2);	
		g1_free(u);
		g1_free(sig);
		g1_free(t1);
		g1_free(p1);
		g2_free(t2);
		g2_free(p2);
		for (int i = 0; i < STATES; i++) {
			RLC_FREE(f[i]);
			bn_free(t[i]);
			bn_free(sk1[i]);
			bn_free(sk2[i]);
			g1_free(cs[i]);
			g1_free(pk1[i]);
			g2_free(pk2[i]);
			g1_free(pk3[i]);
			for (int j = 0; j < GROUPS; j++) {
				for (int k = 0; k < 3 * DAYS; k++) {
					bn_free(m[i][j * 3 * DAYS + k]);
					g1_free(sigs[i][j * 3 * DAYS + k]);
					free(l[i][j * 3 * DAYS + k]);
				}
			}
		}
	}

	core_clean();
	return 0;
}
