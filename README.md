![](https://github.com/relic-toolkit/relic/blob/c56f2cc3529da824e76974ccb5d74cb4ff6cdec7/art/rlc_logo.png)
=====

[![Project stats](https://www.openhub.net/p/relic-toolkit/widgets/project_thin_badge.gif)](https://www.openhub.net/p/relic-toolkit)
[![GHA Status](https://github.com/relic-toolkit/relic/actions/workflows/easy.yml/badge.svg)](https://github.com/relic-toolkit/relic/actions/workflows/easy.yml)
[![GHA Status](https://github.com/relic-toolkit/relic/actions/workflows/gmp.yml/badge.svg)](https://github.com/relic-toolkit/relic/actions/workflows/gmp.yml)
[![GHA Status](https://github.com/relic-toolkit/relic/actions/workflows/bls12-381.yml/badge.svg)](https://github.com/relic-toolkit/relic/actions/workflows/bls12-381.yml)


RELIC is a modern research-oriented cryptographic meta-toolkit with emphasis on efficiency and flexibility. RELIC can be used to build efficient and usable cryptographic toolkits tailored for specific security levels and algorithmic choices.

### Goals

RELIC is an ongoing project and features will be added on demand. The focus is to provide:

 * Ease of portability and inclusion of architecture-dependent code
 * Simple experimentation with alternative implementations
 * Tests and benchmarks for every implemented function
 * Flexible configuration
 * Maximum efficiency

### Algorithms

RELIC implements to date:

 * Multiple-precision integer arithmetic
 * Prime and Binary field arithmetic
 * Elliptic curves over prime and binary fields (NIST curves and pairing-friendly curves)
 * Bilinear maps and related extension fields
 * Cryptographic protocols (RSA, Rabin, ECDSA, ECMQV, ECSS (Schnorr), ECIES, Sakai-Ohgishi-Kasahara ID-based authenticated key agreement, Boneh-Lynn-Schacham and Boneh-Boyen short signatures, Paillier and Benaloh homomorphic encryption systems)
 * [**Pairing delegation protocols**](https://anonymous.4open.science/r/relic-32F2/src/cp/relic_cp_pcdel.c) with public and private inputs
 * [**Batch pairing delegation protocols**](https://anonymous.4open.science/r/relic-32F2/src/cp/relic_cp_pdbat.c) with public inputs

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).

For the pairing delegation protocols, look for the corresponding entries in the output of the `test_cp` testing binary, and entries with prefix `cp_amore_* (1)` (for the sequential version), `cp_amore_* (AGGS)` (for the batch version) in the output of the `bench_cp` benchmarking binary. You can change the parameter `AGGS` in the source code to adjust the number of pairings.

### Support

You can probably get some help over the official mailing list at `relic-discuss@googlegroups.com`

If you like the library, please consider supporting development through [Paypal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=R7D6ZE3BLMTF2&lc=BR&item_name=RELIC%20Development&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted).

### Licensing

This work is dual-licensed under Apache 2.0 and LGPL 2.1-or-above to encourage collaboration with other research groups and contributions from the industry. You can choose between one of them if you use this work.

`SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1`

Starting from version 0.3.3, static linking and changes in the configuration or build system are explicitly exempted from representing derived works. Please refer to the LICENSE files for additional details.

### Disclaimer

RELIC is at best alpha-quality software. Implementations may not be correct or secure and may include patented algorithms. There are *many* configuration options which make the library horribly insecure. Backward API compatibility with early versions may not necessarily be maintained. Side-channel and fault injection attacks are not considered in particular, unless it is explicitly noted. Use at your own risk.
