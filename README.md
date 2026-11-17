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

 * [Multiple-precision integer arithmetic](src/bn)
 * Arithmetic in [prime](src/fp) and [binary](src/fb) fields and their extensions ([prime](src/fpx), [binary](src/fbx))
 * Elliptic curves over [prime](src/ep) and [binary](src/eb) fields, including NIST, SECG and pairing-friendly curves (BN, BLS12, BLS24, BLS48, KSS), and [Edwards curves](src/ed)
 * [Pairings](src/pp) for embedding degrees from 1 to 54, with an [interface for pairing-based protocols](src/pc)
 * [Hash functions](src/md), the [AES block cipher](src/bc) and [random number generators](src/rand)
 * [Secret sharing and triples for multi-party computation](src/mpc)
 * [Cryptographic protocols](src/cp):
   * Encryption: [RSA](src/cp/relic_cp_rsa.c), [ECIES](src/cp/relic_cp_ecies.c), [Boneh-Franklin IBE](src/cp/relic_cp_ibe.c), and homomorphic encryption by [Paillier](src/cp/relic_cp_phpe.c), [Damgård-Jurik](src/cp/relic_cp_ghpe.c) and [Boneh-Goh-Nissim](src/cp/relic_cp_bgn.c)
   * Signatures: [RSA](src/cp/relic_cp_rsa.c), [ECDSA](src/cp/relic_cp_ecdsa.c), [Schnorr](src/cp/relic_cp_ecss.c), [BLS](src/cp/relic_cp_bls.c), [Camenisch-Lysyanskaya](src/cp/relic_cp_cls.c), [Pointcheval-Sanders](src/cp/relic_cp_pss.c), [linearly homomorphic](src/cp/relic_cp_mklhs.c) and [threshold ring](src/cp/relic_cp_etrs.c) signatures
   * Key agreement: [ECDH](src/cp/relic_cp_ecdh.c), [ECMQV](src/cp/relic_cp_ecmqv.c) and [Sakai-Ohgishi-Kasahara](src/cp/relic_cp_sokaka.c)
   * Others: [zero-knowledge proofs](src/cp/relic_cp_pok.c), [private set intersection](src/cp/relic_cp_pbpsi.c), an [oblivious pseudorandom function](src/cp/relic_cp_oprf.c) and [pairing delegation](src/cp/relic_cp_pcdel.c)

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).

To reduce code size, configure with `-DSTRIP=on`. This compiles the library with `-ffunction-sections -fdata-sections` and drops precomputed tables of algorithms that were not selected. Unused functions are then removed at link time, which only happens for static linking: applications linking against `librelic_s.a` must pass `-Wl,--gc-sections` (or `-Wl,-dead_strip` on macOS, `/OPT:REF` with MSVC) to their own linker. The shared library is not reduced.

### Support

You can probably get some help over the official mailing list at `relic-discuss@googlegroups.com`

If you like the library, please consider supporting development through [Paypal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=R7D6ZE3BLMTF2&lc=BR&item_name=RELIC%20Development&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted).
If you use our work in your research, please cite as
```
@misc{relic-toolkit,
    author = {D. F. Aranha and C. P. L. Gouvêa and T. Markmann and R. S. Wahby and K. Liao},
    title = {{RELIC is an Efficient LIbrary for Cryptography}},
    howpublished = {\url{https://github.com/relic-toolkit/relic}},
}
```

### Licensing

This work is dual-licensed under Apache 2.0 and LGPL 2.1-or-above to encourage collaboration with other research groups and contributions from the industry. You can choose between one of them if you use this work.

`SPDX-License-Identifier: Apache-2.0 OR LGPL-2.1`

Starting from version 0.3.3, static linking and changes in the configuration or build system are explicitly exempted from representing derived works. Please refer to the LICENSE files for additional details.

### Disclaimer

RELIC is at best alpha-quality software. Implementations may not be correct or secure and may include patented algorithms. There are *many* configuration options which make the library horribly insecure. Backward API compatibility with early versions may not necessarily be maintained. Side-channel and fault injection attacks are not considered in particular, unless it is explicitly noted. Use at your own risk.
