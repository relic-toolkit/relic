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
 * Implementation of the low-level prime field modular reduction functions.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#include "bls12_381_q_64.c"

/*
 * The function fiat_bls12_381_q_lazyred multiplies two field elements in the Montgomery domain.
 * Postconditions:
 *   0 ≤ eval arg1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: None
 */
void fiat_bls12_381_q_lazyred(uint64_t out1[6], uint64_t arg1[12]) {
  uint64_t x1;
  uint64_t x2;
  uint64_t x3;
  uint64_t x4;
  uint64_t x5;
  uint64_t x6;
  uint64_t x7;
  uint64_t x8;
  uint64_t x9;
  uint64_t x10;
  uint64_t x11;
  uint64_t x12;
  uint64_t x13;
  uint64_t x14;
  uint64_t x15;
  uint64_t x16;
  fiat_bls12_381_q_uint1 x17;
  uint64_t x18;
  fiat_bls12_381_q_uint1 x19;
  uint64_t x20;
  fiat_bls12_381_q_uint1 x21;
  uint64_t x22;
  fiat_bls12_381_q_uint1 x23;
  uint64_t x24;
  fiat_bls12_381_q_uint1 x25;
  uint64_t x26;
  uint64_t x27;
  fiat_bls12_381_q_uint1 x28;
  uint64_t x29;
  fiat_bls12_381_q_uint1 x30;
  uint64_t x31;
  fiat_bls12_381_q_uint1 x32;
  uint64_t x33;
  fiat_bls12_381_q_uint1 x34;
  uint64_t x35;
  fiat_bls12_381_q_uint1 x36;
  uint64_t x37;
  fiat_bls12_381_q_uint1 x38;
  uint64_t x39;
  fiat_bls12_381_q_uint1 x40;
  uint64_t x41;
  fiat_bls12_381_q_uint1 x42;
  uint64_t x43;
  fiat_bls12_381_q_uint1 x44;
  uint64_t x45;
  fiat_bls12_381_q_uint1 x46;
  uint64_t x47;
  fiat_bls12_381_q_uint1 x48;
  uint64_t x49;
  fiat_bls12_381_q_uint1 x50;
  uint64_t x51;
  uint64_t x52;
  uint64_t x53;
  uint64_t x54;
  uint64_t x55;
  uint64_t x56;
  uint64_t x57;
  uint64_t x58;
  uint64_t x59;
  uint64_t x60;
  uint64_t x61;
  uint64_t x62;
  uint64_t x63;
  uint64_t x64;
  uint64_t x65;
  fiat_bls12_381_q_uint1 x66;
  uint64_t x67;
  fiat_bls12_381_q_uint1 x68;
  uint64_t x69;
  fiat_bls12_381_q_uint1 x70;
  uint64_t x71;
  fiat_bls12_381_q_uint1 x72;
  uint64_t x73;
  fiat_bls12_381_q_uint1 x74;
  uint64_t x75;
  uint64_t x76;
  fiat_bls12_381_q_uint1 x77;
  uint64_t x78;
  fiat_bls12_381_q_uint1 x79;
  uint64_t x80;
  fiat_bls12_381_q_uint1 x81;
  uint64_t x82;
  fiat_bls12_381_q_uint1 x83;
  uint64_t x84;
  fiat_bls12_381_q_uint1 x85;
  uint64_t x86;
  fiat_bls12_381_q_uint1 x87;
  uint64_t x88;
  fiat_bls12_381_q_uint1 x89;
  uint64_t x90;
  fiat_bls12_381_q_uint1 x91;
  uint64_t x92;
  fiat_bls12_381_q_uint1 x93;
  uint64_t x94;
  fiat_bls12_381_q_uint1 x95;
  uint64_t x96;
  fiat_bls12_381_q_uint1 x97;
  uint64_t x98;
  uint64_t x99;
  uint64_t x100;
  uint64_t x101;
  uint64_t x102;
  uint64_t x103;
  uint64_t x104;
  uint64_t x105;
  uint64_t x106;
  uint64_t x107;
  uint64_t x108;
  uint64_t x109;
  uint64_t x110;
  uint64_t x111;
  uint64_t x112;
  uint64_t x113;
  fiat_bls12_381_q_uint1 x114;
  uint64_t x115;
  fiat_bls12_381_q_uint1 x116;
  uint64_t x117;
  fiat_bls12_381_q_uint1 x118;
  uint64_t x119;
  fiat_bls12_381_q_uint1 x120;
  uint64_t x121;
  fiat_bls12_381_q_uint1 x122;
  uint64_t x123;
  uint64_t x124;
  fiat_bls12_381_q_uint1 x125;
  uint64_t x126;
  fiat_bls12_381_q_uint1 x127;
  uint64_t x128;
  fiat_bls12_381_q_uint1 x129;
  uint64_t x130;
  fiat_bls12_381_q_uint1 x131;
  uint64_t x132;
  fiat_bls12_381_q_uint1 x133;
  uint64_t x134;
  fiat_bls12_381_q_uint1 x135;
  uint64_t x136;
  fiat_bls12_381_q_uint1 x137;
  uint64_t x138;
  fiat_bls12_381_q_uint1 x139;
  uint64_t x140;
  fiat_bls12_381_q_uint1 x141;
  uint64_t x142;
  fiat_bls12_381_q_uint1 x143;
  uint64_t x144;
  uint64_t x145;
  uint64_t x146;
  uint64_t x147;
  uint64_t x148;
  uint64_t x149;
  uint64_t x150;
  uint64_t x151;
  uint64_t x152;
  uint64_t x153;
  uint64_t x154;
  uint64_t x155;
  uint64_t x156;
  uint64_t x157;
  uint64_t x158;
  uint64_t x159;
  fiat_bls12_381_q_uint1 x160;
  uint64_t x161;
  fiat_bls12_381_q_uint1 x162;
  uint64_t x163;
  fiat_bls12_381_q_uint1 x164;
  uint64_t x165;
  fiat_bls12_381_q_uint1 x166;
  uint64_t x167;
  fiat_bls12_381_q_uint1 x168;
  uint64_t x169;
  uint64_t x170;
  fiat_bls12_381_q_uint1 x171;
  uint64_t x172;
  fiat_bls12_381_q_uint1 x173;
  uint64_t x174;
  fiat_bls12_381_q_uint1 x175;
  uint64_t x176;
  fiat_bls12_381_q_uint1 x177;
  uint64_t x178;
  fiat_bls12_381_q_uint1 x179;
  uint64_t x180;
  fiat_bls12_381_q_uint1 x181;
  uint64_t x182;
  fiat_bls12_381_q_uint1 x183;
  uint64_t x184;
  fiat_bls12_381_q_uint1 x185;
  uint64_t x186;
  fiat_bls12_381_q_uint1 x187;
  uint64_t x188;
  uint64_t x189;
  uint64_t x190;
  uint64_t x191;
  uint64_t x192;
  uint64_t x193;
  uint64_t x194;
  uint64_t x195;
  uint64_t x196;
  uint64_t x197;
  uint64_t x198;
  uint64_t x199;
  uint64_t x200;
  uint64_t x201;
  uint64_t x202;
  uint64_t x203;
  fiat_bls12_381_q_uint1 x204;
  uint64_t x205;
  fiat_bls12_381_q_uint1 x206;
  uint64_t x207;
  fiat_bls12_381_q_uint1 x208;
  uint64_t x209;
  fiat_bls12_381_q_uint1 x210;
  uint64_t x211;
  fiat_bls12_381_q_uint1 x212;
  uint64_t x213;
  uint64_t x214;
  fiat_bls12_381_q_uint1 x215;
  uint64_t x216;
  fiat_bls12_381_q_uint1 x217;
  uint64_t x218;
  fiat_bls12_381_q_uint1 x219;
  uint64_t x220;
  fiat_bls12_381_q_uint1 x221;
  uint64_t x222;
  fiat_bls12_381_q_uint1 x223;
  uint64_t x224;
  fiat_bls12_381_q_uint1 x225;
  uint64_t x226;
  fiat_bls12_381_q_uint1 x227;
  uint64_t x228;
  fiat_bls12_381_q_uint1 x229;
  uint64_t x230;
  uint64_t x231;
  uint64_t x232;
  uint64_t x233;
  uint64_t x234;
  uint64_t x235;
  uint64_t x236;
  uint64_t x237;
  uint64_t x238;
  uint64_t x239;
  uint64_t x240;
  uint64_t x241;
  uint64_t x242;
  uint64_t x243;
  uint64_t x244;
  uint64_t x245;
  fiat_bls12_381_q_uint1 x246;
  uint64_t x247;
  fiat_bls12_381_q_uint1 x248;
  uint64_t x249;
  fiat_bls12_381_q_uint1 x250;
  uint64_t x251;
  fiat_bls12_381_q_uint1 x252;
  uint64_t x253;
  fiat_bls12_381_q_uint1 x254;
  uint64_t x255;
  uint64_t x256;
  fiat_bls12_381_q_uint1 x257;
  uint64_t x258;
  fiat_bls12_381_q_uint1 x259;
  uint64_t x260;
  fiat_bls12_381_q_uint1 x261;
  uint64_t x262;
  fiat_bls12_381_q_uint1 x263;
  uint64_t x264;
  fiat_bls12_381_q_uint1 x265;
  uint64_t x266;
  fiat_bls12_381_q_uint1 x267;
  uint64_t x268;
  fiat_bls12_381_q_uint1 x269;
  uint64_t x270;
  uint64_t x271;
  fiat_bls12_381_q_uint1 x272;
  uint64_t x273;
  fiat_bls12_381_q_uint1 x274;
  uint64_t x275;
  fiat_bls12_381_q_uint1 x276;
  uint64_t x277;
  fiat_bls12_381_q_uint1 x278;
  uint64_t x279;
  fiat_bls12_381_q_uint1 x280;
  uint64_t x281;
  fiat_bls12_381_q_uint1 x282;
  uint64_t x283;
  fiat_bls12_381_q_uint1 x284;
  uint64_t x285;
  uint64_t x286;
  uint64_t x287;
  uint64_t x288;
  uint64_t x289;
  uint64_t x290;
  x1 = (arg1[0]);
  fiat_bls12_381_q_mulx_u64(&x2, &x3, x1, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x4, &x5, x2, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x6, &x7, x2, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x8, &x9, x2, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x10, &x11, x2, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x12, &x13, x2, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x14, &x15, x2, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x16, &x17, 0x0, x15, x12);
  fiat_bls12_381_q_addcarryx_u64(&x18, &x19, x17, x13, x10);
  fiat_bls12_381_q_addcarryx_u64(&x20, &x21, x19, x11, x8);
  fiat_bls12_381_q_addcarryx_u64(&x22, &x23, x21, x9, x6);
  fiat_bls12_381_q_addcarryx_u64(&x24, &x25, x23, x7, x4);
  x26 = (x25 + x5);
  fiat_bls12_381_q_addcarryx_u64(&x27, &x28, 0x0, (arg1[0]), x14);
  fiat_bls12_381_q_addcarryx_u64(&x29, &x30, x28, (arg1[1]), x16);
  fiat_bls12_381_q_addcarryx_u64(&x31, &x32, x30, (arg1[2]), x18);
  fiat_bls12_381_q_addcarryx_u64(&x33, &x34, x32, (arg1[3]), x20);
  fiat_bls12_381_q_addcarryx_u64(&x35, &x36, x34, (arg1[4]), x22);
  fiat_bls12_381_q_addcarryx_u64(&x37, &x38, x36, (arg1[5]), x24);
  fiat_bls12_381_q_addcarryx_u64(&x39, &x40, x38, (arg1[6]), x26);
  fiat_bls12_381_q_addcarryx_u64(&x41, &x42, x40, (arg1[7]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x43, &x44, x42, (arg1[8]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x45, &x46, x44, (arg1[9]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x47, &x48, x46, (arg1[10]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x49, &x50, x48, (arg1[11]), 0x0);
  fiat_bls12_381_q_mulx_u64(&x51, &x52, x29, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x53, &x54, x51, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x55, &x56, x51, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x57, &x58, x51, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x59, &x60, x51, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x61, &x62, x51, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x63, &x64, x51, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x65, &x66, 0x0, x64, x61);
  fiat_bls12_381_q_addcarryx_u64(&x67, &x68, x66, x62, x59);
  fiat_bls12_381_q_addcarryx_u64(&x69, &x70, x68, x60, x57);
  fiat_bls12_381_q_addcarryx_u64(&x71, &x72, x70, x58, x55);
  fiat_bls12_381_q_addcarryx_u64(&x73, &x74, x72, x56, x53);
  x75 = (x74 + x54);
  fiat_bls12_381_q_addcarryx_u64(&x76, &x77, 0x0, x29, x63);
  fiat_bls12_381_q_addcarryx_u64(&x78, &x79, x77, x31, x65);
  fiat_bls12_381_q_addcarryx_u64(&x80, &x81, x79, x33, x67);
  fiat_bls12_381_q_addcarryx_u64(&x82, &x83, x81, x35, x69);
  fiat_bls12_381_q_addcarryx_u64(&x84, &x85, x83, x37, x71);
  fiat_bls12_381_q_addcarryx_u64(&x86, &x87, x85, x39, x73);
  fiat_bls12_381_q_addcarryx_u64(&x88, &x89, x87, x41, x75);
  fiat_bls12_381_q_addcarryx_u64(&x90, &x91, x89, x43, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x92, &x93, x91, x45, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x94, &x95, x93, x47, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x96, &x97, x95, x49, 0x0);
  x98 = ((uint64_t)x97 + x50);
  fiat_bls12_381_q_mulx_u64(&x99, &x100, x78, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x101, &x102, x99, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x103, &x104, x99, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x105, &x106, x99, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x107, &x108, x99, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x109, &x110, x99, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x111, &x112, x99, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x113, &x114, 0x0, x112, x109);
  fiat_bls12_381_q_addcarryx_u64(&x115, &x116, x114, x110, x107);
  fiat_bls12_381_q_addcarryx_u64(&x117, &x118, x116, x108, x105);
  fiat_bls12_381_q_addcarryx_u64(&x119, &x120, x118, x106, x103);
  fiat_bls12_381_q_addcarryx_u64(&x121, &x122, x120, x104, x101);
  x123 = (x122 + x102);
  fiat_bls12_381_q_addcarryx_u64(&x124, &x125, 0x0, x78, x111);
  fiat_bls12_381_q_addcarryx_u64(&x126, &x127, x125, x80, x113);
  fiat_bls12_381_q_addcarryx_u64(&x128, &x129, x127, x82, x115);
  fiat_bls12_381_q_addcarryx_u64(&x130, &x131, x129, x84, x117);
  fiat_bls12_381_q_addcarryx_u64(&x132, &x133, x131, x86, x119);
  fiat_bls12_381_q_addcarryx_u64(&x134, &x135, x133, x88, x121);
  fiat_bls12_381_q_addcarryx_u64(&x136, &x137, x135, x90, x123);
  fiat_bls12_381_q_addcarryx_u64(&x138, &x139, x137, x92, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x140, &x141, x139, x94, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x142, &x143, x141, x96, 0x0);
  x144 = (x143 + x98);
  fiat_bls12_381_q_mulx_u64(&x145, &x146, x126, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x147, &x148, x145, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x149, &x150, x145, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x151, &x152, x145, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x153, &x154, x145, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x155, &x156, x145, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x157, &x158, x145, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x159, &x160, 0x0, x158, x155);
  fiat_bls12_381_q_addcarryx_u64(&x161, &x162, x160, x156, x153);
  fiat_bls12_381_q_addcarryx_u64(&x163, &x164, x162, x154, x151);
  fiat_bls12_381_q_addcarryx_u64(&x165, &x166, x164, x152, x149);
  fiat_bls12_381_q_addcarryx_u64(&x167, &x168, x166, x150, x147);
  x169 = (x168 + x148);
  fiat_bls12_381_q_addcarryx_u64(&x170, &x171, 0x0, x126, x157);
  fiat_bls12_381_q_addcarryx_u64(&x172, &x173, x171, x128, x159);
  fiat_bls12_381_q_addcarryx_u64(&x174, &x175, x173, x130, x161);
  fiat_bls12_381_q_addcarryx_u64(&x176, &x177, x175, x132, x163);
  fiat_bls12_381_q_addcarryx_u64(&x178, &x179, x177, x134, x165);
  fiat_bls12_381_q_addcarryx_u64(&x180, &x181, x179, x136, x167);
  fiat_bls12_381_q_addcarryx_u64(&x182, &x183, x181, x138, x169);
  fiat_bls12_381_q_addcarryx_u64(&x184, &x185, x183, x140, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x186, &x187, x185, x142, 0x0);
  x188 = (x187 + x144);
  fiat_bls12_381_q_mulx_u64(&x189, &x190, x172, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x191, &x192, x189, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x193, &x194, x189, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x195, &x196, x189, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x197, &x198, x189, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x199, &x200, x189, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x201, &x202, x189, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x203, &x204, 0x0, x202, x199);
  fiat_bls12_381_q_addcarryx_u64(&x205, &x206, x204, x200, x197);
  fiat_bls12_381_q_addcarryx_u64(&x207, &x208, x206, x198, x195);
  fiat_bls12_381_q_addcarryx_u64(&x209, &x210, x208, x196, x193);
  fiat_bls12_381_q_addcarryx_u64(&x211, &x212, x210, x194, x191);
  x213 = (x212 + x192);
  fiat_bls12_381_q_addcarryx_u64(&x214, &x215, 0x0, x172, x201);
  fiat_bls12_381_q_addcarryx_u64(&x216, &x217, x215, x174, x203);
  fiat_bls12_381_q_addcarryx_u64(&x218, &x219, x217, x176, x205);
  fiat_bls12_381_q_addcarryx_u64(&x220, &x221, x219, x178, x207);
  fiat_bls12_381_q_addcarryx_u64(&x222, &x223, x221, x180, x209);
  fiat_bls12_381_q_addcarryx_u64(&x224, &x225, x223, x182, x211);
  fiat_bls12_381_q_addcarryx_u64(&x226, &x227, x225, x184, x213);
  fiat_bls12_381_q_addcarryx_u64(&x228, &x229, x227, x186, 0x0);
  x230 = (x229 + x188);
  fiat_bls12_381_q_mulx_u64(&x231, &x232, x216, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x233, &x234, x231, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x235, &x236, x231, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x237, &x238, x231, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x239, &x240, x231, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x241, &x242, x231, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x243, &x244, x231, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x245, &x246, 0x0, x244, x241);
  fiat_bls12_381_q_addcarryx_u64(&x247, &x248, x246, x242, x239);
  fiat_bls12_381_q_addcarryx_u64(&x249, &x250, x248, x240, x237);
  fiat_bls12_381_q_addcarryx_u64(&x251, &x252, x250, x238, x235);
  fiat_bls12_381_q_addcarryx_u64(&x253, &x254, x252, x236, x233);
  x255 = (x254 + x234);
  fiat_bls12_381_q_addcarryx_u64(&x256, &x257, 0x0, x216, x243);
  fiat_bls12_381_q_addcarryx_u64(&x258, &x259, x257, x218, x245);
  fiat_bls12_381_q_addcarryx_u64(&x260, &x261, x259, x220, x247);
  fiat_bls12_381_q_addcarryx_u64(&x262, &x263, x261, x222, x249);
  fiat_bls12_381_q_addcarryx_u64(&x264, &x265, x263, x224, x251);
  fiat_bls12_381_q_addcarryx_u64(&x266, &x267, x265, x226, x253);
  fiat_bls12_381_q_addcarryx_u64(&x268, &x269, x267, x228, x255);
  x270 = (x269 + x230);
  fiat_bls12_381_q_subborrowx_u64(&x271, &x272, 0x0, x258, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_subborrowx_u64(&x273, &x274, x272, x260, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_subborrowx_u64(&x275, &x276, x274, x262, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_subborrowx_u64(&x277, &x278, x276, x264, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_subborrowx_u64(&x279, &x280, x278, x266, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_subborrowx_u64(&x281, &x282, x280, x268, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_subborrowx_u64(&x283, &x284, x282, x270, 0x0);
  fiat_bls12_381_q_cmovznz_u64(&x285, x284, x271, x258);
  fiat_bls12_381_q_cmovznz_u64(&x286, x284, x273, x260);
  fiat_bls12_381_q_cmovznz_u64(&x287, x284, x275, x262);
  fiat_bls12_381_q_cmovznz_u64(&x288, x284, x277, x264);
  fiat_bls12_381_q_cmovznz_u64(&x289, x284, x279, x266);
  fiat_bls12_381_q_cmovznz_u64(&x290, x284, x281, x268);
  out1[0] = x285;
  out1[1] = x286;
  out1[2] = x287;
  out1[3] = x288;
  out1[4] = x289;
  out1[5] = x290;
}

/*
 * The function fiat_bls12_381_q_lazyredalt multiplies two field elements in the Montgomery domain.
 * Postconditions:
 *   0 ≤ eval arg1 < m
 *
 * Input Bounds:
 *   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
 * Output Bounds:
 *   out1: None
 */
static void fiat_bls12_381_q_lazyredalt(uint64_t out1[6], const uint64_t arg1[12]) {
  uint64_t x1;
  uint64_t x2;
  uint64_t x3;
  uint64_t x4;
  uint64_t x5;
  uint64_t x6;
  uint64_t x7;
  uint64_t x8;
  uint64_t x9;
  uint64_t x10;
  uint64_t x11;
  uint64_t x12;
  uint64_t x13;
  uint64_t x14;
  uint64_t x15;
  uint64_t x16;
  fiat_bls12_381_q_uint1 x17;
  uint64_t x18;
  fiat_bls12_381_q_uint1 x19;
  uint64_t x20;
  fiat_bls12_381_q_uint1 x21;
  uint64_t x22;
  fiat_bls12_381_q_uint1 x23;
  uint64_t x24;
  fiat_bls12_381_q_uint1 x25;
  uint64_t x26;
  uint64_t x27;
  fiat_bls12_381_q_uint1 x28;
  uint64_t x29;
  fiat_bls12_381_q_uint1 x30;
  uint64_t x31;
  fiat_bls12_381_q_uint1 x32;
  uint64_t x33;
  fiat_bls12_381_q_uint1 x34;
  uint64_t x35;
  fiat_bls12_381_q_uint1 x36;
  uint64_t x37;
  fiat_bls12_381_q_uint1 x38;
  uint64_t x39;
  fiat_bls12_381_q_uint1 x40;
  uint64_t x41;
  fiat_bls12_381_q_uint1 x42;
  uint64_t x43;
  fiat_bls12_381_q_uint1 x44;
  uint64_t x45;
  fiat_bls12_381_q_uint1 x46;
  uint64_t x47;
  fiat_bls12_381_q_uint1 x48;
  uint64_t x49;
  fiat_bls12_381_q_uint1 x50;
  uint64_t x51;
  uint64_t x52;
  uint64_t x53;
  uint64_t x54;
  uint64_t x55;
  uint64_t x56;
  uint64_t x57;
  uint64_t x58;
  uint64_t x59;
  uint64_t x60;
  uint64_t x61;
  uint64_t x62;
  uint64_t x63;
  uint64_t x64;
  uint64_t x65;
  fiat_bls12_381_q_uint1 x66;
  uint64_t x67;
  fiat_bls12_381_q_uint1 x68;
  uint64_t x69;
  fiat_bls12_381_q_uint1 x70;
  uint64_t x71;
  fiat_bls12_381_q_uint1 x72;
  uint64_t x73;
  fiat_bls12_381_q_uint1 x74;
  uint64_t x75;
  uint64_t x76;
  fiat_bls12_381_q_uint1 x77;
  uint64_t x78;
  fiat_bls12_381_q_uint1 x79;
  uint64_t x80;
  fiat_bls12_381_q_uint1 x81;
  uint64_t x82;
  fiat_bls12_381_q_uint1 x83;
  uint64_t x84;
  fiat_bls12_381_q_uint1 x85;
  uint64_t x86;
  fiat_bls12_381_q_uint1 x87;
  uint64_t x88;
  fiat_bls12_381_q_uint1 x89;
  uint64_t x90;
  fiat_bls12_381_q_uint1 x91;
  uint64_t x92;
  fiat_bls12_381_q_uint1 x93;
  uint64_t x94;
  fiat_bls12_381_q_uint1 x95;
  uint64_t x96;
  fiat_bls12_381_q_uint1 x97;
  uint64_t x98;
  uint64_t x99;
  uint64_t x100;
  uint64_t x101;
  uint64_t x102;
  uint64_t x103;
  uint64_t x104;
  uint64_t x105;
  uint64_t x106;
  uint64_t x107;
  uint64_t x108;
  uint64_t x109;
  uint64_t x110;
  uint64_t x111;
  uint64_t x112;
  fiat_bls12_381_q_uint1 x113;
  uint64_t x114;
  fiat_bls12_381_q_uint1 x115;
  uint64_t x116;
  fiat_bls12_381_q_uint1 x117;
  uint64_t x118;
  fiat_bls12_381_q_uint1 x119;
  uint64_t x120;
  fiat_bls12_381_q_uint1 x121;
  uint64_t x122;
  uint64_t x123;
  fiat_bls12_381_q_uint1 x124;
  uint64_t x125;
  fiat_bls12_381_q_uint1 x126;
  uint64_t x127;
  fiat_bls12_381_q_uint1 x128;
  uint64_t x129;
  fiat_bls12_381_q_uint1 x130;
  uint64_t x131;
  fiat_bls12_381_q_uint1 x132;
  uint64_t x133;
  fiat_bls12_381_q_uint1 x134;
  uint64_t x135;
  fiat_bls12_381_q_uint1 x136;
  uint64_t x137;
  fiat_bls12_381_q_uint1 x138;
  uint64_t x139;
  fiat_bls12_381_q_uint1 x140;
  uint64_t x141;
  fiat_bls12_381_q_uint1 x142;
  uint64_t x143;
  uint64_t x144;
  uint64_t x145;
  uint64_t x146;
  uint64_t x147;
  uint64_t x148;
  uint64_t x149;
  uint64_t x150;
  uint64_t x151;
  uint64_t x152;
  uint64_t x153;
  uint64_t x154;
  uint64_t x155;
  uint64_t x156;
  uint64_t x157;
  fiat_bls12_381_q_uint1 x158;
  uint64_t x159;
  fiat_bls12_381_q_uint1 x160;
  uint64_t x161;
  fiat_bls12_381_q_uint1 x162;
  uint64_t x163;
  fiat_bls12_381_q_uint1 x164;
  uint64_t x165;
  fiat_bls12_381_q_uint1 x166;
  uint64_t x167;
  uint64_t x168;
  fiat_bls12_381_q_uint1 x169;
  uint64_t x170;
  fiat_bls12_381_q_uint1 x171;
  uint64_t x172;
  fiat_bls12_381_q_uint1 x173;
  uint64_t x174;
  fiat_bls12_381_q_uint1 x175;
  uint64_t x176;
  fiat_bls12_381_q_uint1 x177;
  uint64_t x178;
  fiat_bls12_381_q_uint1 x179;
  uint64_t x180;
  fiat_bls12_381_q_uint1 x181;
  uint64_t x182;
  fiat_bls12_381_q_uint1 x183;
  uint64_t x184;
  fiat_bls12_381_q_uint1 x185;
  uint64_t x186;
  uint64_t x187;
  uint64_t x188;
  uint64_t x189;
  uint64_t x190;
  uint64_t x191;
  uint64_t x192;
  uint64_t x193;
  uint64_t x194;
  uint64_t x195;
  uint64_t x196;
  uint64_t x197;
  uint64_t x198;
  uint64_t x199;
  uint64_t x200;
  fiat_bls12_381_q_uint1 x201;
  uint64_t x202;
  fiat_bls12_381_q_uint1 x203;
  uint64_t x204;
  fiat_bls12_381_q_uint1 x205;
  uint64_t x206;
  fiat_bls12_381_q_uint1 x207;
  uint64_t x208;
  fiat_bls12_381_q_uint1 x209;
  uint64_t x210;
  uint64_t x211;
  fiat_bls12_381_q_uint1 x212;
  uint64_t x213;
  fiat_bls12_381_q_uint1 x214;
  uint64_t x215;
  fiat_bls12_381_q_uint1 x216;
  uint64_t x217;
  fiat_bls12_381_q_uint1 x218;
  uint64_t x219;
  fiat_bls12_381_q_uint1 x220;
  uint64_t x221;
  fiat_bls12_381_q_uint1 x222;
  uint64_t x223;
  fiat_bls12_381_q_uint1 x224;
  uint64_t x225;
  fiat_bls12_381_q_uint1 x226;
  uint64_t x227;
  uint64_t x228;
  uint64_t x229;
  uint64_t x230;
  uint64_t x231;
  uint64_t x232;
  uint64_t x233;
  uint64_t x234;
  uint64_t x235;
  uint64_t x236;
  uint64_t x237;
  uint64_t x238;
  uint64_t x239;
  uint64_t x240;
  uint64_t x241;
  fiat_bls12_381_q_uint1 x242;
  uint64_t x243;
  fiat_bls12_381_q_uint1 x244;
  uint64_t x245;
  fiat_bls12_381_q_uint1 x246;
  uint64_t x247;
  fiat_bls12_381_q_uint1 x248;
  uint64_t x249;
  fiat_bls12_381_q_uint1 x250;
  uint64_t x251;
  uint64_t x252;
  fiat_bls12_381_q_uint1 x253;
  uint64_t x254;
  fiat_bls12_381_q_uint1 x255;
  uint64_t x256;
  fiat_bls12_381_q_uint1 x257;
  uint64_t x258;
  fiat_bls12_381_q_uint1 x259;
  uint64_t x260;
  fiat_bls12_381_q_uint1 x261;
  uint64_t x262;
  fiat_bls12_381_q_uint1 x263;
  uint64_t x264;
  fiat_bls12_381_q_uint1 x265;
  x1 = (arg1[0]);
  fiat_bls12_381_q_mulx_u64(&x2, &x3, x1, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x4, &x5, x2, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x6, &x7, x2, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x8, &x9, x2, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x10, &x11, x2, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x12, &x13, x2, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x14, &x15, x2, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x16, &x17, 0x0, x15, x12);
  fiat_bls12_381_q_addcarryx_u64(&x18, &x19, x17, x13, x10);
  fiat_bls12_381_q_addcarryx_u64(&x20, &x21, x19, x11, x8);
  fiat_bls12_381_q_addcarryx_u64(&x22, &x23, x21, x9, x6);
  fiat_bls12_381_q_addcarryx_u64(&x24, &x25, x23, x7, x4);
  x26 = (x25 + x5);
  fiat_bls12_381_q_addcarryx_u64(&x27, &x28, 0x0, (arg1[0]), x14);
  fiat_bls12_381_q_addcarryx_u64(&x29, &x30, x28, (arg1[1]), x16);
  fiat_bls12_381_q_addcarryx_u64(&x31, &x32, x30, (arg1[2]), x18);
  fiat_bls12_381_q_addcarryx_u64(&x33, &x34, x32, (arg1[3]), x20);
  fiat_bls12_381_q_addcarryx_u64(&x35, &x36, x34, (arg1[4]), x22);
  fiat_bls12_381_q_addcarryx_u64(&x37, &x38, x36, (arg1[5]), x24);
  fiat_bls12_381_q_addcarryx_u64(&x39, &x40, x38, (arg1[6]), x26);
  fiat_bls12_381_q_addcarryx_u64(&x41, &x42, x40, (arg1[7]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x43, &x44, x42, (arg1[8]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x45, &x46, x44, (arg1[9]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x47, &x48, x46, (arg1[10]), 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x49, &x50, x48, (arg1[11]), 0x0);
  fiat_bls12_381_q_mulx_u64(&x51, &x52, x29, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x53, &x54, x51, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x55, &x56, x51, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x57, &x58, x51, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x59, &x60, x51, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x61, &x62, x51, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x63, &x64, x51, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x65, &x66, 0x0, x64, x61);
  fiat_bls12_381_q_addcarryx_u64(&x67, &x68, x66, x62, x59);
  fiat_bls12_381_q_addcarryx_u64(&x69, &x70, x68, x60, x57);
  fiat_bls12_381_q_addcarryx_u64(&x71, &x72, x70, x58, x55);
  fiat_bls12_381_q_addcarryx_u64(&x73, &x74, x72, x56, x53);
  x75 = (x74 + x54);
  fiat_bls12_381_q_addcarryx_u64(&x76, &x77, 0x0, x29, x63);
  fiat_bls12_381_q_addcarryx_u64(&x78, &x79, x77, x31, x65);
  fiat_bls12_381_q_addcarryx_u64(&x80, &x81, x79, x33, x67);
  fiat_bls12_381_q_addcarryx_u64(&x82, &x83, x81, x35, x69);
  fiat_bls12_381_q_addcarryx_u64(&x84, &x85, x83, x37, x71);
  fiat_bls12_381_q_addcarryx_u64(&x86, &x87, x85, x39, x73);
  fiat_bls12_381_q_addcarryx_u64(&x88, &x89, x87, x41, x75);
  fiat_bls12_381_q_addcarryx_u64(&x90, &x91, x89, x43, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x92, &x93, x91, x45, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x94, &x95, x93, x47, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x96, &x97, x95, x49, 0x0);
  fiat_bls12_381_q_mulx_u64(&x98, &x99, x78, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x100, &x101, x98, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x102, &x103, x98, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x104, &x105, x98, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x106, &x107, x98, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x108, &x109, x98, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x110, &x111, x98, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x112, &x113, 0x0, x111, x108);
  fiat_bls12_381_q_addcarryx_u64(&x114, &x115, x113, x109, x106);
  fiat_bls12_381_q_addcarryx_u64(&x116, &x117, x115, x107, x104);
  fiat_bls12_381_q_addcarryx_u64(&x118, &x119, x117, x105, x102);
  fiat_bls12_381_q_addcarryx_u64(&x120, &x121, x119, x103, x100);
  x122 = (x121 + x101);
  fiat_bls12_381_q_addcarryx_u64(&x123, &x124, 0x0, x78, x110);
  fiat_bls12_381_q_addcarryx_u64(&x125, &x126, x124, x80, x112);
  fiat_bls12_381_q_addcarryx_u64(&x127, &x128, x126, x82, x114);
  fiat_bls12_381_q_addcarryx_u64(&x129, &x130, x128, x84, x116);
  fiat_bls12_381_q_addcarryx_u64(&x131, &x132, x130, x86, x118);
  fiat_bls12_381_q_addcarryx_u64(&x133, &x134, x132, x88, x120);
  fiat_bls12_381_q_addcarryx_u64(&x135, &x136, x134, x90, x122);
  fiat_bls12_381_q_addcarryx_u64(&x137, &x138, x136, x92, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x139, &x140, x138, x94, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x141, &x142, x140, x96, 0x0);
  fiat_bls12_381_q_mulx_u64(&x143, &x144, x125, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x145, &x146, x143, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x147, &x148, x143, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x149, &x150, x143, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x151, &x152, x143, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x153, &x154, x143, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x155, &x156, x143, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x157, &x158, 0x0, x156, x153);
  fiat_bls12_381_q_addcarryx_u64(&x159, &x160, x158, x154, x151);
  fiat_bls12_381_q_addcarryx_u64(&x161, &x162, x160, x152, x149);
  fiat_bls12_381_q_addcarryx_u64(&x163, &x164, x162, x150, x147);
  fiat_bls12_381_q_addcarryx_u64(&x165, &x166, x164, x148, x145);
  x167 = (x166 + x146);
  fiat_bls12_381_q_addcarryx_u64(&x168, &x169, 0x0, x125, x155);
  fiat_bls12_381_q_addcarryx_u64(&x170, &x171, x169, x127, x157);
  fiat_bls12_381_q_addcarryx_u64(&x172, &x173, x171, x129, x159);
  fiat_bls12_381_q_addcarryx_u64(&x174, &x175, x173, x131, x161);
  fiat_bls12_381_q_addcarryx_u64(&x176, &x177, x175, x133, x163);
  fiat_bls12_381_q_addcarryx_u64(&x178, &x179, x177, x135, x165);
  fiat_bls12_381_q_addcarryx_u64(&x180, &x181, x179, x137, x167);
  fiat_bls12_381_q_addcarryx_u64(&x182, &x183, x181, x139, 0x0);
  fiat_bls12_381_q_addcarryx_u64(&x184, &x185, x183, x141, 0x0);
  fiat_bls12_381_q_mulx_u64(&x186, &x187, x170, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x188, &x189, x186, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x190, &x191, x186, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x192, &x193, x186, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x194, &x195, x186, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x196, &x197, x186, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x198, &x199, x186, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x200, &x201, 0x0, x199, x196);
  fiat_bls12_381_q_addcarryx_u64(&x202, &x203, x201, x197, x194);
  fiat_bls12_381_q_addcarryx_u64(&x204, &x205, x203, x195, x192);
  fiat_bls12_381_q_addcarryx_u64(&x206, &x207, x205, x193, x190);
  fiat_bls12_381_q_addcarryx_u64(&x208, &x209, x207, x191, x188);
  x210 = (x209 + x189);
  fiat_bls12_381_q_addcarryx_u64(&x211, &x212, 0x0, x170, x198);
  fiat_bls12_381_q_addcarryx_u64(&x213, &x214, x212, x172, x200);
  fiat_bls12_381_q_addcarryx_u64(&x215, &x216, x214, x174, x202);
  fiat_bls12_381_q_addcarryx_u64(&x217, &x218, x216, x176, x204);
  fiat_bls12_381_q_addcarryx_u64(&x219, &x220, x218, x178, x206);
  fiat_bls12_381_q_addcarryx_u64(&x221, &x222, x220, x180, x208);
  fiat_bls12_381_q_addcarryx_u64(&x223, &x224, x222, x182, x210);
  fiat_bls12_381_q_addcarryx_u64(&x225, &x226, x224, x184, 0x0);
  fiat_bls12_381_q_mulx_u64(&x227, &x228, x213, UINT64_C(0x89f3fffcfffcfffd));
  fiat_bls12_381_q_mulx_u64(&x229, &x230, x227, UINT64_C(0x1a0111ea397fe69a));
  fiat_bls12_381_q_mulx_u64(&x231, &x232, x227, UINT64_C(0x4b1ba7b6434bacd7));
  fiat_bls12_381_q_mulx_u64(&x233, &x234, x227, UINT64_C(0x64774b84f38512bf));
  fiat_bls12_381_q_mulx_u64(&x235, &x236, x227, UINT64_C(0x6730d2a0f6b0f624));
  fiat_bls12_381_q_mulx_u64(&x237, &x238, x227, UINT64_C(0x1eabfffeb153ffff));
  fiat_bls12_381_q_mulx_u64(&x239, &x240, x227, UINT64_C(0xb9feffffffffaaab));
  fiat_bls12_381_q_addcarryx_u64(&x241, &x242, 0x0, x240, x237);
  fiat_bls12_381_q_addcarryx_u64(&x243, &x244, x242, x238, x235);
  fiat_bls12_381_q_addcarryx_u64(&x245, &x246, x244, x236, x233);
  fiat_bls12_381_q_addcarryx_u64(&x247, &x248, x246, x234, x231);
  fiat_bls12_381_q_addcarryx_u64(&x249, &x250, x248, x232, x229);
  x251 = (x250 + x230);
  fiat_bls12_381_q_addcarryx_u64(&x252, &x253, 0x0, x213, x239);
  fiat_bls12_381_q_addcarryx_u64(&x254, &x255, x253, x215, x241);
  fiat_bls12_381_q_addcarryx_u64(&x256, &x257, x255, x217, x243);
  fiat_bls12_381_q_addcarryx_u64(&x258, &x259, x257, x219, x245);
  fiat_bls12_381_q_addcarryx_u64(&x260, &x261, x259, x221, x247);
  fiat_bls12_381_q_addcarryx_u64(&x262, &x263, x261, x223, x249);
  fiat_bls12_381_q_addcarryx_u64(&x264, &x265, x263, x225, x251);
  out1[0] = x254;
  out1[1] = x256;
  out1[2] = x258;
  out1[3] = x260;
  out1[4] = x262;
  out1[5] = x264;
}

void fp_rdcs_low(dig_t *c, const dig_t *a, const dig_t *m) {
	rlc_align dig_t q[2 * RLC_FP_DIGS], _q[2 * RLC_FP_DIGS], t[2 * RLC_FP_DIGS], r[RLC_FP_DIGS];
	const int *sform;
	int len, first, i, j, k, b0, d0, b1, d1;

	sform = fp_prime_get_sps(&len);

	RLC_RIP(b0, d0, sform[len - 1]);
	first = (d0) + (b0 == 0 ? 0 : 1);

	/* q = floor(a/b^k) */
	dv_zero(q, 2 * RLC_FP_DIGS);
	dv_rshd(q, a, 2 * RLC_FP_DIGS, d0);
	if (b0 > 0) {
		bn_rshb_low(q, q, 2 * RLC_FP_DIGS, b0);
	}

	/* r = a - qb^k. */
	dv_copy(r, a, first);
	if (b0 > 0) {
		r[first - 1] &= RLC_MASK(b0);
	}

	k = 0;
	while (!fp_is_zero(q)) {
		dv_zero(_q, 2 * RLC_FP_DIGS);
		for (i = len - 2; i > 0; i--) {
			j = (sform[i] < 0 ? -sform[i] : sform[i]);
			RLC_RIP(b1, d1, j);
			dv_zero(t, 2 * RLC_FP_DIGS);
			dv_lshd(t, q, RLC_FP_DIGS, d1);
			if (b1 > 0) {
				bn_lshb_low(t, t, 2 * RLC_FP_DIGS, b1);
			}
			/* Check if these two have the same sign. */
			if ((sform[len - 2] < 0) == (sform[i] < 0)) {
				bn_addn_low(_q, _q, t, 2 * RLC_FP_DIGS);
			} else {
				bn_subn_low(_q, _q, t, 2 * RLC_FP_DIGS);
			}
		}
		/* Check if these two have the same sign. */
		if ((sform[len - 2] < 0) == (sform[0] < 0)) {
			bn_addn_low(_q, _q, q, 2 * RLC_FP_DIGS);
		} else {
			bn_subn_low(_q, _q, q, 2 * RLC_FP_DIGS);
		}
		dv_rshd(q, _q, 2 * RLC_FP_DIGS, d0);
		if (b0 > 0) {
			bn_rshb_low(q, q, 2 * RLC_FP_DIGS, b0);
		}
		if (b0 > 0) {
			_q[first - 1] &= RLC_MASK(b0);
		}
		if (sform[len - 2] < 0) {
			fp_add(r, r, _q);
		} else {
			if (k++ % 2 == 0) {
				if (fp_subn_low(r, r, _q)) {
					fp_addn_low(r, r, m);
				}
			} else {
				fp_addn_low(r, r, _q);
			}
		}
	}
	while (dv_cmp(r, m, RLC_FP_DIGS) != RLC_LT) {
		fp_subn_low(r, r, m);
	}
	fp_copy(c, r);
}

void fp_rdcn_low(dig_t *c, dig_t *a) {
	fiat_bls12_381_q_lazyred(c, a);
	//fiat_bls12_381_q_lazyredalt(c, a);
}
