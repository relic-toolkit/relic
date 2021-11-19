#!/bin/sh
CFLAGS="-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native" cmake -DWSIZE=64 -DRAND=UDEV -DSHLIB=OFF -DSTBIN=ON -DTIMER=CYCLE -DCHECK=off -DVERBS=off -DARITH=x64-asm-4l -DFP_PRIME=254 -DFP_METHD="INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE" -DFP_PMERS=off -DFP_QNRES=on -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" $1
