#!/bin/sh

CFLAGS="-O3 -funroll-loops -fomit-frame-pointer" cmake -DWITH="ALL" -DCHECK=off -DARITH=arm-asm-254 -DARCH=ARM -DCOLOR=off -DSEED= -DSHLIB=off -DFP_PRIME=254 -DFP_QNRES=on -DFP_METHD="INTEG;INTEG;INTEG;MONTY;EXGCD;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DTIMER=HREAL -DWSIZE=32 -DSTLIB=on $1
