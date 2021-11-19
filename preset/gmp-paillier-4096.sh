#!/bin/sh 
CFLAGS="-O3 -march=native -mtune=native -fomit-frame-pointer" cmake -DCHECK=off -DARITH=gmp -DBN_PRECI=4096 -DALLOC=DYNAMIC -DWITH="DV;BN;MD;CP" -DSHLIB=off $1
