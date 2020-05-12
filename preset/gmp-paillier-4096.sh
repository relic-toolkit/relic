#!/bin/bash 
cmake -DCHECK=off -DARITH=gmp -DBN_PRECI=4096 -DALLOC=DYNAMIC -DCOMP="-O3 -march=native -mtune=native -fomit-frame-pointer" -DWITH="DV;BN;MD;CP" -DSHLIB=off $1
