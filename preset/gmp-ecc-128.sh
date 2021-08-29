#!/bin/sh 
CFLAGS="-O3 -funroll-loops -fomit-frame-pointer -march=native -mtune=native" cmake -DCHECK=off -DARITH=gmp -DFP_PRIME=255 -DFP_QNRES=off -DEC_METHD="EDDIE" -DFP_METHD="INTEG;COMBA;COMBA;MONTY;MONTY;SLIDE" $1
