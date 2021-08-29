#!/bin/sh 
CFLAGS="-O2 -funroll-loops -fomit-frame-pointer" cmake -DCHECK=off -DARITH=gmp -DFP_PRIME=255 -DFP_QNRES=off -DEC_METHD="PRIME" -DEC_ENDOM=on -DFP_METHD="INTEG;COMBA;COMBA;MONTY;MONTY;SLIDE" $1
