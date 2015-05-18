#!/bin/bash 

export NDK=/opt/android-ndk
SYSROOT=$NDK/platforms/android-14/arch-arm

MIDDLE=toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/
PREF=arm-linux-androideabi-

export CC="$NDK/$MIDDLE/${PREF}gcc  --sysroot=$SYSROOT"
export CXX="$NDK/$MIDDLE/${PREF}g++  --sysroot=$SYSROOT"
export LD="$NDK/$MIDDLE/${PREF}ld  --sysroot=$SYSROOT"
export CPP="$NDK/$MIDDLE/${PREF}cpp  --sysroot=$SYSROOT"
export AS="$NDK/$MIDDLE/${PREF}as  --sysroot=$SYSROOT"
export OBJCOPY="$NDK/$MIDDLE/${PREF}objcopy  --sysroot=$SYSROOT"
export OBJDUMP="$NDK/$MIDDLE/${PREF}objdump  --sysroot=$SYSROOT"
export STRIP="$NDK/$MIDDLE/${PREF}strip  --sysroot=$SYSROOT"
export RANLIB="$NDK/$MIDDLE/${PREF}ranlib  --sysroot=$SYSROOT"
export CCLD="$NDK/$MIDDLE/${PREF}gcc  --sysroot=$SYSROOT"
export AR="$NDK/$MIDDLE/${PREF}ar  --sysroot=$SYSROOT"

cmake -DWITH="ALL" -DCHECK=off -DARITH=arm-asm-254 -DARCH=ARM -DCOLOR=off -DOPSYS=DROID -DSEED=ZERO -DSHLIB=off -DFP_PRIME=254 -DFP_QNRES=on -DFP_METHD="INTEG;INTEG;INTEG;MONTY;EXGCD;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -I/opt/android-ndk/platforms/android-14/arch-arm/usr/include" -DLINK="-L/opt/android-ndk/platforms/android-14/arch-arm/usr/lib/ -llog" -DTIMER=HREAL -DWORD=32 -DSTLIB=on $1
