CFLAGS=-O3 -march=native -mtune=native -ggdb
RELIC_ROOT = ../..

all: lib
	gcc ${CFLAGS} -c main.c -o main.o -I ${RELIC_ROOT}/include -I target/include
	gcc ${CFLAGS} -c mlkem.c -o mlkem.o -I ${RELIC_ROOT}/include -I target/include
	gcc ${CFLAGS} -o main main.o mlkem.o target/lib/librelic_s.a -lgmp

lib:
	mkdir -p target
	cd target; ${RELIC_ROOT}/../preset/gmp-ecc-128.sh ${RELIC_ROOT}/../; cmake -DBN_PRECI=2048 -DBN_METHD='COMBA;COMBA;MONTY;SLIDE;LOWER' -DWITH="MD;BC;DV;BN;CP" -DTESTS=0 -DBENCH=0 .; make

clean:
	rm -rf target *.o main
