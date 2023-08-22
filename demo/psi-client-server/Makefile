CFLAGS=-O3 -march=native -mtune=native -ggdb -I ${RELIC_ROOT}/include -I target/include
LIBS=target/lib/librelic_s.a -lgmp
RELIC_ROOT = ../..

all: lib
	gcc ${CFLAGS} -o test-bench test-bench.c ${LIBS}
	gcc ${CFLAGS} sender.c -o sender ${LIBS}
	gcc ${CFLAGS} receiver.c -o receiver ${LIBS}

lib:
	mkdir -p target
	cd target; ${RELIC_ROOT}/../preset/x64-pbc-bls12-381.sh ${RELIC_ROOT}/../; cmake -DTIMER=HREAL -DBN_PRECI=3072 -DBENCH=1 -DMULTI=PTHREAD -DEP_METHD='JACOB;LWNAF;COMBS;INTER;SSWUM' .; make

clean:
	rm -rf target *.o test-bench receiver sender
