#include "msp430util.h"
#include <stdio.h>

union cycles_t {
    unsigned long long cycles;
    struct {
        unsigned int e0;
        unsigned int e1; 
        unsigned int e2; 
        unsigned int e3; 
    } e;
};

int putchar(int c) {
    TEST_TEXTOUT = (char) c;
    return c;
}

unsigned long long msp430_get_cycles()
{
    union cycles_t cycles;
    cycles.e.e0 = BENCH_CYCLES_0;
    cycles.e.e1 = BENCH_CYCLES_1;
    cycles.e.e2 = BENCH_CYCLES_2;
    cycles.e.e3 = BENCH_CYCLES_3;
    return cycles.cycles;
}
