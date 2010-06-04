#ifndef MSP430UTIL_H
#define MSP430UTIL_H

unsigned long long msp430_get_cycles();

volatile unsigned char TEST_CMD asm("0x01b0");
volatile unsigned char TEST_TEXTOUT asm("0x01b1");
volatile unsigned int BENCH_CYCLES_0 asm("0x01b2");
volatile unsigned int BENCH_CYCLES_1 asm("0x01b3");
volatile unsigned int BENCH_CYCLES_2 asm("0x01b4");
volatile unsigned int BENCH_CYCLES_3 asm("0x01b5");

#define BENCH_RESET_             0x50    //Reset cycle counter
#define BENCH_START_             0x51    //Start counting cycles
#define BENCH_STOP_              0x52    //Stop counting cycles
#define BENCH_PRINT_             0x53    //Print cycle count
#define PROF_CLEAR_              0x60    //Clear profiling information

#define PROF_CLEAR              TEST_CMD = PROF_CLEAR_
#define BENCH_RESET             TEST_CMD = BENCH_RESET_
#define BENCH_START             TEST_CMD = BENCH_START_
#define BENCH_STOP              TEST_CMD = BENCH_STOP_
#define BENCH_PRINT             TEST_CMD = BENCH_PRINT_

#endif //MSP430UTIL_H
