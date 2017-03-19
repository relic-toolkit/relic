.syntax unified
.global fp_mul1_low
.global fp_muln_low

fp_mul1_low:
	PUSH {r4-r12, r14}

	LDR r3, [r1, #(4*0)] 
        LDR r4, [r1, #(4*1)] 
        LDR r5, [r1, #(4*2)] 
        LDR r6, [r1, #(4*3)]
        LDR r7, [r1, #(4*4)]

	UMULL r12, r11, r3, r2
	STR r12, [r0, #(4*0)]

	MOV r12, #0
	UMLAL r11, r12, r4, r2
	STR r11, [r0, #(4*1)]

	MOV r11, #0
	UMLAL r12, r11, r5, r2
	STR r12, [r0, #(4*2)]

	MOV r12, #0
	UMLAL r11, r12, r6, r2
	STR r11, [r0, #(4*3)]
	
	MOV r11, #0
	UMLAL r12, r11, r7, r2
	STR r12, [r0, #(4*4)]

	MOV r12, #0
	STR r11, [r0, #(4*5)]
	STR r12, [r0, #(4*6)]
	STR r12, [r0, #(4*7)]
	STR r12, [r0, #(4*8)]
	STR r12, [r0, #(4*9)]
	POP {r4-r12, pc}

fp_muln_low:
	PUSH {r4-r12, r14}
	LDR r3, [r1, #(4*0)] 
	LDR r4, [r1, #(4*1)] 
	LDR r5, [r1, #(4*2)]
	LDR r6, [r2, #(4*3)]
	LDR r7, [r2, #(4*0)] 
	LDR r8, [r2, #(4*1)] 
	LDR r9, [r2, #(4*2)] 

	UMULL r10, r11, r3, r7
	STR r10, [r0, #(4*0)]
	MOV r10, #0

	MOV r12, #0
	UMLAL r11, r12, r3, r8
	MOV r14, #0
	UMLAL r11, r14, r4, r7
	ADDS r12, r12, r14
	//ADC  r10, r10, #0
	STR r11, [r0, #(4*1)]
	MOV r11, #0

	MOV r14, #0
	UMLAL r12, r14, r3, r9
	ADCS r10, r10, r14
	ADC r11, r11, #0
	MOV r14, #0
	UMLAL r12, r14, r4, r8
	ADDS r10, r10, r14
	ADC r11, r11, #0
	MOV r14, #0
	UMLAL r12, r14, r5, r7
	ADDS r10, r10, r14
	//ADC r11, r11, #0
	STR r12, [r0, #(4*2)]
	MOV r12, #0

	MOV r14, #0
	UMLAL r10, r14, r3, r6
	ADCS r11, r11, r14
	ADC  r12, r12, #0
	MOV r14, #0
	UMLAL r10, r14, r4, r9
	ADDS r11, r11, r14
	ADC  r12, r12, #0
	MOV r14, #0
	UMLAL r10, r14, r5, r8
	ADDS r11, r11, r14
	ADC  r12, r12, #0
	LDR r3, [r1, #(4*3)]
	MOV r14, #0
	UMLAL r10, r14, r3, r7
	ADDS r11, r11, r14
	//ADC  r12, r12, #0
	STR r10, [r0, #(4*3)]
	MOV r10, #0

	MOV r14, #0
	UMLAL r11, r14, r4, r6
	ADCS r12, r12, r14
	ADC r10, r10, #0
	MOV r14, #0
	UMLAL r11, r14, r5, r9
	ADDS r12, r12, r14
	ADC r10, r10, #0
	MOV r14, #0
	UMLAL r11, r14, r3, r8
	ADDS r12, r12, r14
	ADC r10, r10, #0
	LDR r3, [r1, #(4*0)]
	LDR r6, [r2, #(4*4)]
	MOV r14, #0
	UMLAL r11, r14, r3, r6
	ADDS r12, r12, r14
	ADC r10, r10, #0	
	LDR r3, [r1, #(4*4)]
	LDR r6, [r2, #(4*0)]
	MOV r14, #0
	UMLAL r11, r14, r3, r6
	ADDS r12, r12, r14
	//ADC r10, r10, #0
	STR r11, [r0, #(4*4)]
	MOV r11, #0

        LDR r3, [r1, #(4*1)]
	LDR r6, [r2, #(4*4)]	
	MOV r14, #0
	UMLAL r12, r14, r3, r6
	ADCS r10, r10, r14
	ADC  r11, r11, #0
        LDR r3, [r1, #(4*2)]
	LDR r6, [r2, #(4*3)]	
	MOV r14, #0
	UMLAL r12, r14, r3, r6
	ADDS r10, r10, r14
	ADC  r11, r11, #0
        LDR r3, [r1, #(4*3)]
	LDR r6, [r2, #(4*2)]	
	MOV r14, #0
	UMLAL r12, r14, r3, r6
	ADDS r10, r10, r14
	ADC  r11, r11, #0
	LDR r3, [r1, #(4*4)]
	LDR r6, [r2, #(4*1)]
	MOV r14, #0
	UMLAL r12, r14, r3, r6
	ADDS r10, r10, r14
	//ADC  r11, r11, #0
	STR r12, [r0, #(4*5)]
	MOV r12, #0

        LDR r3, [r1, #(4*2)]
	LDR r6, [r2, #(4*4)]
	MOV r14, #0
	UMLAL r10, r14, r3, r6
	ADCS r11, r11, r14
	ADC  r12, r12, #0
        LDR r3, [r1, #(4*3)]
	LDR r6, [r2, #(4*3)]
	MOV r14, #0
	UMLAL r10, r14, r3, r6
	ADDS r11, r11, r14
	ADC  r12, r12, #0
	MOV r14, #0
        LDR r3, [r1, #(4*4)]
	LDR r6, [r2, #(4*2)]	
	UMLAL r10, r14, r3, r6
	ADDS r11, r11, r14
	//ADC  r12, r12, #0
	STR r10, [r0, #(4*6)]
	MOV r10, #0

        LDR r3, [r1, #(4*3)]
	LDR r6, [r2, #(4*4)]	
	MOV r14, #0
	UMLAL r11, r14, r3, r6
	ADCS r12, r12, r14
	ADC r10, r10, #0
	MOV r14, #0
        LDR r3, [r1, #(4*4)]
	LDR r6, [r2, #(4*3)]	
	UMLAL r11, r14, r3, r6
	ADDS r12, r12, r14
	//ADC r10, r10, #0
	MOV r14, #0
	STR r11, [r0, #(4*7)]
	MOV r11, #0
	
	LDR r3, [r1, #(4*4)]
	LDR r6, [r2, #(4*4)]	
	MOV r14, #0
	UMLAL r12, r14, r3, r6
	ADCS r10, r10, r14
	//ADC r11, r11, #0
	STR r12, [r0, #(4*8)]
	STR r10, [r0, #(4*9)]

	POP {r4-r12, pc}
