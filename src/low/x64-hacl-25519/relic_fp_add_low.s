.global fp_add1_low
fp_add1_low:
  push %rdi
  push %rsi
  ;# Clear registers to propagate the carry bit
  xor %r8d, %r8d
  xor %r9d, %r9d
  xor %r10d, %r10d
  xor %r11d, %r11d
  xor %eax, %eax

  ;# Begin addition chain
  addq 0(%rsi), %rdx
  movq %rdx, 0(%rdi)
  adcxq 8(%rsi), %r8
  movq %r8, 8(%rdi)
  adcxq 16(%rsi), %r9
  movq %r9, 16(%rdi)
  adcxq 24(%rsi), %r10
  movq %r10, 24(%rdi)

  ;# Return the carry bit in a register
  adcx %r11, %rax
  pop %rsi
  pop %rdi
  ret

.global fp_addm_low
fp_addm_low:
  ;# Compute the raw addition of f1 + f2
  movq 0(%rdx), %r8
  addq 0(%rsi), %r8
  movq 8(%rdx), %r9
  adcxq 8(%rsi), %r9
  movq 16(%rdx), %r10
  adcxq 16(%rsi), %r10
  movq 24(%rdx), %r11
  adcxq 24(%rsi), %r11
  ;# Wrap the result back into the field
  ;# Step 1: Compute carry*38
  mov $0, %rax
  mov $38, %rdx
  cmovc %rdx, %rax

  ;# Step 2: Add carry*38 to the original sum
  xor %ecx, %ecx
  add %rax, %r8
  adcx %rcx, %r9
  movq %r9, 8(%rdi)
  adcx %rcx, %r10
  movq %r10, 16(%rdi)
  adcx %rcx, %r11
  movq %r11, 24(%rdi)

  ;# Step 3: Fold the carry bit back in; guaranteed not to carry at this point
  mov $0, %rax
  cmovc %rdx, %rax
  add %rax, %r8
  movq %r8, 0(%rdi)
  ret

.global fp_subm_low
fp_subm_low:
  ;# Compute the raw substraction of f1-f2
  movq 0(%rsi), %r8
  subq 0(%rdx), %r8
  movq 8(%rsi), %r9
  sbbq 8(%rdx), %r9
  movq 16(%rsi), %r10
  sbbq 16(%rdx), %r10
  movq 24(%rsi), %r11
  sbbq 24(%rdx), %r11
  ;# Wrap the result back into the field
  ;# Step 1: Compute carry*38
  mov $0, %rax
  mov $38, %rcx
  cmovc %rcx, %rax

  ;# Step 2: Substract carry*38 from the original difference
  sub %rax, %r8
  sbb $0, %r9
  sbb $0, %r10
  sbb $0, %r11

  ;# Step 3: Fold the carry bit back in; guaranteed not to carry at this point
  mov $0, %rax
  cmovc %rcx, %rax
  sub %rax, %r8

  ;# Store the result
  movq %r8, 0(%rdi)
  movq %r9, 8(%rdi)
  movq %r10, 16(%rdi)
  movq %r11, 24(%rdi)
  ret
