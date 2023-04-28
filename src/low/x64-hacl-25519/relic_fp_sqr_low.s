.global _fp_sqrm_low
_fp_sqrm_low:
  push %r15
  push %r13
  push %r14
  push %r12
  push %rbx
  mov %rdx, %r12
  ;# Compute the raw multiplication: tmp <- f * f
  ;# Step 1: Compute all partial products
  movq 0(%rsi), %rdx
  ;# f[0]
  mulxq 8(%rsi), %r8, %r14
  xor %r15d, %r15d
  ;# f[1]*f[0]
  mulxq 16(%rsi), %r9, %r10
  adcx %r14, %r9
  ;# f[2]*f[0]
  mulxq 24(%rsi), %rax, %rcx
  adcx %rax, %r10
  ;# f[3]*f[0]
  movq 24(%rsi), %rdx
  ;# f[3]
  mulxq 8(%rsi), %r11, %rbx
  adcx %rcx, %r11
  ;# f[1]*f[3]
  mulxq 16(%rsi), %rax, %r13
  adcx %rax, %rbx
  ;# f[2]*f[3]
  movq 8(%rsi), %rdx
  adcx %r15, %r13
  ;# f1
  mulxq 16(%rsi), %rax, %rcx
  mov $0, %r14
  ;# f[2]*f[1]

  ;# Step 2: Compute two parallel carry chains
  xor %r15d, %r15d
  adox %rax, %r10
  adcx %r8, %r8
  adox %rcx, %r11
  adcx %r9, %r9
  adox %r15, %rbx
  adcx %r10, %r10
  adox %r15, %r13
  adcx %r11, %r11
  adox %r15, %r14
  adcx %rbx, %rbx
  adcx %r13, %r13
  adcx %r14, %r14

  ;# Step 3: Compute intermediate squares
  movq 0(%rsi), %rdx
  mulx %rdx, %rax, %rcx
  ;# f[0]^2
  movq %rax, 0(%rdi)

  add %rcx, %r8
  movq %r8, 8(%rdi)

  movq 8(%rsi), %rdx
  mulx %rdx, %rax, %rcx
  ;# f[1]^2
  adcx %rax, %r9
  movq %r9, 16(%rdi)

  adcx %rcx, %r10
  movq %r10, 24(%rdi)

  movq 16(%rsi), %rdx
  mulx %rdx, %rax, %rcx
  ;# f[2]^2
  adcx %rax, %r11
  movq %r11, 32(%rdi)

  adcx %rcx, %rbx
  movq %rbx, 40(%rdi)

  movq 24(%rsi), %rdx
  mulx %rdx, %rax, %rcx
  ;# f[3]^2
  adcx %rax, %r13
  movq %r13, 48(%rdi)

  adcx %rcx, %r14
  movq %r14, 56(%rdi)


  ;# Line up pointers
  mov %rdi, %rsi
  mov %r12, %rdi
  ;# Wrap the result back into the field
  ;# Step 1: Compute dst + carry == tmp_hi * 38 + tmp_lo
  mov $38, %rdx
  mulxq 32(%rsi), %r8, %r13
  xor %ecx, %ecx
  adoxq 0(%rsi), %r8
  mulxq 40(%rsi), %r9, %rbx
  adcx %r13, %r9
  adoxq 8(%rsi), %r9
  mulxq 48(%rsi), %r10, %r13
  adcx %rbx, %r10
  adoxq 16(%rsi), %r10
  mulxq 56(%rsi), %r11, %rax
  adcx %r13, %r11
  adoxq 24(%rsi), %r11
  adcx %rcx, %rax
  adox %rcx, %rax
  imul %rdx, %rax

  ;# Step 2: Fold the carry back into dst
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
  pop %rbx
  pop %r12
  pop %r14
  pop %r13
  pop %r15
  ret
