.global _fp_mulm_low
_fp_mulm_low:
  push %r13
  push %r14
  push %r15
  push %rbx
  mov %rdx, %r15
  ;# Compute the raw multiplication: tmp <- src1 * src2
  ;# Compute src1[0] * src2
  movq 0(%rsi), %rdx
  mulxq 0(%rcx), %r8, %r9
  xor %r10d, %r10d
  movq %r8, 0(%rdi)

  mulxq 8(%rcx), %r10, %r11
  adox %r9, %r10
  movq %r10, 8(%rdi)

  mulxq 16(%rcx), %rbx, %r13
  adox %r11, %rbx
  mulxq 24(%rcx), %r14, %rdx
  adox %r13, %r14
  mov $0, %rax
  adox %rdx, %rax


  ;# Compute src1[1] * src2
  movq 8(%rsi), %rdx
  mulxq 0(%rcx), %r8, %r9
  xor %r10d, %r10d
  adcxq 8(%rdi), %r8
  movq %r8, 8(%rdi)
  mulxq 8(%rcx), %r10, %r11
  adox %r9, %r10
  adcx %rbx, %r10
  movq %r10, 16(%rdi)
  mulxq 16(%rcx), %rbx, %r13
  adox %r11, %rbx
  adcx %r14, %rbx
  mov $0, %r8
  mulxq 24(%rcx), %r14, %rdx
  adox %r13, %r14
  adcx %rax, %r14
  mov $0, %rax
  adox %rdx, %rax
  adcx %r8, %rax


  ;# Compute src1[2] * src2
  movq 16(%rsi), %rdx
  mulxq 0(%rcx), %r8, %r9
  xor %r10d, %r10d
  adcxq 16(%rdi), %r8
  movq %r8, 16(%rdi)
  mulxq 8(%rcx), %r10, %r11
  adox %r9, %r10
  adcx %rbx, %r10
  movq %r10, 24(%rdi)
  mulxq 16(%rcx), %rbx, %r13
  adox %r11, %rbx
  adcx %r14, %rbx
  mov $0, %r8
  mulxq 24(%rcx), %r14, %rdx
  adox %r13, %r14
  adcx %rax, %r14
  mov $0, %rax
  adox %rdx, %rax
  adcx %r8, %rax


  ;# Compute src1[3] * src2
  movq 24(%rsi), %rdx
  mulxq 0(%rcx), %r8, %r9
  xor %r10d, %r10d
  adcxq 24(%rdi), %r8
  movq %r8, 24(%rdi)
  mulxq 8(%rcx), %r10, %r11
  adox %r9, %r10
  adcx %rbx, %r10
  movq %r10, 32(%rdi)
  mulxq 16(%rcx), %rbx, %r13
  adox %r11, %rbx
  adcx %r14, %rbx
  movq %rbx, 40(%rdi)
  mov $0, %r8
  mulxq 24(%rcx), %r14, %rdx
  adox %r13, %r14
  adcx %rax, %r14
  movq %r14, 48(%rdi)
  mov $0, %rax
  adox %rdx, %rax
  adcx %r8, %rax
  movq %rax, 56(%rdi)


  ;# Line up pointers
  mov %rdi, %rsi
  mov %r15, %rdi
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
  pop %r15
  pop %r14
  pop %r13
  ret
