.text
.intel_syntax noprefix

fp_mulm_low:
sub rsp, 352
mov rax, rdx
mov rdx, [ rsi + 0x8 ]
mulx r11, r10, [ rax + 0x8 ]
mov rdx, [ rsi + 0x10 ]
mulx r8, rcx, [ rax + 0x10 ]
mov rdx, [ rax + 0x0 ]
mov [ rsp - 0x80 ], rbx
mulx rbx, r9, [ rsi + 0x10 ]
mov rdx, [ rax + 0x10 ]
mov [ rsp - 0x78 ], rbp
mov [ rsp - 0x70 ], r12
mulx r12, rbp, [ rsi + 0x28 ]
mov rdx, [ rax + 0x0 ]
mov [ rsp - 0x68 ], r13
mov [ rsp - 0x60 ], r14
mulx r14, r13, [ rsi + 0x8 ]
mov rdx, [ rax + 0x0 ]
mov [ rsp - 0x58 ], r15
mov [ rsp - 0x50 ], rdi
mulx rdi, r15, [ rsi + 0x18 ]
test al, al
adox r10, r14
mov rdx, [ rax + 0x10 ]
mov [ rsp - 0x48 ], r15
mulx r15, r14, [ rsi + 0x8 ]
mov rdx, [ rsi + 0x8 ]
mov [ rsp - 0x40 ], r9
mov [ rsp - 0x38 ], r10
mulx r10, r9, [ rax + 0x18 ]
adox r14, r11
adox r9, r15
mov rdx, [ rsi + 0x10 ]
mulx r15, r11, [ rax + 0x8 ]
adcx r11, rbx
mov rdx, [ rsi + 0x8 ]
mov [ rsp - 0x30 ], r11
mulx r11, rbx, [ rax + 0x20 ]
adcx rcx, r15
mov rdx, [ rsi + 0x10 ]
mov [ rsp - 0x28 ], rcx
mulx rcx, r15, [ rax + 0x18 ]
mov rdx, [ rsi + 0x8 ]
mov [ rsp - 0x20 ], r9
mov [ rsp - 0x18 ], r14
mulx r14, r9, [ rax + 0x28 ]
adox rbx, r10
adox r9, r11
mov rdx, [ rax + 0x20 ]
mulx r11, r10, [ rsi + 0x10 ]
adcx r15, r8
adcx r10, rcx
mov rdx, [ rax + 0x28 ]
mulx rcx, r8, [ rsi + 0x10 ]
adcx r8, r11
mov rdx, [ rsi + 0x18 ]
mov [ rsp - 0x10 ], r8
mulx r8, r11, [ rax + 0x8 ]
mov rdx, [ rax + 0x18 ]
mov [ rsp - 0x8 ], r10
mov [ rsp + 0x0 ], r15
mulx r15, r10, [ rsi + 0x18 ]
mov rdx, 0x0 
adcx rcx, rdx
mov rdx, [ rax + 0x10 ]
mov [ rsp + 0x8 ], rcx
mov [ rsp + 0x10 ], r9
mulx r9, rcx, [ rsi + 0x18 ]
clc
adcx r11, rdi
adcx rcx, r8
mov rdx, 0x0 
adox r14, rdx
adcx r10, r9
mov rdx, [ rax + 0x20 ]
mulx r8, rdi, [ rsi + 0x18 ]
adcx rdi, r15
mov rdx, [ rax + 0x8 ]
mulx r9, r15, [ rsi + 0x28 ]
mov rdx, [ rax + 0x28 ]
mov [ rsp + 0x18 ], rdi
mov [ rsp + 0x20 ], r10
mulx r10, rdi, [ rsi + 0x18 ]
adcx rdi, r8
mov rdx, [ rsi + 0x0 ]
mov [ rsp + 0x28 ], rdi
mulx rdi, r8, [ rax + 0x0 ]
adc r10, 0x0
mov rdx, [ rax + 0x0 ]
mov [ rsp + 0x30 ], r10
mov [ rsp + 0x38 ], rcx
mulx rcx, r10, [ rsi + 0x28 ]
mov rdx, 0x89f3fffcfffcfffd 
mov [ rsp + 0x40 ], r10
mov [ rsp + 0x48 ], r11
mulx r11, r10, r8
xor r11, r11
adox r15, rcx
adox rbp, r9
mov rdx, [ rax + 0x18 ]
mulx rcx, r9, [ rsi + 0x28 ]
mov rdx, [ rax + 0x8 ]
mov [ rsp + 0x50 ], rbp
mulx rbp, r11, [ rsi + 0x0 ]
adox r9, r12
mov rdx, [ rsi + 0x0 ]
mov [ rsp + 0x58 ], r9
mulx r9, r12, [ rax + 0x10 ]
mov rdx, [ rax + 0x20 ]
mov [ rsp + 0x60 ], r15
mov [ rsp + 0x68 ], r14
mulx r14, r15, [ rsi + 0x28 ]
mov rdx, [ rsi + 0x28 ]
mov [ rsp + 0x70 ], rbx
mov [ rsp + 0x78 ], r13
mulx r13, rbx, [ rax + 0x28 ]
adox r15, rcx
adox rbx, r14
mov rdx, [ rsi + 0x0 ]
mulx r14, rcx, [ rax + 0x20 ]
adcx r11, rdi
mov rdx, [ rsi + 0x0 ]
mov [ rsp + 0x80 ], rbx
mulx rbx, rdi, [ rax + 0x18 ]
adcx r12, rbp
adcx rdi, r9
mov rdx, [ rax + 0x28 ]
mulx r9, rbp, [ rsi + 0x0 ]
adcx rcx, rbx
adcx rbp, r14
mov rdx, 0x0 
adox r13, rdx
adc r9, 0x0
mov r14, 0xb9feffffffffaaab 
mov rdx, r10
mulx rbx, r10, r14
mov r14, 0x1eabfffeb153ffff 
mov [ rsp + 0x88 ], r13
mov [ rsp + 0x90 ], r15
mulx r15, r13, r14
test al, al
adox r10, r8
adcx r13, rbx
adox r13, r11
mov r10, 0x6730d2a0f6b0f624 
mulx r11, r8, r10
adcx r8, r15
adox r8, r12
mov r12, 0x4b1ba7b6434bacd7 
mulx r15, rbx, r12
mov r12, 0x64774b84f38512bf 
mulx r14, r10, r12
adcx r10, r11
adcx rbx, r14
adox r10, rdi
adox rbx, rcx
mov rdi, 0x1a0111ea397fe69a 
mulx r11, rcx, rdi
adcx rcx, r15
mov rdx, 0x0 
adcx r11, rdx
adox rcx, rbp
clc
adcx r13, [ rsp + 0x78 ]
adox r11, r9
adcx r8, [ rsp - 0x38 ]
mov rdx, [ rsi + 0x20 ]
mulx r9, rbp, [ rax + 0x18 ]
adcx r10, [ rsp - 0x18 ]
adcx rbx, [ rsp - 0x20 ]
adcx rcx, [ rsp + 0x70 ]
adcx r11, [ rsp + 0x10 ]
mov rdx, [ rsi + 0x20 ]
mulx r14, r15, [ rax + 0x0 ]
mov rdx, [ rax + 0x10 ]
mulx r12, rdi, [ rsi + 0x20 ]
mov rdx, [ rax + 0x8 ]
mov [ rsp + 0x98 ], r15
mov [ rsp + 0xa0 ], r11
mulx r11, r15, [ rsi + 0x20 ]
setc dl
clc
adcx r15, r14
adcx rdi, r11
adcx rbp, r12
movzx rdx, dl
movzx r14, dl
adox r14, [ rsp + 0x68 ]
mov rdx, 0x89f3fffcfffcfffd 
mulx r11, r12, r13
mov rdx, [ rsi + 0x20 ]
mov [ rsp + 0xa8 ], rbp
mulx rbp, r11, [ rax + 0x20 ]
mov rdx, [ rax + 0x28 ]
mov [ rsp + 0xb0 ], rdi
mov [ rsp + 0xb8 ], r15
mulx r15, rdi, [ rsi + 0x20 ]
adcx r11, r9
mov rdx, 0xb9feffffffffaaab 
mov [ rsp + 0xc0 ], r11
mulx r11, r9, r12
adcx rdi, rbp
setc bpl
clc
adcx r9, r13
mov r9, 0x1eabfffeb153ffff 
mov rdx, r12
mulx r13, r12, r9
movzx r9, bpl
lea r9, [ r9 + r15 ]
seto r15b
mov rbp, -0x2 
inc rbp
adox r12, r11
mov r11, 0x6730d2a0f6b0f624 
mov [ rsp + 0xc8 ], r9
mulx r9, rbp, r11
adox rbp, r13
adcx r12, r8
adcx rbp, r10
mov r8, 0x64774b84f38512bf 
mulx r13, r10, r8
mov r8, 0x4b1ba7b6434bacd7 
mov [ rsp + 0xd0 ], rdi
mulx rdi, r11, r8
adox r10, r9
adox r11, r13
adcx r10, rbx
mov rbx, 0x1a0111ea397fe69a 
mulx r13, r9, rbx
adox r9, rdi
adcx r11, rcx
mov rcx, 0x0 
adox r13, rcx
adcx r9, [ rsp + 0xa0 ]
adcx r13, r14
movzx r14, r15b
adc r14, 0x0
xor r15, r15
adox r12, [ rsp - 0x40 ]
adox rbp, [ rsp - 0x30 ]
adox r10, [ rsp - 0x28 ]
adox r11, [ rsp + 0x0 ]
mov rcx, 0x89f3fffcfffcfffd 
mov rdx, rcx
mulx rdi, rcx, r12
adox r9, [ rsp - 0x8 ]
mov rdi, 0x1eabfffeb153ffff 
mov rdx, rdi
mulx r15, rdi, rcx
adox r13, [ rsp - 0x10 ]
mov rbx, 0xb9feffffffffaaab 
mov rdx, rcx
mulx r8, rcx, rbx
adcx rdi, r8
adox r14, [ rsp + 0x8 ]
seto r8b
mov rbx, -0x2 
inc rbx
adox rcx, r12
adox rdi, rbp
mov rcx, 0x6730d2a0f6b0f624 
mulx rbp, r12, rcx
adcx r12, r15
adox r12, r10
mov r10, 0x64774b84f38512bf 
mulx rbx, r15, r10
adcx r15, rbp
mov rbp, 0x4b1ba7b6434bacd7 
mulx rcx, r10, rbp
adox r15, r11
adcx r10, rbx
mov r11, 0x1a0111ea397fe69a 
mulx rbp, rbx, r11
adcx rbx, rcx
mov rdx, 0x0 
adcx rbp, rdx
clc
adcx rdi, [ rsp - 0x48 ]
adcx r12, [ rsp + 0x48 ]
mov rcx, 0x89f3fffcfffcfffd 
mov rdx, rdi
mulx r11, rdi, rcx
adox r10, r9
adox rbx, r13
mov r11, 0xb9feffffffffaaab 
xchg rdx, rdi
mulx r13, r9, r11
adox rbp, r14
adcx r15, [ rsp + 0x38 ]
adcx r10, [ rsp + 0x20 ]
adcx rbx, [ rsp + 0x18 ]
adcx rbp, [ rsp + 0x28 ]
seto r14b
mov r11, -0x2 
inc r11
adox r9, rdi
movzx r9, r14b
movzx r8, r8b
lea r9, [ r9 + r8 ]
mov r8, 0x1eabfffeb153ffff 
mulx r14, rdi, r8
adcx r9, [ rsp + 0x30 ]
setc r11b
clc
adcx rdi, r13
adox rdi, r12
mov r12, 0x6730d2a0f6b0f624 
mulx r8, r13, r12
adcx r13, r14
adox r13, r15
mov r15, 0x64774b84f38512bf 
mulx r12, r14, r15
adcx r14, r8
adox r14, r10
mov r10, 0x4b1ba7b6434bacd7 
mulx r15, r8, r10
adcx r8, r12
adox r8, rbx
mov rbx, 0x1a0111ea397fe69a 
mulx r10, r12, rbx
adcx r12, r15
adox r12, rbp
setc dl
clc
adcx rdi, [ rsp + 0x98 ]
adcx r13, [ rsp + 0xb8 ]
movzx rbp, dl
lea rbp, [ rbp + r10 ]
adox rbp, r9
adcx r14, [ rsp + 0xb0 ]
mov rdx, rcx
mulx r9, rcx, rdi
mov r9, 0xb9feffffffffaaab 
mov rdx, r9
mulx r15, r9, rcx
movzx r10, r11b
mov rbx, 0x0 
adox r10, rbx
mov r11, 0x6730d2a0f6b0f624 
mov rdx, rcx
mulx rbx, rcx, r11
adcx r8, [ rsp + 0xa8 ]
adcx r12, [ rsp + 0xc0 ]
adcx rbp, [ rsp + 0xd0 ]
mov r11, -0x2 
inc r11
adox r9, rdi
mov r9, 0x1eabfffeb153ffff 
mulx r11, rdi, r9
adcx r10, [ rsp + 0xc8 ]
setc r9b
clc
adcx rdi, r15
adcx rcx, r11
adox rdi, r13
adox rcx, r14
mov r13, 0x64774b84f38512bf 
mulx r15, r14, r13
adcx r14, rbx
mov rbx, 0x4b1ba7b6434bacd7 
mulx r13, r11, rbx
adox r14, r8
adcx r11, r15
mov r8, 0x1a0111ea397fe69a 
mulx rbx, r15, r8
adcx r15, r13
mov rdx, 0x0 
adcx rbx, rdx
adox r11, r12
adox r15, rbp
adox rbx, r10
movzx r12, r9b
adox r12, rdx
xor rbp, rbp
adox rdi, [ rsp + 0x40 ]
adox rcx, [ rsp + 0x60 ]
mov rdx, 0x89f3fffcfffcfffd 
mulx r10, r9, rdi
mov r10, 0x1eabfffeb153ffff 
mov rdx, r9
mulx r13, r9, r10
adox r14, [ rsp + 0x50 ]
adox r11, [ rsp + 0x58 ]
adox r15, [ rsp + 0x90 ]
mov rbp, 0xb9feffffffffaaab 
mulx r10, r8, rbp
adox rbx, [ rsp + 0x80 ]
adox r12, [ rsp + 0x88 ]
adcx r9, r10
seto r10b
mov rbp, -0x2 
inc rbp
adox r8, rdi
adox r9, rcx
mov r8, 0x6730d2a0f6b0f624 
mulx rcx, rdi, r8
adcx rdi, r13
mov r13, 0x64774b84f38512bf 
mulx r8, rbp, r13
adcx rbp, rcx
adox rdi, r14
mov r14, 0x4b1ba7b6434bacd7 
mulx r13, rcx, r14
adcx rcx, r8
adox rbp, r11
mov r11, 0x1a0111ea397fe69a 
mulx r14, r8, r11
adcx r8, r13
adox rcx, r15
mov rdx, 0x0 
adcx r14, rdx
adox r8, rbx
adox r14, r12
movzx r15, r10b
adox r15, rdx
mov rbx, r9
mov r10, 0xb9feffffffffaaab 
sub rbx, r10
mov r12, rdi
mov r13, 0x1eabfffeb153ffff 
sbb r12, r13
mov rdx, rbp
mov r11, 0x6730d2a0f6b0f624 
sbb rdx, r11
mov r11, rcx
mov r13, 0x64774b84f38512bf 
sbb r11, r13
mov r13, r8
mov r10, 0x4b1ba7b6434bacd7 
sbb r13, r10
mov r10, r14
mov [ rsp + 0xd8 ], rdx
mov rdx, 0x1a0111ea397fe69a 
sbb r10, rdx
sbb r15, 0x00000000
cmovc rbx, r9
cmovc r11, rcx
cmovc r13, r8
mov r15, [ rsp - 0x50 ]
mov [ r15 + 0x20 ], r13
mov [ r15 + 0x0 ], rbx
cmovc r12, rdi
cmovc r10, r14
mov [ r15 + 0x8 ], r12
mov [ r15 + 0x28 ], r10
mov [ r15 + 0x18 ], r11
mov r9, [ rsp + 0xd8 ]
cmovc r9, rbp
mov [ r15 + 0x10 ], r9
mov rbx, [ rsp - 0x80 ]
mov rbp, [ rsp - 0x78 ]
mov r12, [ rsp - 0x70 ]
mov r13, [ rsp - 0x68 ]
mov r14, [ rsp - 0x60 ]
mov r15, [ rsp - 0x58 ]
add rsp, 352
ret
// cpu Intel(R) Core(TM) i9-10900K CPU @ 3.70GHz
// ratio 1.8980
// seed 2910039682142008 
// CC / CFLAGS clang / -march=native -mtune=native -O3 
// time needed: 5268392 ms on 180000 evaluations.
// Time spent for assembling and measuring (initial batch_size=31, initial num_batches=31): 132796 ms
// number of used evaluations: 180000
// Ratio (time for assembling + measure)/(total runtime for 180000 evals): 0.025206172965109658
// number reverted permutation / tried permutation: 69492 / 89703 =77.469%
// number reverted decision / tried decision: 62053 / 90296 =68.722%
// validated in 51.361s