.text
_start: .global _start:
moveqs r3, r6
movle r6, #03
mvngt r9, r6
mvnne r0, #3
addges r3, r4
addal r2, r6, #4
addpl r4, r2, r5, lsr #5
sub r1, r5, r7, lsl #2
fibo:
rsbs r0, r3, #02
eor r4, r3, r2, ror #4
eor r2, r5, r7, asr #5
swi 0
swi 5
mul r5, r2
mul r2, r5, r7
mla r2, r3, r5, r7
beq fibo
blle fibo
msg1: .word 1234
msg2: .asciz "hello, world\n"
adr r3, msg1
adr r6, msg2
ldr r4, =123
ldr r6, =256
ldr r3, =0x12345678
ldr r4, =msg3
ldr r5, =msg5
.data
msg3: .asciz "hello, world\n"
msg4: .word 0x12345678
msg5: .word 256
.end