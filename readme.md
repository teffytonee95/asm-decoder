# ASM – String Decoder for Malware Reverse Engineering
© 2016 AEA Consultoría Informática — All Rights Reserved

Low-level malware-analysis string decoder written in **x86 Assembly (NASM)** for Linux.

## Features
- XOR decoding (single-byte key)
- ROT13
- Caesar shift (+/- 1–25)
- Minimal Base64 decoder stub
- Hex-string input → byte buffer
- No libc, no dependencies
- Ideal for reversing obfuscated samples

## Build
```bash
nasm -f elf32 decoder.asm -o decoder.o
ld -m elf_i386 decoder.o -o decoder

## USAGE
```bash
./decoder xor 41 48656C6C6F
./decoder rot13 5572yyb
./decoder caesar 3 486HZO

Notes

Written for malware RE workflows that require:

fast decoding of obfuscated strings

verification of embedded config blobs

reversing small stagers or x86 shellcode

