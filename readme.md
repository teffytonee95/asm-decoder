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
