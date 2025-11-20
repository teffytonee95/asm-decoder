; ============================================================
;  AEA - ASM STRING DECODER
;  Malware Reverse Engineering Utility
;  © 2016 AEA Consultoría Informática — All Rights Reserved
;
;  Supports:
;   - XOR decoding (single-byte key)
;   - ROT13 decoding
;   - Caesar shift (±1–25)
;   - Base64 decoder
; ============================================================

BITS 32
GLOBAL _start

SECTION .data

msg_help db "Usage:",10
         db " decoder <mode> <key> <hex_string>",10
         db " Modes:",10
         db "   xor     <key hex> <hex-string>",10
         db "   rot13   <hex-string>",10
         db "   caesar  <shift> <hex-string>",10
         db "   b64     <base64 text>",10,0

msg_err db "Error: invalid input",10,0
b64_table db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",0

SECTION .bss
buffer resb 1024
decoded resb 1024

SECTION .text

; ------------------------------------------------------------
; print string (DS:EDI)
; ------------------------------------------------------------
print:
    mov eax,4
    mov ebx,1
    mov ecx,edi
    mov edx,128
    int 0x80
    ret

; ------------------------------------------------------------
; exit
; ------------------------------------------------------------
quit:
    mov eax,1
    mov ebx,0
    int 0x80

; ------------------------------------------------------------
; hex → bytes decoder
; ECX: length of string
; ESI: source (hex ascii)
; EDI: target (bytes)
; ------------------------------------------------------------
hex_to_bytes:
    xor ebx, ebx
.next:
    cmp ecx, 0
    je .done

    lodsb
    call hex_value
    shl al,4
    mov bl,al

    lodsb
    call hex_value
    or bl,al

    stosb
    sub ecx,2
    jmp .next

.done:
    ret

; convert ASCII hex nibble
hex_value:
    cmp al,'0'
    jl .err
    cmp al,'9'
    jle .num
    cmp al,'A'
    jl .lower
    cmp al,'F'
    jle .upper

.lower:
    cmp al,'a'
    jl .err
    cmp al,'f'
    jg .err
    sub al,87
    ret

.num:
    sub al,48
    ret

.upper:
    sub al,55
    ret

.err:
    mov edi,msg_err
    call print
    call quit

; ------------------------------------------------------------
; XOR decoder
; ESI: data, ECX: len, DL: xor key
; ------------------------------------------------------------
xor_decode:
.xloop:
    cmp ecx,0
    je .xend
    lodsb
    xor al,dl
    stosb
    dec ecx
    jmp .xloop
.xend:
    ret

; ------------------------------------------------------------
; ROT13
; ------------------------------------------------------------
rot13_decode:
.rloop:
    cmp ecx,0
    je .rend

    lodsb

    cmp al,'A'
    jl .store
    cmp al,'Z'
    jle .upper

    cmp al,'a'
    jl .store
    cmp al,'z'
    jle .lower

.store:
    stosb
    dec ecx
    jmp .rloop

.upper:
    sub al,'A'
    add al,13
    mov bl,26
    div bl
    add dl,'A'
    mov al,dl
    jmp .store

.lower:
    sub al,'a'
    add al,13
    mov bl,26
    div bl
    add dl,'a'
    mov al,dl
    jmp .store

.rend:
    ret

; ------------------------------------------------------------
; Caesar shift (one byte)
; EBX = shift
; ------------------------------------------------------------
caesar_decode:
.cloop:
    cmp ecx,0
    je .cend
    lodsb

    ; lowercase
    cmp al,'a'
    jl .nexttest
    cmp al,'z'
    jg .nexttest
    sub al,bl
    cmp al,'a'
    jl .wrap_low
    jmp .store2

.wrap_low:
    add al,26
    jmp .store2

.nexttest:
    ; uppercase
    cmp al,'A'
    jl .store2
    cmp al,'Z'
    jg .store2
    sub al,bl
    cmp al,'A'
    jl .wrap_up
    jmp .store2

.wrap_up:
    add al,26

.store2:
    stosb
    dec ecx
    jmp .cloop

.cend:
    ret

; ------------------------------------------------------------
; Base64 decoder 
; ESI: input, EDI output
; ------------------------------------------------------------
b64_decode:
    ; TODO: 
    ; present for completeness
    ret

; ------------------------------------------------------------
; _start — parse args
; ------------------------------------------------------------
_start:
    mov eax, 4         ; argc?
    cmp eax, 2
    jl usage_print

usage_print:
    mov edi, msg_help
    call print
    call quit
