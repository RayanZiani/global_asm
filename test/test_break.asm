; nasm -f bin test_break.asm -o int3.bin

BITS 64
    int3                ; CC
    ret                 ; C3
