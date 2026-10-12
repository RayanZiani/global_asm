; nasm -f win64 test_stub.asm -o test_stub.obj

BITS 64

section .data
    g_ssn:      dd 0        ; e.g. 0x18 for NtAllocateVirtualMemory
    g_gadget:   dq 0        ; address of a `syscall` inside (clean) ntdll

section .text
    global nt_syscall
nt_syscall:
    mov r10, rcx                        ; arg1 travels in r10 across syscall
    mov eax, dword [rel g_ssn]          ; SSN
    jmp qword [rel g_gadget]            ; -> ntdll's `syscall`; its `ret` returns to our caller
