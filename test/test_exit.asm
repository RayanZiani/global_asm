; nasm -f bin test_exit.asm -o exit.bin

BITS 64

    push 0x1337                     ; exit code

    ; --- kernel32 base via the loader list ---
    mov rax, gs:[0x60]              ; PEB
    mov rax, [rax + 0x18]           ; PEB->Ldr
    mov rax, [rax + 0x20]           ; Ldr->InMemoryOrderModuleList (Flink)
    mov rax, [rax]                  ; 2nd entry: ntdll
    mov rax, [rax]                  ; 3rd entry: kernel32
    mov rbx, [rax + 0x20]           ; DllBase

    ; --- export directory ---
    mov eax, [rbx + 0x3C]           ; e_lfanew
    add rax, rbx                    ; rax = NT headers
    mov r9d, [rax + 0x88]           ; DataDirectory[0].VirtualAddress (export)
    add r9, rbx                     ; r9 = IMAGE_EXPORT_DIRECTORY
    mov r8d, [r9 + 0x1C]            ; AddressOfFunctions RVA
    add r8, rbx                     ; r8 = EAT
    mov r10d, [r9 + 0x20]           ; AddressOfNames RVA
    add r10, rbx                    ; r10 = name pointers
    mov r11d, [r9 + 0x24]           ; AddressOfNameOrdinals RVA
    add r11, rbx                    ; r11 = ordinals
    mov ecx, [r9 + 0x18]            ; NumberOfNames
    test ecx, ecx
    jz .done

.next:
    dec ecx
    mov eax, [r10 + rcx*4]          ; RVA of this name
    lea rdx, [rbx + rax]            ; its VA
    mov rax, 0x636F725074697845     ; "ExitProc"
    cmp [rdx], rax
    jne .short
    mov eax, 0x00737365             ; "ess\0"
    cmp [rdx + 8], eax
    je  .found
.short:
    test ecx, ecx
    jnz .next

.done:
    pop rcx
    ret                             ; not found: just return

.found:
    movzx eax, word [r11 + rcx*2]   ; ordinal
    mov eax, [r8 + rax*4]           ; function RVA
    add rax, rbx                    ; function VA
    pop rcx                         ; restore ExitProcess(0x1337) argument
    call rax
    ret
