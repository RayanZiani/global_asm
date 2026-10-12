# global-asm

Indirect-syscall shellcode runner with zero imports, for Windows 10/11 x64.

## How it works

1. Walk the PEB loader list (`gs:[0x60]`) to find `ntdll.dll` without imports.
2. Parse its export table, resolve APIs by **ROR13** name hash.
3. Read each function's **syscall number (SSN)** from its ntdll stub at runtime
   (never hard-coded), with a Halo's Gate fallback for hooked stubs.
4. Optionally map a clean `ntdll` from `\KnownDlls\ntdll.dll` and borrow its
   `syscall` gadget.
5. Invoke via a hand-written trampoline:
   `mov r10, rcx; mov eax, ssn; jmp <syscall in ntdll>`.

## Requirements

Windows 10 19041+ / Windows 11, x86_64, Rust 1.88+ with the MSVC toolchain
(`x86_64-pc-windows-msvc`).

## Build

```powershell
cargo build --release
# -> target\x86_64-pc-windows-msvc\release\global-asm.exe
```

## Run

```powershell
$exe = ".\target\x86_64-pc-windows-msvc\release\global-asm.exe"
& $exe resolve          # PEB walk + export/SSN diagnostics (no execution)
& $exe map              # map \KnownDlls\ntdll.dll, print the clean gadget
& $exe run              # decrypt and run the embedded harmless payload
& $exe exec .\test\nop.bin
& $exe smoke            # end-to-end smoke test; exits with code 0x1337
& $exe help
```

## Test & lint

```powershell
cargo test
cargo clippy --all-targets -- -D warnings   # or: cargo lint
cargo fmt --all --check
```

## Payloads

`test/` holds NASM templates plus two ready-made fixtures: `nop.bin` (`C3`,
safe) and `int3.bin` (`CC C3`, debugger only). Assemble with:

```powershell
nasm -f bin test\test_nop.asm -o test\nop.bin
```

## Layout

| Path | Contents |
|------|----------|
| `src/hash.rs` | ROR13 hashing + constants |
| `src/ntdll.rs` | PEB walk, export parsing, SSN extract, Halo's Gate |
| `src/syscall.rs` | `global_asm!` trampoline + indirect syscalls |
| `src/clean.rs` | `\KnownDlls\ntdll.dll` mapping |
| `src/payload.rs` | rolling-XOR cipher + embedded payload |
| `src/smoke.rs` | harmless end-to-end smoke payloads |
| `docs/AUDIT.md` | correctness / portability audit + limitations |

MIT : [`LICENSE`](LICENSE)
