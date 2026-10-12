use crate::{hash, ntdll, syscall};
use core::mem::transmute;

pub unsafe fn exitprocess_via_resolver(code: u32) -> ! {
    let k32 = ntdll::find_module("kernel32.dll");
    let ep = ntdll::resolve_export(k32, hash::EXIT_PROCESS);
    if ep.is_null() {
        eprintln!("[!] ExitProcess not resolved; aborting with code 0xFF");
        std::process::exit(0xFF);
    }
    let exit_process: extern "system" fn(u32) = transmute(ep);
    exit_process(code);
    loop {
        core::hint::spin_loop();
    }
}

pub unsafe fn ntterminate_via_syscall(code: u32) -> ! {
    let t = match syscall::resolve_targets() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[!] {e}; aborting with code 0xFE");
            std::process::exit(0xFE);
        }
    };
    let nt_term = ntdll::resolve_export(t.ntdll_base as *mut u8, hash::NTERMINATE);
    let ssn = ntdll::syscall_number(nt_term).unwrap_or(0);
    let _ = syscall::raw(
        ssn,
        t.gadget,
        [
            syscall::CURRENT_PROCESS,
            code as usize,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    loop {
        core::hint::spin_loop();
    }
}

pub unsafe fn run_shellcode_smoke() -> Result<(), syscall::Error> {
    syscall::exec(&[0x48, 0x31, 0xC0, 0xC3])
}
