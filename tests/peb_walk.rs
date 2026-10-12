#[test]
fn finds_ntdll_and_kernel32() {
    let ntdll = global_asm::ntdll::find_module("ntdll.dll");
    assert!(!ntdll.is_null(), "ntdll.dll not found via PEB walk");
    let k32 = global_asm::ntdll::find_module("kernel32.dll");
    assert!(!k32.is_null(), "kernel32.dll not found via PEB walk");
}

#[test]
fn resolves_known_export() {
    let ntdll = global_asm::ntdll::find_module("ntdll.dll");
    assert!(!ntdll.is_null());
    let alloc = unsafe { global_asm::ntdll::resolve_export(ntdll, global_asm::hash::NALLOC) };
    assert!(!alloc.is_null(), "NtAllocateVirtualMemory not resolved");
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
fn targets_resolve() {
    let t = unsafe { global_asm::syscall::resolve_targets() }.expect("resolve_targets");
    assert!(t.ssn_allocate > 0, "NtAllocateVirtualMemory SSN");
    assert!(t.ssn_protect > 0, "NtProtectVirtualMemory SSN");
    assert_ne!(t.gadget, 0, "syscall gadget");
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[test]
#[ignore = "maps a section; run explicitly with --ignored"]
fn clean_mapping() {
    let t = unsafe { global_asm::syscall::resolve_targets() }.expect("resolve_targets");
    let m = unsafe { global_asm::clean::map_clean_ntdll(&t) }.expect("clean mapping");
    assert_ne!(m.base, 0);
    assert_ne!(m.gadget, 0);
    unsafe { m.release() };
}
