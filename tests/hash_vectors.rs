use global_asm::hash::*;

#[test]
fn ntdll_export_hashes() {
    assert_eq!(ror13_hash("NtAllocateVirtualMemory"), 0xD33B_CABD);
    assert_eq!(ror13_hash("NtProtectVirtualMemory"), 0x8C39_4D89);
    assert_eq!(ror13_hash("NtFreeVirtualMemory"), 0xDB63_B5AB);
    assert_eq!(ror13_hash("NtOpenSection"), 0x92B5_DD95);
    assert_eq!(ror13_hash("NtMapViewOfSection"), 0xD515_9B94);
    assert_eq!(ror13_hash("NtCreateSection"), 0x5BB2_9BCB);
    assert_eq!(ror13_hash("NtUnmapViewOfSection"), 0xF210_37D0);
    assert_eq!(ror13_hash("NtClose"), 0xDCD4_4C5F);
    assert_eq!(ror13_hash("NtTerminateProcess"), 0x7929_BBF3);
}

#[test]
fn kernel32_export_hashes() {
    assert_eq!(ror13_hash("ExitProcess"), 0x73E2_D87E);
    assert_eq!(ror13_hash("GetProcAddress"), 0x7C0D_FCAA);
    assert_eq!(ror13_hash("LoadLibraryA"), 0xEC0E_4E8E);
}

#[test]
fn constants_are_derived_from_names() {
    assert_eq!(NALLOC, ror13_hash("NtAllocateVirtualMemory"));
    assert_eq!(NPROTECT, ror13_hash("NtProtectVirtualMemory"));
    assert_eq!(NFREE, ror13_hash("NtFreeVirtualMemory"));
    assert_eq!(NOPEN_SECTION, ror13_hash("NtOpenSection"));
    assert_eq!(NMAP_VIEW, ror13_hash("NtMapViewOfSection"));
    assert_eq!(NCREATE_SECTION, ror13_hash("NtCreateSection"));
    assert_eq!(NUNMAP, ror13_hash("NtUnmapViewOfSection"));
    assert_eq!(NCLOSE, ror13_hash("NtClose"));
    assert_eq!(NTERMINATE, ror13_hash("NtTerminateProcess"));
    assert_eq!(EXIT_PROCESS, ror13_hash("ExitProcess"));
}

#[test]
fn edge_cases() {
    assert_eq!(ror13_hash(""), 0);
    assert_ne!(ror13_hash("ab"), ror13_hash("ba"));
}
