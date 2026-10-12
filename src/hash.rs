const ROT: u32 = 13; // ROR13

pub const fn ror13_hash(name: &str) -> u32 {
    let bytes = name.as_bytes();
    let mut hash: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        hash = hash.rotate_right(ROT).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

// ---- ntdll exports used by the runner ----

pub const NALLOC: u32 = ror13_hash("NtAllocateVirtualMemory");
pub const NPROTECT: u32 = ror13_hash("NtProtectVirtualMemory");
pub const NFREE: u32 = ror13_hash("NtFreeVirtualMemory");
pub const NOPEN_SECTION: u32 = ror13_hash("NtOpenSection");
pub const NMAP_VIEW: u32 = ror13_hash("NtMapViewOfSection");
pub const NCREATE_SECTION: u32 = ror13_hash("NtCreateSection");
pub const NCLOSE: u32 = ror13_hash("NtClose");
pub const NUNMAP: u32 = ror13_hash("NtUnmapViewOfSection");
pub const NTERMINATE: u32 = ror13_hash("NtTerminateProcess");

// ---- kernel32 exports used by the smoke test ----

pub const EXIT_PROCESS: u32 = ror13_hash("ExitProcess");
pub const LOAD_LIBRARY: u32 = ror13_hash("LoadLibraryA");
pub const GET_PROC_ADDRESS: u32 = ror13_hash("GetProcAddress");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntdll_vectors() {
        assert_eq!(ror13_hash("NtAllocateVirtualMemory"), 0xD33B_CABD);
        assert_eq!(ror13_hash("NtProtectVirtualMemory"), 0x8C39_4D89);
        assert_eq!(ror13_hash("NtOpenSection"), 0x92B5_DD95);
        assert_eq!(ror13_hash("NtMapViewOfSection"), 0xD515_9B94);
        assert_eq!(ror13_hash("NtCreateSection"), 0x5BB2_9BCB);
        assert_eq!(ror13_hash("NtClose"), 0xDCD4_4C5F);
        assert_eq!(ror13_hash("NtTerminateProcess"), 0x7929_BBF3);
        assert_eq!(ror13_hash("NtFreeVirtualMemory"), 0xDB63_B5AB);
        assert_eq!(ror13_hash("NtUnmapViewOfSection"), 0xF210_37D0);
    }

    #[test]
    fn constants_match_names() {
        assert_eq!(NALLOC, ror13_hash("NtAllocateVirtualMemory"));
        assert_eq!(NPROTECT, ror13_hash("NtProtectVirtualMemory"));
        assert_eq!(NFREE, ror13_hash("NtFreeVirtualMemory"));
        assert_eq!(NOPEN_SECTION, ror13_hash("NtOpenSection"));
        assert_eq!(NMAP_VIEW, ror13_hash("NtMapViewOfSection"));
        assert_eq!(NCREATE_SECTION, ror13_hash("NtCreateSection"));
        assert_eq!(NCLOSE, ror13_hash("NtClose"));
        assert_eq!(NTERMINATE, ror13_hash("NtTerminateProcess"));
        assert_eq!(EXIT_PROCESS, ror13_hash("ExitProcess"));
    }

    #[test]
    fn metasploit_vectors() {
        fn ror13_ascii_null(name: &str) -> u32 {
            let mut h = 0u32;
            for b in name.bytes().chain(core::iter::once(0)) {
                h = h.rotate_right(13).wrapping_add(b as u32);
            }
            h
        }
        fn module_hash(module_upper: &str) -> u32 {
            let mut h = 0u32;
            let units = module_upper.encode_utf16().chain(core::iter::once(0u16));
            for unit in units {
                h = h.rotate_right(13).wrapping_add(u32::from(unit & 0xFF));
                h = h.rotate_right(13).wrapping_add(u32::from(unit >> 8));
            }
            h
        }

        assert_eq!(module_hash("KERNEL32.DLL"), 0x92AF_16DA);
        assert_eq!(ror13_ascii_null("WinExec"), 0xF4C0_7457);
        assert_eq!(
            module_hash("KERNEL32.DLL").wrapping_add(ror13_ascii_null("WinExec")),
            0x876F_8B31
        );
        assert_eq!(
            module_hash("KERNEL32.DLL").wrapping_add(ror13_ascii_null("ExitProcess")),
            0x56A2_B5F0
        );
        assert_eq!(
            module_hash("KERNEL32.DLL").wrapping_add(ror13_ascii_null("LoadLibraryA")),
            0x0726_774C
        );
    }
}
