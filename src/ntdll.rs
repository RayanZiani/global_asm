use crate::hash;
use core::ptr;

// ---- x64 structure offsets (PEB / LDR) ----
const PEB_LDR_OFFSET: usize = 0x18; // PEB->Ldr
const LDR_INMEMORY_ORDER_OFFSET: usize = 0x20; // PEB_LDR_DATA->InMemoryOrderModuleList
const LDR_ENTRY_INMEMORY_LINKS: usize = 0x10; // offset of the links in the entry
const LDR_ENTRY_DLL_BASE: usize = 0x30;
const LDR_ENTRY_BASE_DLL_NAME: usize = 0x58; // UNICODE_STRING BaseDllName

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const DATA_DIRECTORY_ENTRY_EXPORT: usize = 0;
const DATA_DIRECTORY_OFFSET: usize = 0x70; // start of DataDirectory[] in Optional Header (PE32+)
const OPTIONAL_HEADER_OFFSET: usize = 0x18; // from NT headers
const SIZE_OF_IMAGE_OFFSET: usize = 0x38; // within Optional Header

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,         // bytes, excluding terminator
    pub maximum_length: u16, // bytes
    pub buffer: *mut u16,
}

mod exp {
    pub const NUMBER_OF_NAMES: usize = 0x18;
    pub const ADDRESS_OF_FUNCTIONS: usize = 0x1C;
    pub const ADDRESS_OF_NAMES: usize = 0x20;
    pub const ADDRESS_OF_NAME_ORDINALS: usize = 0x24;
}

// ---- unaligned readers ----

#[inline]
unsafe fn read_ptr(p: *const u8) -> *mut u8 {
    ptr::read_unaligned(p as *const *mut u8)
}

#[inline]
unsafe fn read_u16(p: *const u8) -> u16 {
    u16::from_le(ptr::read_unaligned(p as *const u16))
}

#[inline]
unsafe fn read_u32(p: *const u8) -> u32 {
    u32::from_le(ptr::read_unaligned(p as *const u32))
}

// ---- PEB walk ----

#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!(
        "mov {}, qword ptr gs:[0x60]", // qword ptr required; LLVM would otherwise guess a size
        out(reg) peb,
        options(nostack, preserves_flags, readonly)
    );
    peb
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
unsafe fn get_peb() -> *mut u8 {
    ptr::null_mut()
}

pub fn find_module(name: &str) -> *mut u8 {
    unsafe {
        let peb = get_peb();
        if peb.is_null() {
            return ptr::null_mut();
        }
        let ldr = read_ptr(peb.add(PEB_LDR_OFFSET));
        if ldr.is_null() {
            return ptr::null_mut();
        }
        let list_head = ldr.add(LDR_INMEMORY_ORDER_OFFSET);
        let mut link = read_ptr(list_head);
        while !link.is_null() && link != list_head {
            let entry = link.sub(LDR_ENTRY_INMEMORY_LINKS);
            let base_dll_name = entry.add(LDR_ENTRY_BASE_DLL_NAME) as *const UnicodeString;
            if unicode_eq_ascii_ci(&*base_dll_name, name) {
                return read_ptr(entry.add(LDR_ENTRY_DLL_BASE));
            }
            link = read_ptr(link); // Flink of the current links
        }
        ptr::null_mut()
    }
}

pub fn get_ntdll_base() -> *mut u8 {
    find_module("ntdll.dll")
}

unsafe fn unicode_eq_ascii_ci(us: &UnicodeString, ascii: &str) -> bool {
    if us.buffer.is_null() {
        return false;
    }
    let char_len = (us.length as usize) / 2;
    let expected: Vec<u16> = ascii.encode_utf16().collect();
    if char_len != expected.len() {
        return false;
    }
    let actual = core::slice::from_raw_parts(us.buffer, char_len);
    actual
        .iter()
        .zip(expected.iter())
        .all(|(a, b)| ascii_lower(*a) == ascii_lower(*b))
}

#[inline]
fn ascii_lower(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + 0x20
    } else {
        c
    }
}

// ---- export enumeration / resolution ----

pub unsafe fn for_each_export(base: *mut u8, mut f: impl FnMut(&str, *mut u8)) {
    if base.is_null() || read_u16(base) != IMAGE_DOS_SIGNATURE {
        return;
    }
    let e_lfanew = read_u32(base.add(0x3C)) as usize;
    if e_lfanew < 0x40 || e_lfanew > 0x1000_0000 {
        return;
    }
    let nt = base.add(e_lfanew);
    if read_u32(nt) != IMAGE_NT_SIGNATURE {
        return;
    }

    let data_dir =
        nt.add(OPTIONAL_HEADER_OFFSET + DATA_DIRECTORY_OFFSET + DATA_DIRECTORY_ENTRY_EXPORT * 8);
    let export_rva = read_u32(data_dir) as usize;
    let export_size = read_u32(data_dir.add(4)) as usize;
    if export_rva == 0 || export_size == 0 {
        return;
    }

    let dir = base.add(export_rva);
    let number_of_names = read_u32(dir.add(exp::NUMBER_OF_NAMES)) as usize;
    let funcs = base.add(read_u32(dir.add(exp::ADDRESS_OF_FUNCTIONS)) as usize);
    let names = base.add(read_u32(dir.add(exp::ADDRESS_OF_NAMES)) as usize);
    let ordinals = base.add(read_u32(dir.add(exp::ADDRESS_OF_NAME_ORDINALS)) as usize);

    for i in 0..number_of_names {
        let name_rva = read_u32(names.add(i * 4)) as usize;
        let name_ptr = base.add(name_rva);
        let Ok(name) = std::ffi::CStr::from_ptr(name_ptr as *const i8).to_str() else {
            continue;
        };
        let ordinal = read_u16(ordinals.add(i * 2)) as usize;
        let func_rva = read_u32(funcs.add(ordinal * 4)) as usize;
        // forwarder = RVA pointing back into the export directory; skip it
        if func_rva >= export_rva && func_rva < export_rva + export_size {
            continue;
        }
        f(name, base.add(func_rva));
    }
}

pub unsafe fn resolve_export(base: *mut u8, target_hash: u32) -> *mut u8 {
    let mut found: *mut u8 = ptr::null_mut();
    for_each_export(base, |name, addr| {
        if found.is_null() && hash::ror13_hash(name) == target_hash {
            found = addr;
        }
    });
    found
}

pub unsafe fn size_of_image(base: *mut u8) -> usize {
    if base.is_null() || read_u16(base) != IMAGE_DOS_SIGNATURE {
        return 0;
    }
    let e_lfanew = read_u32(base.add(0x3C)) as usize;
    if e_lfanew < 0x40 || e_lfanew > 0x1000_0000 {
        return 0;
    }
    read_u32(base.add(e_lfanew + OPTIONAL_HEADER_OFFSET + SIZE_OF_IMAGE_OFFSET)) as usize
}

// ---- syscall-number extraction ----

const MOV_R10_RCX: [u8; 3] = [0x4C, 0x8B, 0xD1]; // mov r10, rcx
const MOV_R10D_ECX: [u8; 3] = [0x44, 0x8B, 0xD1]; // mov r10d, ecx
const MOV_EAX_IMM: u8 = 0xB8; // mov eax, imm32
const SYSCALL: [u8; 2] = [0x0F, 0x05];
const RET: u8 = 0xC3;

const PROLOGUE_SCAN: usize = 16;
const TAIL_SCAN: usize = 24;

pub fn parse_syscall_number(bytes: &[u8]) -> Option<u32> {
    let mov_at = find_prologue(bytes)?;
    let imm_at = mov_at + MOV_R10_RCX.len();
    if *bytes.get(imm_at)? != MOV_EAX_IMM {
        return None;
    }
    let imm = [
        *bytes.get(imm_at + 1)?,
        *bytes.get(imm_at + 2)?,
        *bytes.get(imm_at + 3)?,
        *bytes.get(imm_at + 4)?,
    ];
    let ssn = u32::from_le_bytes(imm);

    let tail_start = imm_at + 5;
    let tail_end = core::cmp::min(tail_start + TAIL_SCAN, bytes.len());
    let tail = bytes.get(tail_start..tail_end)?;
    if !contains(tail, &SYSCALL) || !contains(tail, &[RET]) {
        return None;
    }
    Some(ssn)
}

fn find_prologue(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + MOV_R10_RCX.len() <= bytes.len() && i < PROLOGUE_SCAN {
        let w = &bytes[i..i + MOV_R10_RCX.len()];
        if w == MOV_R10_RCX || w == MOV_R10D_ECX {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub unsafe fn syscall_number(func: *mut u8) -> Option<u32> {
    const STUB_WINDOW: usize = 32;
    if func.is_null() {
        return None;
    }
    let bytes = core::slice::from_raw_parts(func, STUB_WINDOW);
    parse_syscall_number(bytes)
}

pub unsafe fn syscall_gadget(stub: *mut u8) -> Option<usize> {
    if stub.is_null() {
        return None;
    }
    let bytes = core::slice::from_raw_parts(stub, 32);
    bytes
        .windows(2)
        .position(|w| w == SYSCALL)
        .map(|off| stub as usize + off)
}

pub unsafe fn syscall_number_halo_gate(ntdll: *mut u8, func: *mut u8) -> Option<u32> {
    if ntdll.is_null() || func.is_null() {
        return None;
    }

    let mut stubs: Vec<(usize, Option<u32>)> = Vec::new();
    for_each_export(ntdll, |_name, addr| {
        let head = core::slice::from_raw_parts(addr, MOV_R10_RCX.len());
        if head == MOV_R10_RCX || head == MOV_R10D_ECX {
            let bytes = core::slice::from_raw_parts(addr, 32);
            stubs.push((addr as usize, parse_syscall_number(bytes)));
        }
    });
    stubs.sort_by_key(|(a, _)| *a);
    stubs.dedup_by_key(|(a, _)| *a);

    let target = func as usize;
    let ti = stubs.iter().position(|(a, _)| *a == target)?;

    // nearest clean stub; higher address => higher SSN
    for delta in 1..stubs.len() {
        if delta <= ti {
            let j = ti - delta;
            if let Some(ssn) = stubs[j].1 {
                return Some(ssn + (ti - j) as u32);
            }
        }
        let j = ti + delta;
        if j < stubs.len() {
            if let Some(ssn) = stubs[j].1 {
                let d = (j - ti) as u32;
                if ssn >= d {
                    return Some(ssn - d);
                }
            }
        }
    }
    None
}

pub unsafe fn syscall_number_robust(ntdll: *mut u8, func: *mut u8) -> Option<u32> {
    syscall_number(func).or_else(|| syscall_number_halo_gate(ntdll, func))
}

// ---- clean ntdll (section mapping) ----
pub use crate::clean;

#[cfg(test)]
mod parser_tests {
    use super::parse_syscall_number;

    fn nt_open_process() -> Vec<u8> {
        vec![
            0x4C, 0x8B, 0xD1, // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00, // mov eax, 0x26
            0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, // test byte ptr [7FFE0308h],1
            0x75, 0x03, // jne +3
            0x0F, 0x05, // syscall
            0xC3, // ret
            0xCD, 0x2E, // int 2Eh
            0xC3, // ret
        ]
    }

    fn minimal_stub() -> Vec<u8> {
        vec![
            0x4C, 0x8B, 0xD1, 0xB8, 0x3A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        ]
    }

    fn mov_r10d_variant() -> Vec<u8> {
        vec![
            0x44, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        ]
    }

    fn padded_stub() -> Vec<u8> {
        let mut v = vec![0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
        v.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00]);
        v.extend_from_slice(&[0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03]);
        v.extend_from_slice(&[0x0F, 0x05, 0xC3]);
        v
    }

    #[test]
    fn classic() {
        assert_eq!(parse_syscall_number(&nt_open_process()), Some(0x26));
    }

    #[test]
    fn minimal() {
        assert_eq!(parse_syscall_number(&minimal_stub()), Some(0x3A));
    }

    #[test]
    fn mov_r10d() {
        assert_eq!(parse_syscall_number(&mov_r10d_variant()), Some(0x18));
    }

    #[test]
    fn padded() {
        assert_eq!(parse_syscall_number(&padded_stub()), Some(0x55));
    }

    #[test]
    fn hooked_stub_is_rejected() {
        let hooked = vec![0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90]; // jmp rel32
        assert_eq!(parse_syscall_number(&hooked), None);
    }

    #[test]
    fn truncated_is_rejected() {
        assert_eq!(parse_syscall_number(&[0x4C, 0x8B, 0xD1, 0xB8]), None);
        assert_eq!(parse_syscall_number(&[]), None);
    }

    #[test]
    fn missing_syscall_is_rejected() {
        let bogus = vec![
            0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90,
        ];
        assert_eq!(parse_syscall_number(&bogus), None);
    }
}
