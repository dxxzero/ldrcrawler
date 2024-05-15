use std::arch::asm;
use std::ffi::c_void;
use std::ffi::CStr;
use std::os::raw::c_char;
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;

pub type WinExecFunc = extern "stdcall" fn(LPCSTR: *const u8, UINT: u32) -> u32;

#[inline]
#[cfg(target_arch = "x86_64")]
fn __readgsqword(offset: u32) -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "mov {1:r}, gs:[{0:e}]", in(reg) offset, out(reg) out,
        );
    }
    out
}

#[inline]
#[cfg(target_arch = "x86")]
fn __readfsword(offset: u32) -> u32 {
    let out: u32;
    unsafe {
        asm!(
            "mov {1:e}, fs:[{0:e}]", in(reg) offset, out(reg) out,
        );
    }
    out
}

#[cfg(target_arch = "x86_64")]
const ENTRY_OFFSET: usize = 16; //-16 is used instead of the CONTAINING_RECORD macro.
#[cfg(target_arch = "x86")]
const ENTRY_OFFSET: usize = 8; //-8 is used instead of the CONTAINING_RECORD macro.

pub fn get_module_handle(lib_name: &str) -> usize {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        let peb = __readgsqword(0x60) as *const Peb;
        #[cfg(target_arch = "x86")]
        let peb = __readfsword(0x30) as *const Peb;

        let header = (*(*peb).ldr).in_memory_order_module_list;

        let mut curr = header.flink;
        curr = (*curr).flink;

        while curr != header.flink {
            let data = (curr as usize - ENTRY_OFFSET) as *const LdrDataTableEntry;
            let dll_name_slice = std::slice::from_raw_parts(
                (*data).base_dll_name.buffer,
                ((*data).base_dll_name.length / 2) as usize, // /2 because of unicode
            );
            let dll_name = String::from_utf16_lossy(dll_name_slice).to_lowercase();
            if dll_name == lib_name {
                return (*data).dll_base as usize;
            }
            curr = (*curr).flink;
        }
    }

    0
}

pub fn hide_module(lib_name: &str) {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        let peb = __readgsqword(0x60) as *const Peb;
        #[cfg(target_arch = "x86")]
        let peb = __readfsword(0x30) as *const Peb;

        let header = (*(*peb).ldr).in_memory_order_module_list;

        let mut curr = header.flink;
        curr = (*curr).flink;

        while curr != header.flink {
            let in_mem_list  = (curr as usize - ENTRY_OFFSET) as *const LdrDataTableEntry;
            let dll_name_slice = std::slice::from_raw_parts(
                (*in_mem_list).base_dll_name.buffer,
                ((*in_mem_list).base_dll_name.length / 2) as usize, // /2 because of unicode
            );
            let dll_name = String::from_utf16_lossy(dll_name_slice).to_lowercase();
            if dll_name == lib_name {
                let mut prev = (*in_mem_list).in_memory_order_links.blink;
                let mut next = (*in_mem_list).in_memory_order_links.flink;
                if !prev.is_null() {
                    (*prev).flink = next;
                }
                if !next.is_null() {
                    (*next).blink = prev;
                }

                prev = (*in_mem_list).in_load_order_links.blink;
                next = (*in_mem_list).in_load_order_links.flink;
                if !prev.is_null() {
                    (*prev).flink = next;
                }
                if !next.is_null() {
                    (*next).blink = prev;
                }

                prev = (*in_mem_list).in_initialization_order_links.blink;
                next = (*in_mem_list).in_initialization_order_links.flink;
                if !prev.is_null() {
                    (*prev).flink = next;
                }
                if !next.is_null() {
                    (*next).blink = prev;
                }

                break;
            }
            curr = (*curr).flink;
        }
    }

}

pub fn get_func_address(module_base: usize, func_name: &str) -> usize {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    #[cfg(target_arch = "x86_64")]
    let nt_headers =
        unsafe { (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };
    #[cfg(target_arch = "x86")]
    let nt_headers =
        unsafe { (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS32 };
    let optional_headers = (unsafe { *nt_headers }).OptionalHeader;
    let export_table_data = optional_headers.DataDirectory[0];

    let export_table =
        (module_base + export_table_data.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let array_of_functions = module_base + (unsafe { *export_table }).AddressOfFunctions as usize;
    let array_of_names = module_base + (unsafe { *export_table }).AddressOfNames as usize;
    let array_of_names_ordinals =
        module_base + (unsafe { *export_table }).AddressOfNameOrdinals as usize;

    unsafe {
        for i in 0..(*export_table).NumberOfFunctions {
            let fn_name_address =
                module_base + *((array_of_names + (i * 4) as usize) as *const u32) as usize; // * 4 because of size of a DWORD
            let fn_name =
                if let Ok(cstr) = CStr::from_ptr(fn_name_address as *const c_char).to_str() {
                    cstr.to_string()
                } else {
                    continue;
                };
            if fn_name == func_name {
                let num_curr_api_ordinal =
                    *((array_of_names_ordinals + (i * 2) as usize) as *const u16) as usize; // * 2 because size of a WORD
                println!(
                    "[+] Found ordinal {:4x} - {}",
                    num_curr_api_ordinal + 1,
                    fn_name
                );
                return module_base
                    + *((array_of_functions + ((num_curr_api_ordinal) * 4)) // * 4 because of size of a DWORD
                        as *const u32) as usize;
            }
        }
    }
    0
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
union HashLinksOrSectionPointer {
    hash_links: ListEntry,
    section_pointer: *mut c_void,
}

#[repr(C)]
union TimeDateStampOrLoadedImports {
    time_date_stamp: usize,
    loaded_imports: *mut c_void,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: usize,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    flags: usize,
    load_count: u16,
    tls_index: u16,
    hash_links_or_section_pointer: HashLinksOrSectionPointer, // Union
    checksum: usize,
    time_date_stamp_or_loaded_imports: TimeDateStampOrLoadedImports, // Union
    entry_point_activation_context: *mut c_void,
    patch_information: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PebLdrData {
    length: usize,
    initialized: u8,
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry,
    in_memory_order_module_list: ListEntry,
    in_initialization_order_module_list: ListEntry,
    entry_in_progress: *mut c_void,
}

#[repr(C)]
struct Peb {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    bit_field: u8,
    mutant: *mut c_void,
    image_base_address: *mut c_void,
    ldr: *mut PebLdrData,
    process_parameters: usize,
    sub_system_data: *mut c_void,
    process_heap: *mut c_void,
    fast_peb_lock: *mut c_void,
    atl_thunk_slist_ptr: *mut c_void,
    ifeo_key: *mut c_void,
    cross_process_flags: usize,
    user_shared_info_ptr: *mut c_void,
    system_reserved: usize,
    atl_thunk_slist_ptr32: usize,
    api_set_map: *mut c_void,
}
