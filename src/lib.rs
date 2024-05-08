use std::arch::asm;
use std::ffi::c_void;
use std::ffi::CStr;
use std::os::raw::c_char;
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

#[cfg(target_arch = "x86_64")]
pub fn get_module_handle(lib_name: &str) -> u64 {
    unsafe {
        let peb = __readgsqword(0x60) as *const Peb;
        let header = (*(*peb).ldr).in_memory_order_module_list;

        let mut curr = header.flink;
        curr = (*(curr as *mut ListEntry)).flink;
        while curr != header.flink {
            let data = (curr - 16) as *const LdrDataTableEntry; //-16 is used instead of the CONTAINING_RECORD macro. Prolly needs to be adjusted for x86
            let dll_name_slice = std::slice::from_raw_parts(
                (*data).base_dll_name.buffer,
                ((*data).base_dll_name.length / 2) as usize, // /2 because of unicode
            );
            let dll_name = String::from_utf16_lossy(dll_name_slice).to_lowercase();
            if dll_name == lib_name {
                return (*data).dll_base;
            }
            curr = (*(curr as *mut ListEntry)).flink;
        }
    }

    0
}

#[cfg(target_arch = "x86_64")]
pub fn get_func_address(module_base: u64, func_name: &str) -> u64 {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    let nt_headers =
        unsafe { (module_base + (*dos_header).e_lfanew as u64) as *const IMAGE_NT_HEADERS64 };
    let optional_headers = (unsafe { *nt_headers }).OptionalHeader;
    let export_table_data = optional_headers.DataDirectory[0];

    let export_table =
        (module_base + export_table_data.VirtualAddress as u64) as *const IMAGE_EXPORT_DIRECTORY;
    let array_of_functions =
        (module_base + (unsafe { *export_table }).AddressOfFunctions as u64) as u64;
    let array_of_names = (module_base + (unsafe { *export_table }).AddressOfNames as u64) as u64;
    let array_of_names_ordinals =
        (module_base + (unsafe { *export_table }).AddressOfNameOrdinals as u64) as u64;

    unsafe {
        for i in 0..(*export_table).NumberOfFunctions {
            let fn_name_address =
                module_base + *((array_of_names as usize + (i * 4) as usize) as *const u32) as u64;
            let fn_name =
                if let Ok(cstr) = CStr::from_ptr(fn_name_address as *const c_char).to_str() {
                    cstr.to_string()
                } else {
                    String::default()
                };
            if fn_name == func_name {
                let num_curr_api_ordinal =
                    *((array_of_names_ordinals as usize + (i * 2) as usize) as *const u16) as u64;
                println!(
                    "[+] Found ordinal {:4x} - {}",
                    num_curr_api_ordinal + 1,
                    fn_name
                );
                return module_base
                    + *((array_of_functions as usize + ((num_curr_api_ordinal) * 4) as usize)
                        as *const u32) as u64;
            }
        }
    }
    0
}

#[repr(C)]
struct UnicodeString32 {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
union HashLinksOrSectionPointer {
    hash_links: ListEntry,
    section_pointer: u64,
}

#[repr(C)]
union TimeDateStampOrLoadedImports {
    time_date_stamp: u64,
    loaded_imports: u64,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: u64,
    entry_point: u64,
    size_of_image: u64,
    full_dll_name: UnicodeString32,
    base_dll_name: UnicodeString32,
    flags: u64,
    load_count: u16,
    tls_index: u16,
    hash_links_or_section_pointer: HashLinksOrSectionPointer, // Union
    checksum: u64,
    time_date_stamp_or_loaded_imports: TimeDateStampOrLoadedImports, // Union
    entry_point_activation_context: u64,
    patch_information: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ListEntry {
    flink: u64,
    blink: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PebLdrData {
    length: u64,
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
    mutant: u64,
    image_base_address: u64,
    ldr: *mut PebLdrData,
    process_parameters: u64,
    sub_system_data: u64,
    process_heap: u64,
    fast_peb_lock: u64,
    atl_thunk_slist_ptr: u64,
    ifeo_key: u64,
    cross_process_flags: u64,
    user_shared_info_ptr: u64,
    system_reserved: u64,
    atl_thunk_slist_ptr32: u64,
    api_set_map: u64,
}
