use ldrcrawler::{get_func_address, get_module_handle, WinExecFunc};
use std::mem::transmute;

fn main() {
    let kernel32_base = get_module_handle("kernel32.dll");
    println!(
        "[+] get_module_handle({}) = {:x}",
        "kernel32", kernel32_base
    );
    let ptr_winexec: WinExecFunc = unsafe { transmute(get_func_address(kernel32_base, "WinExec")) };
    println!("[+] get_func_address({}) = {:?}", "WinExec", ptr_winexec);
    let _ = ptr_winexec("calc\0".as_ptr() as *const u8, 5);
}
