#![no_std]
#![no_main]

use aya_ebpf::{bpf_printk, helpers::{bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes, bpf_probe_read_kernel_str_bytes}, macros::{kprobe, kretprobe}, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn kprobes(ctx: ProbeContext) -> u32 {
    match try_kprobes(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

/// The filename arg comes in the form of "struct filename *name"
/// therefore a double dereference is needed to access the path.
fn try_kprobes(ctx: ProbeContext) -> Result<u32, u32> {
    let mut filename_bytes = [0u8; 256];
    let arg1: *const *const u8 = ctx.arg(1).unwrap();
    let filename_ptr: *const u8 = unsafe { bpf_probe_read_kernel(arg1).unwrap()};

    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(filename_ptr, &mut filename_bytes).unwrap())
    }.as_ptr();

    unsafe {
        bpf_printk!(b"filename: %s", filename);
    }

    info!(&ctx, "function do_unlinkat called");
    Ok(0)
}

#[kretprobe]
pub fn kretprobe_test(ctx: ProbeContext) -> u32{
    let retval: u8 = ctx.ret().unwrap();
    info!(&ctx, "Leaving do_unlinkat: {}", retval);
    return 0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
