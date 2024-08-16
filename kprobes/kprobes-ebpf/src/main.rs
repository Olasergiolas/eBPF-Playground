#![no_std]
#![no_main]

use aya_ebpf::{bpf_printk, cty::c_int, helpers::{bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_user, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes, bpf_probe_read_kernel_str_bytes}, macros::{kprobe, kretprobe}, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn kprobes(ctx: ProbeContext) -> u32 {
    match try_kprobes(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kprobes(ctx: ProbeContext) -> Result<u32, u32> {
    let mut buf = [0u8; 256];
    //let mut buf2 = [0u8; 8];

    let testing: *const *const u8 = ctx.arg(1).unwrap();
    let buf2: *const u8 = unsafe { bpf_probe_read_kernel(testing).unwrap()};

    //let filename_struct = ctx.arg::<*const u8>(1).unwrap();
    let filename = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(buf2, &mut buf).unwrap())
    }
    .as_ptr();

    unsafe {
        bpf_printk!(b"filename: %s", filename);
    }

    info!(&ctx, "function do_unlinkat called");
    Ok(0)
}

#[kretprobe]
pub fn kretprobe_test(ctx: ProbeContext) -> u32{
    info!(&ctx, "Leaving do_unlinkat!");
    return 0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
