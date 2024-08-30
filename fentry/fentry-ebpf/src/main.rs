#![no_std]
#![no_main]

use aya_ebpf::{
    macros::fentry,
    programs::FEntryContext, EbpfContext,
};
use aya_log_ebpf::info;

#[fentry(function="do_unlinkat")]
pub fn fentry(ctx: FEntryContext) -> u32 {
    match try_fentry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fentry(ctx: FEntryContext) -> Result<u32, u32> {
    info!(&ctx, "function do_unlinkat called");

    let arg1: *const *const u8 = unsafe{ctx.arg(1)};

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
