//! Stackdog eBPF main binary
//!
//! This is the entry point for eBPF programs

#![no_main]
#![no_std]

mod maps;
mod syscalls;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
