use core::panic::PanicInfo;

use log::error;

use crate::ghcb::exit;

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    error!("{info}");
    exit();
}
