use constants::EXIT_PORT;
use x86_64::instructions::port::PortWriteOnly;

pub fn exit(success: bool) {
    unsafe {
        PortWriteOnly::<u32>::new(EXIT_PORT).write(u32::from(success));
    }
}
