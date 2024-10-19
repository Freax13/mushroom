use std::io::{Read, Result, Write};

use bytemuck::bytes_of;
use tdx_types::report::TdReport;
use vsock::{VsockAddr, VsockStream};

/// Convert a TD report into a TD quote.
pub fn generate_quote(cid: u32, port: u32, report: &TdReport) -> Result<Vec<u8>> {
    let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))?;

    let bytes = bytes_of(report);
    stream.write_all(bytes)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(buf)
}
