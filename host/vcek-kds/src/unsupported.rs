use std::io::{Error, ErrorKind, Result};

use crate::VcekParameters;

impl VcekParameters {
    /// Determine the parameters of the current platform.
    pub fn current_parameters() -> Result<Self> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "fetching parameters is not supported on this platform",
        ))
    }
}
