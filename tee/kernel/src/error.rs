#[derive(Debug)]
pub enum Error {
    NoEnt = 2,
    NoMem = 12,
    Acces = 13,
    Fault = 14,
    Exist = 17,
    NotDir = 20,
    IsDir = 21,
    Inval = 22,
    NoSys = 38,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
