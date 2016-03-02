pub use core::result;

use core::fmt;

pub const VALID_BGP_MARKER: [u8; 16] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];


#[derive(PartialEq, Debug)]
pub struct Prefix<'a> {
    pub inner: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub enum BgpError {
    BadLength,
    Invalid,
}

pub type Result<T> = result::Result<T, BgpError>;

impl fmt::Display for BgpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct Afi(u16);

impl From<u16> for Afi {
    fn from(other: u16) -> Afi {
        Afi(other)
    }
}

impl fmt::Debug for Afi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1 => write!(f, "ipv4"),
            2 => write!(f, "ipv6"),
            n => write!(f, "unknown({})", n),
        }
    }
}


pub struct Safi(u8);

impl From<u8> for Safi {
    fn from(other: u8) -> Safi {
        Safi(other)
    }
}

impl fmt::Debug for Safi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1 => write!(f, "unicast"),
            2 => write!(f, "multicast"),
            n => write!(f, "unknown({})", n),
        }
    }
}

#[derive(PartialEq)]
pub struct AutNum(u32);

impl From<u16> for AutNum {
    fn from(other: u16) -> AutNum {
        AutNum(other as u32)
    }
}

impl From<u32> for AutNum {
    fn from(other: u32) -> AutNum {
        AutNum(other)
    }
}

impl fmt::Display for AutNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

impl fmt::Debug for AutNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
