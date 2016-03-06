pub use core::result;
use core::fmt;

pub const VALID_BGP_MARKER: [u8; 16] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

#[derive(PartialEq)]
pub struct Prefix<'a> {
    pub inner: &'a [u8],
}

impl<'a> fmt::Debug for Prefix<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let masklen = self.inner[0];
        let mut print_period = false;
        for octet in &self.inner[1..] {
            if print_period {
                try!(fmt.write_str("."));
            }
            print_period = true;
            try!(octet.fmt(fmt));
        }
        try!(fmt.write_str("/"));
        masklen.fmt(fmt)
    }
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

#[derive(PartialEq)]
pub struct Afi(u16);

pub const AFI_IPV4: Afi = Afi(1);
pub const AFI_IPV6: Afi = Afi(2);

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

pub const SAFI_UNICAST: Safi = Safi(1);
pub const SAFI_MULTICAST: Safi = Safi(2);

#[derive(PartialEq)]
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
