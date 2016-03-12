pub use core::result;
use core::fmt;

pub use afi::*;
pub use safi::*;

pub const VALID_BGP_MARKER: [u8; 16] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

#[derive(PartialEq)]
pub struct Ipv4Prefix<'a> {
    pub inner: &'a [u8],
}

impl<'a> fmt::Debug for Ipv4Prefix<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let masklen = self.inner[0];
        if masklen == 0 {
            return fmt.write_str("0/0");
        }

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

#[derive(PartialEq)]
pub struct Ipv6Prefix<'a> {
    pub inner: &'a [u8],
}

impl<'a> fmt::Debug for Ipv6Prefix<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let masklen = self.inner[0];
        if masklen == 0 {
            return fmt.write_str("::/0");
        }

        let mut print_colon = false;
        for chunk in self.inner[1..].chunks(2) {
            let a = chunk[0] as u16;
            let b: u8 = *chunk.get(1).unwrap_or(&0);
            let segment: u16 = a << 8 | (b as u16);
            if print_colon {
                try!(fmt.write_str(":"));
            }
            print_colon = true;
            try!(fmt.write_fmt(format_args!("{:04x}", segment)));
        }
        if masklen < 112 {
            try!(fmt.write_str("::"));
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

