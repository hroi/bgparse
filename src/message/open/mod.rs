//! After a TCP connection is established, the first message sent by each
//! side is an OPEN message.  If the OPEN message is acceptable, a
//! KEEPALIVE message confirming the OPEN is sent back.

use types::*;

pub mod capability;
use self::capability::*;


#[derive(Debug)]
pub struct Open<'a> {
    pub inner: &'a [u8],
}

impl<'a> Open<'a> {
    pub fn new(raw: &'a [u8]) -> Result<Open> {
        if raw.len() < 10 {
            Err(BgpError::BadLength)
        } else {
            Ok(Open {
                inner: raw,
            })
        }
    }

    pub fn version(&self) -> u8 {
        self.inner[0]
    }

    pub fn aut_num(&self) -> u32 {
        (self.inner[1] as u32) << 8 | self.inner[2] as u32
    }

    pub fn hold_time(&self) -> u16 {
        (self.inner[3] as u16) << 8 | self.inner[4] as u16
    }

    pub fn ident(&self) -> u32 {
        (self.inner[5] as u32) << 24 | (self.inner[6] as u32) << 16 |
        (self.inner[7] as u32) <<  8 | (self.inner[8] as u32)
    }

    pub fn params(&self) -> OptionalParams {
        OptionalParams::new(&self.inner[10..])
    }
}

#[derive(Debug)]
pub enum OptionalParam<'a> {
    Capability(Capability<'a>),
    Unknown(u8),
}

#[derive(Debug)]
pub struct OptionalParams<'a> {
    pub inner: &'a [u8],
    error: Option<BgpError>,
}

impl<'a> OptionalParams<'a> {
    pub fn new(inner: &'a [u8]) -> OptionalParams<'a> {
        OptionalParams {
            inner: inner,
            error: None,
        }
    }
}

impl<'a> Iterator for OptionalParams<'a> {
    type Item = Result<OptionalParam<'a>>;

    fn next(&mut self) -> Option<Result<OptionalParam<'a>>> {
        if self.error.is_some() {
            return None;
        }
        if self.inner.len() == 0 {
            return None;
        }
        if self.inner.len() < 2 {
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }
        let param_type = self.inner[0];
        let param_len = self.inner[1] as usize;
        if self.inner.len() < param_len + 2 {
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }
        let param_value = &self.inner[2..param_len + 2];
        self.inner = &self.inner[param_len + 2..];
        match param_type {
            2 => {
                match Capability::from_bytes(param_value) {
                    Ok(cap) => Some(Ok(OptionalParam::Capability(cap))),
                    Err(err) => Some(Err(err))
                }

            }
            n => Some(Ok(OptionalParam::Unknown(n))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::capability::*;
    use types::*;
    //use message::open::AddPathDirection;

    #[test]
    fn parse_open() {
        let bytes = &[//0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            //0xff, 0xff, 0xff, 0xff, 0x00, 0x41, 0x01,
            0x04, 0xfc, 0x00, 0x00, 0xb4,
            0x0a, 0x00, 0x00, 0x06, 0x24, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00,
            0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x46,
            0x00, 0x02, 0x06, 0x45, 0x04, 0x00, 0x01, 0x01, 0x03, 0x02, 0x06, 0x41,
            0x04, 0x00, 0x00, 0xfc, 0x00];
        let open = Open::new(bytes).unwrap();
        assert_eq!(open.version(), 4);
        assert_eq!(open.aut_num(), 64512);
        assert_eq!(open.hold_time(), 180);
        assert_eq!(open.ident(), 167772166);

        let mut params = open.params();

        macro_rules! expect_capability {
            ($a:expr, $p:pat) => {
                match $a {
                    OptionalParam::Capability(cap) => {
                        match cap {
                            $p => cap,
                            x => panic!("expected {}, got CapabilityType::{:?}", stringify!($p:tt), x)
                        }
                    }
                    _ => panic!("expected OptionalParam::Capability")
                }
            }
        }

        if let Capability::MultiProtocol(mp) = expect_capability!(params.next().unwrap().unwrap(),
                                                                  Capability::MultiProtocol) {
            assert_eq!(mp.afi(),AFI_IPV4);
            assert_eq!(mp.safi(),SAFI_UNICAST);
        }
        if let Capability::Private(p) = expect_capability!(params.next().unwrap().unwrap(),
                                                           Capability::Private) {
            assert_eq!(p.code(), 128);
        }
        expect_capability!(params.next().unwrap().unwrap(), Capability::RouteRefresh);
        expect_capability!(params.next().unwrap().unwrap(), Capability::EnhancedRouteRefresh);
        if let Capability::AddPath(ap) = expect_capability!(params.next().unwrap().unwrap(),
                                                            Capability::AddPath) {
            assert_eq!(ap.afi(), AFI_IPV4);
            assert_eq!(ap.safi(), SAFI_UNICAST);
            assert_eq!(ap.direction(), ADDPATH_DIRECTION_BOTH);
        }
        if let Capability::FourByteASN(fba) = expect_capability!(params.next().unwrap().unwrap(),
                                                                 Capability::FourByteASN) {
            assert_eq!(fba.aut_num(), 64512);
        }

        assert!(params.next().is_none());
    }
}
