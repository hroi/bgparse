//! After a TCP connection is established, the first message sent by each
//! side is an OPEN message.  If the OPEN message is acceptable, a
//! KEEPALIVE message confirming the OPEN is sent back.

mod capability;
pub use self::capability::*;
use types::*;

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

    pub fn aut_num(&self) -> AutNum {
        AutNum::from((self.inner[1] as u32) << 8 | self.inner[2] as u32)
    }

    pub fn hold_time(&self) -> u16 {
        (self.inner[3] as u16) << 8 | self.inner[4] as u16
    }

    pub fn ident(&self) -> u32 {
        (self.inner[5] as u32) << 24 | (self.inner[6] as u32) << 16 |
        (self.inner[7] as u32) <<  8 | (self.inner[8] as u32)
    }

    pub fn params(&self) -> OpenParams {
        OpenParams::new(&self.inner[10..])
    }
}

#[derive(Debug)]
pub enum OpenParam<'a> {
    Capability(Capability<'a>),
    Unknown(u8),
}

#[derive(Debug)]
pub struct OpenParams<'a> {
    pub inner: &'a [u8],
    error: Option<BgpError>,
}

impl<'a> OpenParams<'a> {
    pub fn new(inner: &'a [u8]) -> OpenParams<'a> {
        OpenParams {
            inner: inner,
            error: None,
        }
    }
}

impl<'a> Iterator for OpenParams<'a> {
    type Item = Result<OpenParam<'a>>;

    fn next(&mut self) -> Option<Result<OpenParam<'a>>> {
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
            2 => Some(Ok(OpenParam::Capability(Capability::new(param_value)))),
            n => Some(Ok(OpenParam::Unknown(n))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::*;
    //use message::*;

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
        assert_eq!(open.aut_num(), AutNum::from(64512u32));
        assert_eq!(open.hold_time(), 180);
        assert_eq!(open.ident(), 167772166);
        {
            let params = open.params();
            let mut count = 0;
            for param in params {
                match param {
                    Ok(OpenParam::Capability(_cap)) => (),
                    _ => panic!("expected a capability")
                }
                count += 1;
            }
            assert_eq!(count, 6);
        }
    }

}
