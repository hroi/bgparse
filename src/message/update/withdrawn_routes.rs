use types::*;
use core::fmt;

/// This is a variable-length field that contains a list of IP
/// address prefixes for the routes that are being withdrawn from
/// service.
#[derive(Clone)]
pub struct WithdrawnRoutes<'a> {
    pub inner: &'a [u8],
    error: Option<BgpError>,
}

impl<'a> WithdrawnRoutes<'a> {
    pub fn new(inner: &'a [u8]) -> WithdrawnRoutes<'a> {
        WithdrawnRoutes {
            inner: inner,
            error: None,
        }
    }
}

impl<'a> Iterator for WithdrawnRoutes<'a> {
    type Item = Result<Prefix<'a>>;

    fn next(&mut self) -> Option<Result<Prefix<'a>>> {
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
        let mask_len = self.inner[0] as usize;
        let prefix_len = (mask_len+15) / 8; // length in bytes

        if self.inner.len() < mask_len + prefix_len {
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }
        let prefix = &self.inner[..prefix_len];
        self.inner = &self.inner[prefix_len..];
        Some(Ok(Prefix{inner: prefix}))
    }
}

impl<'a> fmt::Debug for WithdrawnRoutes<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_list = fmt.debug_list();
        for attr in self.clone() {
            debug_list.entry(&attr);
        }
        debug_list.finish()
    }
}
