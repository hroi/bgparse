use types::*;

/// This is a variable-length field that contains a list of IP
/// address prefixes for the routes that are being withdrawn from
/// service.
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
        if self.inner.len() < mask_len + 1 {
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }
        let prefix = &self.inner[..((mask_len+15) / 8)];
        Some(Ok(Prefix{inner: prefix}))
    }
}

