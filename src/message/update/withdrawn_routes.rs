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
        if self.inner.len() < 1 {
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }
        let mask_len = self.inner[0] as usize;
        let prefix_len = (mask_len+15) / 8; // length in bytes to represent masklen and ip prefix

        if self.inner.len() < prefix_len {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_withdrawn_routes() {
        let bytes = &[24, 103, 230, 182, // masklen, a, b, c
                      23, 103, 31, 178,
                      23, 103, 253, 46,
                      22, 150, 107, 48,
                      23, 150, 242, 106,
                      22, 103, 15, 164,
                      23, 103, 244, 12,
                      23, 103, 228, 200,
                      23, 103, 15, 166,
                      23, 43, 245, 234,
                      23, 103, 253, 44,
                      22, 43, 245, 232,
                      23, 103, 15, 164,
                      22, 103, 228, 200,
                      22, 103, 244, 12,
                      23, 103, 244, 14,
                      22, 150, 242, 104,
                      21, 114, 129, 8,
                      23, 103, 228, 202,
                      23, 150, 242, 104,
                      22, 103, 31, 176,
                      23, 43, 245, 232];
        let routes = WithdrawnRoutes::new(bytes);
        assert_eq!(routes.count(), 22);
    }
}
