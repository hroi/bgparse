use types::*;

#[derive(PartialEq, Debug)]
pub struct Nlri<'a> {
    pub path_id: Option<u32>,
    pub prefix: Prefix<'a>,
}

#[derive(Debug)]
pub struct NlriIter<'a> {
    inner: &'a [u8],
    add_paths: bool,
    error: Option<BgpError>,
}

impl<'a> NlriIter<'a> {
    pub fn new(inner: &'a[u8], add_paths: bool) -> NlriIter {
        NlriIter {
            inner: inner,
            add_paths: add_paths,
            error: None,
        }
    }
}

impl<'a> Iterator for NlriIter<'a> {
    type Item = Result<Nlri<'a>>;

    fn next(&mut self) -> Option<Result<Nlri<'a>>> {
        if self.error.is_some() {return None;}
        if self.inner.len() == 0 { return None;}

        let path = if self.add_paths {
            if self.inner.len() < 5 {
                let err = BgpError::BadLength;
                self.error = Some(err);
                return Some(Err(err));
            }
            let (path_bytes,rest) = self.inner.split_at(4);
            self.inner = rest;
            Some((path_bytes[0] as u32) << 24
                 | (path_bytes[1] as u32) << 16
                 | (path_bytes[2] as u32) << 8
                 | path_bytes[3] as u32)
        } else {
            None
        };

        let mask_len = self.inner[0] as usize;
        let byte_len = (mask_len+15) / 8;
        if self.inner.len() < byte_len {
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }
        let slice = &self.inner[..byte_len];
        let nlri = Nlri{path_id: path, prefix: Prefix{inner: slice}};
        self.inner = &self.inner[byte_len..];
        Some(Ok(nlri))
    }
}
