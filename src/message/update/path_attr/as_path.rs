use types::*;

#[derive(PartialEq, Debug)]
/// AS_PATH is a well-known mandatory attribute that is composed
/// of a sequence of AS path segments.  Each AS path segment is
/// represented by a triple <path segment type, path segment
/// length, path segment value>.
pub struct AsPath<'a> {
    pub inner: &'a [u8],
}

impl<'a> AsPath<'a> {
    pub fn new(inner: &'a [u8]) -> AsPath {
        AsPath {
            inner: inner,
        }
    }

    pub fn segments(&self, four_byte: bool) -> AsPathIter {
        AsPathIter{
            inner: self.inner,
            error: None,
            four_byte: four_byte,
        }
    }
}

pub enum AsPathSegment<'a> {
    AsSequence(AsSequence<'a>),
    AsSet(AsSet<'a>),
}

pub struct AsPathIter<'a> {
    inner: &'a [u8],
    error: Option<BgpError>,
    four_byte: bool,
}

impl<'a> Iterator for AsPathIter<'a> {
    type Item = Result<AsPathSegment<'a>>;

    fn next(&mut self) -> Option<Result<AsPathSegment<'a>>> {
        if self.error.is_some() {
            return None;
        }
        if self.inner.len() == 0 {
            return None;
        }
        let as_size = if self.four_byte { 4 } else { 2 };
        let ret = match self.inner[0] {
            1 => {
                let len = self.inner[1] as usize;
                let slice = &self.inner[2..][..(len*as_size)];
                self.inner = &self.inner[2..][(len*as_size)..];
                Ok(AsPathSegment::AsSet(AsSet{inner: slice, four_byte: self.four_byte}))
            }
            2 => {
                let len = self.inner[1] as usize;
                let slice = &self.inner[2..][..(len*as_size)];
                self.inner = &self.inner[2..][(len*as_size)..];
                Ok(AsPathSegment::AsSequence(AsSequence{inner: slice, four_byte: self.four_byte}))
            }
            _ => {
                let err = BgpError::Invalid;
                self.error = Some(err);
                Err(err)
            }
        };
        Some(ret)
    }
}


macro_rules! impl_asx {
    ($a:ident, $b:ident, $doc:expr) => {

        #[derive(PartialEq, Debug)]
        #[doc=$doc]
        pub struct $a<'a> {
            pub inner: &'a [u8],
            four_byte: bool,
        }

        impl<'a> $a<'a> {

            pub fn aut_nums(&self) -> $b {
                $b{ inner: self.inner, error: None, four_byte: self.four_byte }
            }
        }

        pub struct $b<'a> {
            inner: &'a [u8],
            error: Option<BgpError>,
            four_byte: bool,
        }

        impl<'a> Iterator for $b<'a> {
            type Item = Result<u32>;

            fn next(&mut self) -> Option<Result<u32>> {
                if self.error.is_some() { return None;}
                if self.inner.len() == 0 { return None;}

                let as_size = if self.four_byte { 4 } else { 2 };

                if self.inner.len() < as_size {
                    let err = BgpError::BadLength;
                    self.error = Some(err);
                    return Some(Err(err));
                }

                let asn = if self.four_byte {
                    (self.inner[0] as u32) << 24
                        | (self.inner[1] as u32) << 16
                        | (self.inner[2] as u32) << 8
                        | (self.inner[3] as u32)
                } else {
                    (self.inner[0] as u32) << 8
                        | (self.inner[1] as u32)
                };

                self.inner = &self.inner[as_size..];
                Some(Ok(asn))
            }
        }
    }
}

impl_asx!(AsSet, AsSetIter, "AS_SET: unordered set of ASes a route in the UPDATE message has traversed");
impl_asx!(AsSequence, AsSequenceIter, "AS_SEQUENCE: ordered set of ASes a route in the UPDATE message has traversed");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_as_set() {
        let four_byte_asn = false;
        let bytes = &[0x02, 0x01, 0x00, 0x1e, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x14];
        let as_path = AsPath::new(bytes);
        let mut segments = as_path.segments(four_byte_asn);
        match segments.next() {
            Some(Ok(AsPathSegment::AsSequence(seq))) => {
                let mut asns = seq.aut_nums();
                assert_eq!(asns.next().unwrap().unwrap(), 30);
                let next = asns.next();
                assert!(next.is_none(), "expected None, got {:?}", next);
            },
            _ => panic!("expected AS_SEQUENCE")
        }
        match segments.next() {
            Some(Ok(AsPathSegment::AsSet(set))) => {
                let mut asns = set.aut_nums();
                assert_eq!(asns.next().unwrap().unwrap(), 10);
                assert_eq!(asns.next().unwrap().unwrap(), 20);
                assert!(asns.next().is_none());
            }
            _ => panic!("expected AS_SET")
        }
        assert!(segments.next().is_none());
    }
}
