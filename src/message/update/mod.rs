//! An UPDATE message is used to advertise feasible routes that share
//! common path attributes to a peer, or to withdraw multiple unfeasible
//! routes from service (see 3.1).  An UPDATE message MAY simultaneously
//! advertise a feasible route and withdraw multiple unfeasible routes
//! from service.  The UPDATE message always includes the fixed-size BGP

use types::*;
use core::fmt;

pub mod path_attr;
pub mod withdrawn_routes;
pub mod nlri;

use self::path_attr::*;
use self::withdrawn_routes::*;
use self::nlri::*;

pub struct Update<'a> {
    pub inner: &'a [u8],
    four_byte_asn: bool,
    add_paths: bool,
}

impl<'a> Update<'a> {
    pub fn from_bytes(raw: &'a [u8], four_byte_asn: bool, add_paths: bool) -> Result<Update> {
        if raw.len() < 19+4 {
            Err(BgpError::BadLength)
        } else {
            Ok(Update {
                inner: raw,
                four_byte_asn: four_byte_asn,
                add_paths: add_paths,
            })
        }
    }

    fn value(&self) -> &'a [u8] {
        &self.inner[19..]
    }

    fn withdrawn_routes_len(&self) -> usize {
        (self.value()[0] as usize) << 8 | self.value()[1] as usize
    }

    fn total_path_attr_len(&self) -> usize {
        let offset = self.withdrawn_routes_len() + 2;
        (self.value()[offset] as usize) << 8 | self.value()[offset+1] as usize
    }

    pub fn withdrawn_routes(&self) -> WithdrawnRoutes {
        let slice = &self.value()[2..][..self.withdrawn_routes_len()];
        WithdrawnRoutes::new(slice)
    }

    pub fn path_attrs(&self) -> PathAttrIter {
        let offset = 4 + self.withdrawn_routes_len();
        let slice = &self.value()[offset..][..self.total_path_attr_len()];
        PathAttrIter::new(slice, self.four_byte_asn)
    }

    pub fn nlris(&self) -> NlriIter {
        let offset = 4 + self.withdrawn_routes_len() + self.total_path_attr_len();
        let slice = &self.value()[offset..];
        NlriIter::new(slice, self.add_paths)
    }
}

impl<'a> fmt::Debug for Update<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Update")
            .field("withdrawn_routes", &self.withdrawn_routes())
            .field("path_attrs", &self.path_attrs())
            .field("nlris", &self.nlris())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use types::*;
    use super::*;
    use super::path_attr::*;
    use super::nlri::*;

    macro_rules! expect_attr {
        ($a:expr, $p:pat, $b:block) => {
            if let Some(Ok(attr)) = $a {
                match attr {
                    $p => $b,
                    _ => panic!("expected PathAttr")
                }
            } else {
                panic!("expected {}", stringify!($p))
            }
        }
    }

    #[test]
    #[cfg_attr(feature="clippy", allow(cyclomatic_complexity))]
    fn parse_update_1() {
        let four_byte_asn = true;
        let add_paths = true;

        let bytes = &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0x00, 0x59, 0x02, 0x00, 0x00, 0x00, 0x30, 0x40,
                      0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfb, 0xff,
                      0x40, 0x03, 0x04, 0x0a, 0x00, 0x0e, 0x01, 0x80, 0x04, 0x04, 0x00, 0x00,
                      0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x0a, 0x04,
                      0x0a, 0x00, 0x22, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x0f, 0x01, 0x00,
                      0x00, 0x00, 0x01, 0x20, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x01,
                      0x20, 0xc0, 0xa8, 0x01, 0x05];
        let update = Update::from_bytes(bytes, four_byte_asn, add_paths).unwrap();

        // withdrawn
        let mut withdrawn = update.withdrawn_routes();
        assert!(withdrawn.next().is_none());

        // attrs
        let mut attrs = update.path_attrs();

        expect_attr!(attrs.next(), PathAttr::Origin(orig), {
            assert_eq!(orig.origin(), OriginType::Igp);
        });

        expect_attr!(attrs.next(), PathAttr::As4Path(path), {
            let mut segments = path.segments();
            match segments.next() {
                Some(Ok(AsPathSegment::AsSequence(seq))) => {
                    let mut asns = seq.aut_nums().unwrap();
                    assert_eq!(asns.next().unwrap(), 64511);
                    assert!(asns.next().is_none());
                }
                _ => panic!("expected AS_SEQUENCE")
            }
        });

        expect_attr!(attrs.next(), PathAttr::NextHop(nh), {
            assert_eq!(nh.ip(), 0x0a000e01);
        });

        expect_attr!(attrs.next(), PathAttr::MultiExitDisc(med), {
            assert_eq!(med.med(), 0);
        });

        expect_attr!(attrs.next(), PathAttr::LocalPreference(pref), {
            assert_eq!(pref.preference(), 100);
        });

        expect_attr!(attrs.next(), PathAttr::ClusterList(list), {
            let mut cluster_ids = list.ids();
            match cluster_ids.next() {
                Some(Ok(id)) => assert_eq!(id, 0x0a002204),
                _ => panic!("expected id")
            };
            assert!(cluster_ids.next().is_none());
        });

        expect_attr!(attrs.next(), PathAttr::OriginatorId(id), {
            assert_eq!(id.ident(), 0x0a000f01);
        });

        assert!(attrs.next().is_none());

        // NLRIs

        let mut nlri = update.nlris();
        assert_eq!(nlri.next().unwrap().unwrap(),
                   Nlri{path_id: Some(1),
                        prefix: Prefix{inner: &[0x20, 0x05, 0x05, 0x05, 0x05]}});
        assert_eq!(nlri.next().unwrap().unwrap(),
                   Nlri{path_id: Some(1),
                        prefix: Prefix{inner: &[0x20, 0xc0, 0xa8, 0x01, 0x05]}});
        assert!(nlri.next().is_none());
    }
}
