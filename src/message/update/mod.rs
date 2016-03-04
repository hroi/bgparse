use types::*;

pub mod path_attr;
pub mod withdrawn_routes;
pub mod nlri;

use self::path_attr::*;
use self::withdrawn_routes::*;
use self::nlri::*;

#[derive(Debug)]
pub struct Update<'a> {
    pub inner: &'a [u8],
}

impl<'a> Update<'a> {
    pub fn new(raw: &'a [u8]) -> Result<Update> {
        if raw.len() < 4 {
            Err(BgpError::BadLength)
        } else {
            Ok(Update {
                inner: raw,
            })
        }
    }

    fn withdrawn_routes_len(&self) -> usize {
        (self.inner[0] as usize) << 8 | self.inner[1] as usize
    }

    fn total_path_attr_len(&self) -> usize {
        let offset = self.withdrawn_routes_len() + 2;
        (self.inner[offset] as usize) << 8 | self.inner[offset+1] as usize
    }

    pub fn withdrawn_routes(&self) -> WithdrawnRoutes {
        let slice = &self.inner[2..][..self.withdrawn_routes_len()];
        WithdrawnRoutes::new(slice)
    }

    pub fn path_attrs(&self) -> PathAttrIter {
        let offset = 4 + self.withdrawn_routes_len();
        let slice = &self.inner[offset..][..self.total_path_attr_len()];
        PathAttrIter::new(slice)
    }

    pub fn nlri(&self, add_paths: bool) -> NlriIter {
        let offset = 4 + self.withdrawn_routes_len() + self.total_path_attr_len();
        let slice = &self.inner[offset..];
        NlriIter::new(slice, add_paths)
    }
}

#[cfg(test)]
mod tests {
    //use types::*;
    //use super::*;
    //use super::path_attr::*;
    //use super::nlri::*;

    // #[test]
    // fn parse_update() {
    //     let four_byte_asn = true;
    //     let add_paths = true;

    //     let bytes = &[//0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    //                   //0xff, 0xff, 0xff, 0xff, 0x00, 0x59, 0x02,
    //                   0x00, 0x00, 0x00, 0x30, 0x40,
    //                   0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfb, 0xff,
    //                   0x40, 0x03, 0x04, 0x0a, 0x00, 0x0e, 0x01, 0x80, 0x04, 0x04, 0x00, 0x00,
    //                   0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x0a, 0x04,
    //                   0x0a, 0x00, 0x22, 0x04, 0x80, 0x09, 0x04, 0x0a, 0x00, 0x0f, 0x01, 0x00,
    //                   0x00, 0x00, 0x01, 0x20, 0x05, 0x05, 0x05, 0x05, 0x00, 0x00, 0x00, 0x01,
    //                   0x20, 0xc0, 0xa8, 0x01, 0x05];
    //     let update = Update::new(bytes).unwrap();
    //     //assert_eq!(update.withdrawn_routes_len(), 0);
    //     //assert_eq!(update.total_path_attr_len(), 48);
    //     // withdrawn

    //     let mut withdrawn = update.withdrawn_routes();
    //     assert!(withdrawn.next().is_none());

    //     // attrs
    //     let mut attrs = update.path_attrs();

    //     assert_eq!(attrs.next().unwrap().unwrap().attr_type(), PathAttrType::Origin(Origin::Igp));
    //     match attrs.next().unwrap().unwrap().attr_type() {
    //         PathAttrType::AsPath(path) => {
    //             let mut segments = path.segments(four_byte_asn);
    //             match segments.next() {
    //                 Some(Ok(AsPathSegment::AsSequence(seq))) => {
    //                     let mut asns = seq.aut_nums();
    //                     assert_eq!(asns.next().unwrap().unwrap(), 64511);
    //                     assert!(asns.next().is_none());
    //                 },
    //                 _ => panic!("expected an AS_SEQUENCE")
    //             }
    //             assert!(segments.next().is_none());
    //         },
    //         _ => panic!("expected an AS_PATH"),
    //     }
    //     assert_eq!(attrs.next().unwrap().unwrap().attr_type(), PathAttrType::NextHop(0x0a000e01));
    //     assert_eq!(attrs.next().unwrap().unwrap().attr_type(), PathAttrType::MultiExitDiscriminator(0));
    //     assert_eq!(attrs.next().unwrap().unwrap().attr_type(), PathAttrType::LocalPref(100));
    //     match attrs.next().unwrap().unwrap().attr_type() {
    //         PathAttrType::ClusterList(list) => {
    //             let mut cluster_ids = list.ids();
    //             match cluster_ids.next() {
    //                 Some(Ok(id)) => assert_eq!(id, 0x0a002204),
    //                 _ => panic!("expected id")
    //             };
    //             assert!(cluster_ids.next().is_none());
    //         },
    //         _ => panic!("expected CLUSTER_LIST"),
    //     }
    //     assert_eq!(attrs.next().unwrap().unwrap().attr_type(), PathAttrType::OriginatorId(0x0a000f01));
    //     assert!(attrs.next().is_none());

    //     // NLRIs

    //     let mut nlri = update.nlri(add_paths);
    //     assert_eq!(nlri.next().unwrap().unwrap(),
    //                Nlri{path_id: Some(1),
    //                     prefix: Prefix{inner: &[0x20, 0x05, 0x05, 0x05, 0x05]}});
    //     assert_eq!(nlri.next().unwrap().unwrap(),
    //                Nlri{path_id: Some(1),
    //                     prefix: Prefix{inner: &[0x20, 0xc0, 0xa8, 0x01, 0x05]}});
    //     assert!(nlri.next().is_none());
    // }
}
