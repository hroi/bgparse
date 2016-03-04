pub mod as_path;
pub mod cluster_list;
pub mod origin;

use types::*;
pub use self::as_path::*;
pub use self::cluster_list::*;
pub use self::origin::*;

const FLAG_EXT_LEN: u8 = 0b00010000;

#[derive(PartialEq, Debug)]
pub enum PathAttrType<'a> {
    /// well-known mandatory attribute that defines the origin of the path information.
    Origin(Origin),
    /// well-known mandatory attribute that is composed of a sequence of AS path segments.
    AsPath(AsPath<'a>),
    /// defines the (unicast) IP address of the router that SHOULD be used as the next hop to the
    /// destinations listed in the Network Layer Reachability Information field
    NextHop(u32),
    /// optional non-transitive attribute that is a four-octet unsigned integer.  The value of this
    /// attribute MAY be used by a BGP speaker's Decision Process to discriminate among multiple
    /// entry points to a neighboring autonomous system.
    MultiExitDiscriminator(u32),
    /// well-known attribute that is a four-octet unsigned integer.  A BGP speaker uses it to inform
    /// its other internal peers of the advertising speaker's degree of preference for an advertised
    /// route.
    LocalPref(u32),
    /// well-known discretionary attribute of length 0.
    AtomicAggregate,
    /// optional transitive attribute of length 6. The attribute contains the last AS number that
    /// formed the aggregate route (encoded as 2 octets), followed by the IP address of the BGP
    /// speaker that formed the aggregate route (encoded as 4 octets).
    Aggregator,
    /// optional transitive attribute of variable length.  The attribute consists of a set of four
    /// octet values, each of which specify a community.
    Community,
    OriginatorId(u32),
    ClusterList(ClusterList<'a>),
    Unknown(u8),
}

#[derive(Debug)]
pub struct PathAttr<'a> {
    pub inner: &'a [u8],
}

impl<'a> PathAttr<'a> {

    pub fn attr_flags(&self) -> u8 {
        self.inner[0]
    }

    pub fn attr_type(&self) -> PathAttrType {
        match self.inner[1] {
            1 => {
                match self.attr_value()[0] {
                    0 => PathAttrType::Origin(Origin::Igp),
                    1 => PathAttrType::Origin(Origin::Egp),
                    2 => PathAttrType::Origin(Origin::Incomplete),
                    _ => PathAttrType::Origin(Origin::Unknown),
                }
            },
            2 => PathAttrType::AsPath(AsPath::new(self.attr_value())),
            3 => {
                let ip =
                    (self.attr_value()[0] as u32) << 24
                    | (self.attr_value()[1] as u32) << 16
                    | (self.attr_value()[2] as u32) << 8
                    | (self.attr_value()[3] as u32);
                PathAttrType::NextHop(ip)
            },
            4 => {
                let med =
                    (self.attr_value()[0] as u32) << 24
                    | (self.attr_value()[1] as u32) << 16
                    | (self.attr_value()[2] as u32) << 8
                    | (self.attr_value()[3] as u32);
                PathAttrType::MultiExitDiscriminator(med)
            },
            5 => {
                let lpref =
                    (self.attr_value()[0] as u32) << 24
                    | (self.attr_value()[1] as u32) << 16
                    | (self.attr_value()[2] as u32) << 8
                    | (self.attr_value()[3] as u32);
                PathAttrType::LocalPref(lpref)
            },
            6 => PathAttrType::AtomicAggregate,
            7 => PathAttrType::Aggregator,
            8 => PathAttrType::Community,
            9 => {
                let id =
                    (self.attr_value()[0] as u32) << 24
                    | (self.attr_value()[1] as u32) << 16
                    | (self.attr_value()[2] as u32) << 8
                    | (self.attr_value()[3] as u32);
                PathAttrType::OriginatorId(id)
            },
            10 => {
                PathAttrType::ClusterList(ClusterList::new(self.attr_value()))
            }
            n => PathAttrType::Unknown(n),
        }
    }

    fn attr_value(&self) -> &[u8] {
        let is_extended = self.attr_flags() & FLAG_EXT_LEN > 0;
        if is_extended {
            &self.inner[4..]
        } else {
            &self.inner[3..]
        }
    }

}

pub struct PathAttrIter<'a> {
    pub inner: &'a [u8],
    error: Option<BgpError>,
}

impl<'a> PathAttrIter<'a> {
    pub fn new(inner: &'a [u8]) -> PathAttrIter<'a> {
        PathAttrIter {
            inner: inner,
            error: None,
        }
    }
}

impl<'a> Iterator for PathAttrIter<'a> {
    type Item = Result<PathAttr<'a>>;

    fn next(&mut self) -> Option<Result<PathAttr<'a>>> {
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

        let attr_flags = self.inner[0];

        let is_extended = attr_flags & FLAG_EXT_LEN > 0;

        let attr_value_offset = if is_extended { 4 } else { 3 };

        let attr_len = if is_extended {
            (self.inner[2] as usize) << 8 | self.inner[3] as usize
        } else {
            self.inner[2] as usize
        };

        if self.inner.len() < attr_value_offset + attr_len{
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }
        let next_offset = attr_value_offset + attr_len;
        let slice = &self.inner[..next_offset];
        self.inner = &self.inner[next_offset..];
        Some(Ok(PathAttr{inner: slice}))
    }
}

