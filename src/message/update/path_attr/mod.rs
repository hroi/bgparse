use types::*;

/// Defines whether the attribute is optional (if set to 1) or well-known (if set to 0)
pub const FLAG_OPTIONAL:   u8 = 0b10000000;
/// Defines whether an optional attribute is transitive (if set to 1) or non-transitive (if set to 0).
/// For well-known attributes, the Transitive bit MUST be set to 1.
pub const FLAG_TRANSITIVE: u8 = 0b01000000;
/// Defines whether the information contained in the optional transitive attribute is partial (if
/// set to 1) or complete (if set to 0).  For well-known attributes
/// and for optional non-transitive attributes, the Partial bit
/// MUST be set to 0.
pub const FLAG_PARTIAL:    u8 = 0b00100000;
/// Defines whether the Attribute Length is one octet (if set to 0) or two octets (if set to 1).
pub const FLAG_EXT_LEN:    u8 = 0b00010000;

pub enum PathAttr<'a> {
    Origin(Origin<'a>),
    AsPath(AsPath<'a>),
    NextHop(NextHop<'a>),
    MultiExitDisc(MultiExitDisc<'a>),
    LocalPreference(LocalPreference<'a>),
    AtomicAggregate(AtomicAggregate<'a>),
    Aggregator(Aggregator<'a>),
    Community(Community<'a>),
    OriginatorId(OriginatorId<'a>),
    ClusterList(ClusterList<'a>),
    MpReachNlri(MpReachNlri<'a>),
    MpUnreachNlri(MpUnreachNlri<'a>),
    ExtendedCommunities(ExtendedCommunities<'a>),
    As4Path(As4Path<'a>),
    As4Aggregator(As4Aggregator<'a>),
    PmsiTunnel(PmsiTunnel<'a>),
    TunnelEncapAttr(TunnelEncapAttr<'a>),
    TrafficEngineering(TrafficEngineering<'a>),
    Ipv6AddrSpecificExtCommunity(Ipv6AddrSpecificExtCommunity<'a>),
    Aigp(Aigp<'a>),
    PeDistinguisherLabels(PeDistinguisherLabels<'a>),
    BgpLs(BgpLs<'a>),
    AttrSet(AttrSet<'a>),
    Other(Other<'a>),
}

impl<'a> PathAttr<'a> {

    #[cfg_attr(feature="clippy", allow(match_same_arms))]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<PathAttr<'a>> {
        if bytes.len() < 3 { return Err(BgpError::BadLength);}

        let attr_flags = bytes[0];
        let attr_type  = bytes[1];
        let is_extended = attr_flags & FLAG_EXT_LEN > 0;

        if is_extended && bytes.len() < 4 { return Err(BgpError::BadLength);}

        let attr_len = if is_extended {
            (bytes[2] as u16) << 8
                | bytes[3] as u16
        } else {
            bytes[2] as u16
        };

        match (attr_type, attr_len) {
            ( 0, _) => Err(BgpError::Invalid),
            ( 1, 1) => Ok(PathAttr::Origin(Origin{inner: bytes})),
            ( 1, _) => Err(BgpError::Invalid),
            ( 2, _) => Ok(PathAttr::AsPath(AsPath{inner: bytes})),
            ( 3, _) => Ok(PathAttr::NextHop(NextHop{inner: bytes})),
            ( 4, 4) => Ok(PathAttr::MultiExitDisc(MultiExitDisc{inner: bytes})),
            ( 4, _) => Err(BgpError::Invalid),
            ( 5, 4) => Ok(PathAttr::LocalPreference(LocalPreference{inner: bytes})),
            ( 5, _) => Err(BgpError::Invalid),
            ( 6, 0) => Ok(PathAttr::AtomicAggregate(AtomicAggregate{inner: bytes})),
            ( 6, _) => Err(BgpError::Invalid),
            ( 7, 6) => Ok(PathAttr::Aggregator(Aggregator{inner: bytes})),
            ( 7, _) => Err(BgpError::Invalid),
            ( 8, _) => Ok(PathAttr::Community(Community{inner: bytes})),
            ( 9, 4) => Ok(PathAttr::OriginatorId(OriginatorId{inner: bytes})),
            ( 9, _) => Err(BgpError::Invalid),
            (10, _) => Ok(PathAttr::ClusterList(ClusterList{inner: bytes})),
            (14, _) => Ok(PathAttr::MpReachNlri(MpReachNlri{inner: bytes})),
            (15, _) => Ok(PathAttr::MpUnreachNlri(MpUnreachNlri{inner: bytes})),
            (16, _) => Ok(PathAttr::ExtendedCommunities(ExtendedCommunities{inner: bytes})),
            (17, _) => Ok(PathAttr::As4Path(As4Path{inner: bytes})),
            (18, _) => Ok(PathAttr::As4Aggregator(As4Aggregator{inner: bytes})),
            (22, _) => Ok(PathAttr::PmsiTunnel(PmsiTunnel{inner: bytes})),
            (23, _) => Ok(PathAttr::TunnelEncapAttr(TunnelEncapAttr{inner: bytes})),
            (24, _) => Ok(PathAttr::TrafficEngineering(TrafficEngineering{inner: bytes})),
            (25, _) => Ok(PathAttr::Ipv6AddrSpecificExtCommunity(Ipv6AddrSpecificExtCommunity{inner: bytes})),
            (26, _) => Ok(PathAttr::Aigp(Aigp{inner: bytes})),
            (27, _) => Ok(PathAttr::PeDistinguisherLabels(PeDistinguisherLabels{inner: bytes})),
            (29, _) => Ok(PathAttr::BgpLs(BgpLs{inner: bytes})),
            (128,_) => Ok(PathAttr::AttrSet(AttrSet{inner: bytes})),
            _ => Ok(PathAttr::Other(Other{inner: bytes})),
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

        Some(PathAttr::from_bytes(slice))
    }
}


pub trait Attr {

    fn flags(&self) -> u8;
    fn code(&self) -> u8;
    fn value(&self) -> &[u8];

    fn is_optional(&self) ->   bool { self.flags() & FLAG_OPTIONAL > 0 }
    fn is_partial(&self) ->    bool { self.flags() & FLAG_PARTIAL > 0 }
    fn is_transitive(&self) -> bool { self.flags() & FLAG_TRANSITIVE > 0 }
    fn is_ext_len(&self) ->    bool { self.flags() & FLAG_EXT_LEN > 0 }
}


macro_rules! define_path_attr {

    ($name:ident, $doc:expr) => {
        #[derive(Debug)]
        #[doc=$doc]
        pub struct $name<'a> {
            inner: &'a [u8],
        }

        impl<'a> Attr for $name<'a> {
            fn flags(&self) -> u8 {
                self.inner[0]
            }

            fn code(&self) -> u8 {
                self.inner[0]
            }

            fn value(&self) -> &[u8] {
                if self.is_ext_len() {
                    &self.inner[4..]
                } else {
                    &self.inner[3..]
                }
            }
        }
    }
}

define_path_attr!(Origin,
                  "The ORIGIN attribute is generated by the speaker that originates the associated routing information.
                  ORIGIN is a well-known mandatory attribute.");

define_path_attr!(AsPath,
                  "This attribute identifies the autonomous systems through which routing information
                   carried in this UPDATE message has passed.

                   The components of this list can be AS_SETs or AS_SEQUENCEs.
                   AS_PATH is a well-known mandatory attribute.");

define_path_attr!(NextHop,
                  "The NEXT_HOP is a well-known mandatory attribute that defines the IP
                   address of the router that SHOULD be used as the next hop to the
                   destinations listed in the UPDATE message.");

define_path_attr!(MultiExitDisc,
                  "The MULTI_EXIT_DISC is an optional non-transitive attribute that is
                   intended to be used on external (inter-AS) links to discriminate
                   among multiple exit or entry points to the same neighboring AS.");

define_path_attr!(LocalPreference,
                  "LOCAL_PREF is a well-known attribute that SHALL be included in all
                   UPDATE messages that a given BGP speaker sends to other internal
                   peers.

                   A BGP speaker SHALL calculate the degree of preference for
                   each external route based on the locally-configured policy, and
                   include the degree of preference when advertising a route to its
                   internal peers.  The higher degree of preference MUST be preferred.");

define_path_attr!(AtomicAggregate,
                  "ATOMIC_AGGREGATE is a well-known discretionary
                   attribute.
 
                   When a BGP speaker aggregates several routes for the purpose of
                   advertisement to a particular peer, the AS_PATH of the aggregated
                   route normally includes an AS_SET formed from the set of ASes from
                   which the aggregate was formed.  In many cases, the network
                   administrator can determine if the aggregate can safely be advertised
                   without the AS_SET, and without forming route loops.");

define_path_attr!(Aggregator,
                  "AGGREGATOR is an optional transitive attribute, which MAY be included
                  in updates that are formed by aggregation (see Section 9.2.2.2).  A
                  BGP speaker that performs route aggregation MAY add the AGGREGATOR
                  attribute, which SHALL contain its own AS number and IP address.  The
                  IP address SHOULD be the same as the BGP Identifier of the speaker.");

define_path_attr!(Community,"BGP Community Attribute.");
define_path_attr!(OriginatorId,"");
define_path_attr!(ClusterList,"");
define_path_attr!(MpReachNlri,"");
define_path_attr!(MpUnreachNlri,"");
define_path_attr!(ExtendedCommunities,"");
define_path_attr!(As4Path,"");
define_path_attr!(As4Aggregator,"");
define_path_attr!(PmsiTunnel,"");
define_path_attr!(TunnelEncapAttr,"");
define_path_attr!(TrafficEngineering,"");
define_path_attr!(Ipv6AddrSpecificExtCommunity,"");
define_path_attr!(Aigp,"");
define_path_attr!(PeDistinguisherLabels,"");
define_path_attr!(BgpLs,"");
define_path_attr!(AttrSet,"");
define_path_attr!(Other,"");

impl<'a> AsPath<'a> {

    pub fn segments(&self, four_byte: bool) -> AsPathIter {
        AsPathIter{
            inner: self.value(),
            error: None,
            four_byte: four_byte,
        }
    }
}

impl<'a> As4Path<'a> {

    pub fn segments(&self) -> AsPathIter {
        AsPathIter{
            inner: self.value(),
            error: None,
            four_byte: true,
        }
    }
}

#[cfg_attr(feature="clippy", allow(enum_variant_names))]
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
        let segment_type = self.inner[0];
        let ret = match segment_type {
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

impl<'a> ClusterList<'a> {
    pub fn ids(&self) -> ClusterListIter {
        ClusterListIter{
            inner: &self.value(),
            error: None,
        }
    }
}

pub struct ClusterListIter<'a> {
    inner: &'a [u8],
    error: Option<BgpError>,
}

impl<'a> Iterator for ClusterListIter<'a> {
    type Item = Result<u32>;

    fn next(&mut self) -> Option<Result<u32>> {
        if self.error.is_some() {
            return None;
        }
        if self.inner.len() == 0 {
            return None;
        }

        if self.inner.len() < 4 {
            let err = BgpError::BadLength;
            self.error = Some(err);
            return Some(Err(err));
        }

        let id = (self.inner[0]  as u32) << 24
            | (self.inner[1]  as u32) << 16
            | (self.inner[2]  as u32) << 8
            | (self.inner[3]  as u32);

        self.inner = &self.inner[4..];

        Some(Ok(id))
    }
}

macro_rules! impl_as_segment {

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

impl_as_segment!(AsSet, AsSetIter, "AS_SET: unordered set of ASes a route in the UPDATE message has traversed");
impl_as_segment!(AsSequence, AsSequenceIter, "AS_SEQUENCE: ordered set of ASes a route in the UPDATE message has traversed");


#[derive(PartialEq,Debug)]
pub enum OriginType {
    /// Network Layer Reachability Information is interior to the originating AS
    Igp,
    /// Network Layer Reachability Information learned via the EGP protocol [RFC904]
    Egp,
    /// Network Layer Reachability Information learned by some other means
    Incomplete,
    Unknown,
}

impl<'a> Origin<'a> {

    pub fn origin(&self) -> OriginType {
        match self.value()[0] {
            0 => OriginType::Igp,
            1 => OriginType::Egp,
            2 => OriginType::Incomplete,
            _ => OriginType::Unknown,
        }
    }
}

impl<'a> Aggregator<'a> {

    /// The last AS number that formed the aggregate route
    pub fn aut_num(&self) -> u32 {
        (self.value()[0] as u32) << 8
            | self.value()[1] as u32
    }

    /// The IP address of the BGP speaker that formed the aggregate route
    /// (encoded as 4 octets).  This SHOULD be the same address as
    /// the one used for the BGP Identifier of the speaker.
    pub fn ident(&self) -> u32 {
        (self.value()[2] as u32) << 24
            | (self.value()[3] as u32) << 16
            | (self.value()[4] as u32) << 8
            |  self.value()[5] as u32
    }
}

impl<'a> NextHop<'a> {
    pub fn ip(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            | (self.value()[3] as u32)
    }
}

impl<'a> MultiExitDisc<'a> {
    pub fn med(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            | (self.value()[3] as u32)
    }
}

impl<'a> LocalPreference<'a> {
    pub fn preference(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            | (self.value()[3] as u32)
    }
}

impl<'a> OriginatorId<'a> {
    pub fn ident(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            |  self.value()[3] as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_as_set() {
        let four_byte_asn = false;
        let bytes = &[0x40, 0x02, 0x0a, 0x02, 0x01, 0x00, 0x1e, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x14];
        let as_path = AsPath{inner: bytes};
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
