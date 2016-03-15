use types::*;
use core::fmt;

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

#[derive(Debug)]
pub enum PathAttr<'a> {
    Origin(Origin<'a>),
    AsPath(AsPath<'a>),
    NextHop(NextHop<'a>),
    MultiExitDisc(MultiExitDisc<'a>),
    LocalPreference(LocalPreference<'a>),
    AtomicAggregate(AtomicAggregate<'a>),
    Aggregator(Aggregator<'a>),
    Communities(Communities<'a>),
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
    pub fn from_bytes(bytes: &'a [u8], four_byte_asn: bool) -> Result<PathAttr<'a>> {
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
            ( 2, _) if four_byte_asn => Ok(PathAttr::As4Path(As4Path{inner: bytes})),
            ( 2, _) => Ok(PathAttr::AsPath(AsPath{inner: bytes})),
            ( 3, _) => Ok(PathAttr::NextHop(NextHop{inner: bytes})),
            ( 4, 4) => Ok(PathAttr::MultiExitDisc(MultiExitDisc{inner: bytes})),
            ( 4, _) => Err(BgpError::Invalid),
            ( 5, 4) => Ok(PathAttr::LocalPreference(LocalPreference{inner: bytes})),
            ( 5, _) => Err(BgpError::Invalid),
            ( 6, 0) => Ok(PathAttr::AtomicAggregate(AtomicAggregate{inner: bytes})),
            ( 6, _) => Err(BgpError::Invalid),
            ( 7, 8) if four_byte_asn => Ok(PathAttr::As4Aggregator(As4Aggregator{inner: bytes})),
            ( 7, 6) if !four_byte_asn => Ok(PathAttr::Aggregator(Aggregator{inner: bytes})),
            ( 7, _) => Err(BgpError::Invalid),
            ( 8, _) => Ok(PathAttr::Communities(Communities{inner: bytes})),
            ( 9, 4) => Ok(PathAttr::OriginatorId(OriginatorId{inner: bytes})),
            ( 9, _) => Err(BgpError::Invalid),
            (10, _) => Ok(PathAttr::ClusterList(ClusterList{inner: bytes})),
            (14, _) => Ok(PathAttr::MpReachNlri(try!(MpReachNlri::from_bytes(bytes)))),
            (15, _) => Ok(PathAttr::MpUnreachNlri(try!(MpUnreachNlri::from_bytes(bytes)))),
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

#[derive(Clone)]
pub struct PathAttrIter<'a> {
    inner: &'a [u8],
    error: bool,
    four_byte_asn: bool,
}

impl<'a> fmt::Debug for PathAttrIter<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_list().entries(self.clone()).finish()
    }
}

impl<'a> PathAttrIter<'a> {

    pub fn new(inner: &'a [u8], four_byte_asn: bool) -> PathAttrIter<'a> {
        PathAttrIter {
            inner: inner,
            error: false,
            four_byte_asn: four_byte_asn,
        }
    }
}

impl<'a> Iterator for PathAttrIter<'a> {
    type Item = Result<PathAttr<'a>>;

    fn next(&mut self) -> Option<Result<PathAttr<'a>>> {
        if self.error || self.inner.is_empty() {
            return None;
        }

        if self.inner.len() < 2 {
            self.error = true;
            return Some(Err(BgpError::BadLength));
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
            self.error = true;
            return Some(Err(BgpError::BadLength));
        }

        let next_offset = attr_value_offset + attr_len;
        let slice = &self.inner[..next_offset];
        self.inner = &self.inner[next_offset..];

        Some(PathAttr::from_bytes(slice, self.four_byte_asn))
    }
}


pub trait Attr<'a> {

    fn flags(&self) -> u8;
    fn code(&self) -> u8;
    fn value(&self) -> &'a [u8];

    fn is_optional(&self) ->   bool { self.flags() & FLAG_OPTIONAL > 0 }
    fn is_partial(&self) ->    bool { self.flags() & FLAG_PARTIAL > 0 }
    fn is_transitive(&self) -> bool { self.flags() & FLAG_TRANSITIVE > 0 }
    fn is_ext_len(&self) ->    bool { self.flags() & FLAG_EXT_LEN > 0 }
}


macro_rules! define_path_attr {

    ($name:ident, $( $m:meta ),*) => {
        $( #[$m] )*
        pub struct $name<'a> {
            inner: &'a [u8],
        }

        impl<'a> Attr<'a> for $name<'a> {
            fn flags(&self) -> u8 {
                self.inner[0]
            }

            fn code(&self) -> u8 {
                self.inner[0]
            }

            fn value(&self) -> &'a [u8] {
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
                  doc="The ORIGIN attribute is generated by the speaker that originates the associated routing information.
                  ORIGIN is a well-known mandatory attribute.");

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


impl<'a> fmt::Debug for Origin<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.origin().fmt(fmt)
    }
}

define_path_attr!(AsPath,
                  doc="This attribute identifies the autonomous systems through which routing information
                   carried in this UPDATE message has passed.

                   The components of this list can be AS_SETs or AS_SEQUENCEs.
                   AS_PATH is a well-known mandatory attribute.");

impl<'a> AsPath<'a> {

    pub fn segments(&self) -> AsPathIter {
        AsPathIter{
            inner: self.value(),
            error: false,
            four_byte: false,
        }
    }
}

impl<'a> fmt::Debug for AsPath<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.segments().fmt(fmt)
    }
}

#[cfg_attr(feature="clippy", allow(enum_variant_names))]
#[derive(Clone,Debug)]
pub enum AsPathSegment<'a> {
    AsSequence(AsSequence<'a>),
    AsSet(AsSet<'a>),
}

#[derive(Clone)]
pub struct AsPathIter<'a> {
    inner: &'a [u8],
    error: bool,
    four_byte: bool,
}

impl<'a> fmt::Debug for AsPathIter<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        for segment in self.clone() {
            match segment {
               Ok(AsPathSegment::AsSet(x)) => {&x.aut_nums().fmt(fmt);}
               Ok(AsPathSegment::AsSequence(x)) => {&x.aut_nums().fmt(fmt);}
               x => {&x.fmt(fmt);}
            };
        }
        Ok(())
    }
}

impl<'a> Iterator for AsPathIter<'a> {

    type Item = Result<AsPathSegment<'a>>;

    fn next(&mut self) -> Option<Result<AsPathSegment<'a>>> {
        if self.error || self.inner.is_empty() {
            return None;
        }

        let as_size = if self.four_byte { 4 } else { 2 };
        let segment_type = self.inner[0];
        let ret = match segment_type {
            1 => {
                let len = self.inner[1] as usize;
                let slice = &self.inner[2..(len*as_size) + 2];
                self.inner = &self.inner[(len*as_size) + 2..];
                Ok(AsPathSegment::AsSet(AsSet{inner: slice, four_byte: self.four_byte}))
            }
            2 => {
                let len = self.inner[1] as usize;
                let slice = &self.inner[2..(len*as_size) + 2];
                self.inner = &self.inner[(len*as_size) + 2..];
                Ok(AsPathSegment::AsSequence(AsSequence{inner: slice, four_byte: self.four_byte}))
            }
            _ => {
                self.error = true;
                Err(BgpError::Invalid)
            }
        };
        Some(ret)
    }
}

macro_rules! impl_as_path_segment {

    ($coll:ident, $iter:ident, $doc:expr) => {

        #[derive(PartialEq,Debug,Clone)]
        #[doc=$doc]
        pub struct $coll<'a> {
            inner: &'a [u8],
            four_byte: bool,
        }

        impl<'a> $coll<'a> {

            pub fn aut_nums(&self) -> Result<$iter> {
                let as_size = if self.four_byte { 4 } else { 2 };
                if self.inner.len() % as_size > 0 {
                    return Err(BgpError::BadLength);
                }
                Ok($iter{ inner: self.inner, error: false, four_byte: self.four_byte })
            }
        }

        #[derive(Clone)]
        pub struct $iter<'a> {
            inner: &'a [u8],
            error: bool,
            four_byte: bool,
        }

        impl<'a> fmt::Debug for $iter<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.debug_list().entries(self.clone()).finish()
            }
        }

        impl<'a> Iterator for $iter<'a> {
            type Item = u32;

            fn next(&mut self) -> Option<u32> {
                if self.error || self.inner.is_empty() {
                    return None;
                }

                let as_size = if self.four_byte { 4 } else { 2 };

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
                Some(asn)
            }
        }
    }
}

impl_as_path_segment!(AsSet, AsSetIter,
                      "AS_SET: unordered set of ASes a route in the UPDATE message has traversed");
impl_as_path_segment!(AsSequence, AsSequenceIter,
                      "AS_SEQUENCE: ordered set of ASes a route in the UPDATE message has traversed");

define_path_attr!(NextHop,
                  doc="The NEXT_HOP is a well-known mandatory attribute that defines the IP
                   address of the router that SHOULD be used as the next hop to the
                   destinations listed in the UPDATE message.");

impl<'a> NextHop<'a> {
    pub fn ip(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            | (self.value()[3] as u32)
    }
}

impl<'a> fmt::Debug for NextHop<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("{}.{}.{}.{}",
                                   self.value()[0], self.value()[1],
                                   self.value()[2], self.value()[3], ))
    }
}

define_path_attr!(MultiExitDisc,
                  doc="The MULTI_EXIT_DISC is an optional non-transitive attribute that is
                   intended to be used on external (inter-AS) links to discriminate
                   among multiple exit or entry points to the same neighboring AS.");

impl<'a> MultiExitDisc<'a> {
    pub fn med(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            | (self.value()[3] as u32)
    }
}

impl<'a> fmt::Debug for MultiExitDisc<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.med().fmt(fmt)
    }
}

define_path_attr!(LocalPreference,
                  doc="LOCAL_PREF is a well-known attribute that SHALL be included in all
                   UPDATE messages that a given BGP speaker sends to other internal
                   peers.

                   A BGP speaker SHALL calculate the degree of preference for
                   each external route based on the locally-configured policy, and
                   include the degree of preference when advertising a route to its
                   internal peers.  The higher degree of preference MUST be preferred.");

impl<'a> LocalPreference<'a> {
    pub fn preference(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            | (self.value()[3] as u32)
    }
}

impl<'a> fmt::Debug for LocalPreference<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.preference().fmt(fmt)
    }
}

define_path_attr!(AtomicAggregate,
                  doc="ATOMIC_AGGREGATE is a well-known discretionary
                   attribute.

                   When a BGP speaker aggregates several routes for the purpose of
                   advertisement to a particular peer, the AS_PATH of the aggregated
                   route normally includes an AS_SET formed from the set of ASes from
                   which the aggregate was formed.  In many cases, the network
                   administrator can determine if the aggregate can safely be advertised
                   without the AS_SET, and without forming route loops.");

impl<'a> fmt::Debug for AtomicAggregate<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("AtomicAggregate").finish()
    }
}


define_path_attr!(Aggregator,
                  doc="AGGREGATOR is an optional transitive attribute, which MAY be included
                  in updates that are formed by aggregation (see Section 9.2.2.2).  A
                  BGP speaker that performs route aggregation MAY add the AGGREGATOR
                  attribute, which SHALL contain its own AS number and IP address.  The
                  IP address SHOULD be the same as the BGP Identifier of he speaker.");

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

impl<'a> fmt::Debug for Aggregator<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("AS{}, {}.{}.{}.{}", self.aut_num(),
                                   self.value()[2], self.value()[3],
                                   self.value()[4], self.value()[5],))
    }
}

define_path_attr!(Communities, doc="BGP Community Attribute.");

impl<'a> Communities<'a> {
    pub fn communities(&self) -> Result<CommunityIter> {
        let slice = self.value();
        if slice.len() % 4 > 0 {
            Err(BgpError::BadLength)
        } else {
            Ok(CommunityIter {
                inner: slice,
            })
        }
    }
}

impl<'a> fmt::Debug for Communities<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.communities().fmt(fmt)
    }
}

pub struct Community<'a> {
    inner: &'a [u8],
}

impl<'a> fmt::Debug for Community<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let left = (self.inner[0] as u16) << 8
            | self.inner[1] as u16;
        let right = (self.inner[2] as u16) << 8
            | self.inner[3] as u16;
        fmt.write_fmt(format_args!("{}:{}", left, right))
    }
}


#[derive(Clone)]
pub struct CommunityIter<'a> {
    inner: &'a [u8],
}

impl<'a> Iterator for CommunityIter<'a> {
    type Item = Community<'a>;

    fn next(&mut self) -> Option<Community<'a>> {
        if self.inner.is_empty() { return None;}
        let community = Community{inner: &self.inner[..4]};
        self.inner = &self.inner[4..];
        Some(community)
    }
}

impl<'a> fmt::Debug for CommunityIter<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_list().entries(self.clone()).finish()
    }
}

define_path_attr!(OriginatorId, derive(Debug), doc="BGP Route Reflection");

impl<'a> OriginatorId<'a> {
    pub fn ident(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            |  self.value()[3] as u32
    }
}

define_path_attr!(ClusterList, derive(Debug), doc="BGP Route Reflection");

impl<'a> ClusterList<'a> {
    pub fn ids(&self) -> ClusterListIter {
        ClusterListIter{
            inner: &self.value(),
            error: false,
        }
    }
}

pub struct ClusterListIter<'a> {
    inner: &'a [u8],
    error: bool,
}

impl<'a> Iterator for ClusterListIter<'a> {
    type Item = Result<u32>;

    fn next(&mut self) -> Option<Result<u32>> {
        if self.error || self.inner.is_empty() {
            return None;
        }

        if self.inner.len() < 4 {
            self.error = true;
            return Some(Err(BgpError::BadLength));
        }

        let id
            = (self.inner[0]  as u32) << 24
            | (self.inner[1]  as u32) << 16
            | (self.inner[2]  as u32) << 8
            | (self.inner[3]  as u32);

        self.inner = &self.inner[4..];

        Some(Ok(id))
    }
}

mod mp_reach_nlri;
pub use self::mp_reach_nlri::*;


define_path_attr!(ExtendedCommunities, doc="Extended Communities Attribute");

impl<'a> ExtendedCommunities<'a> {
    pub fn communities(&self) -> Result<ExtendedCommunityIter<'a>> {
        if self.value().len() % 8 == 0 {
            Ok(ExtendedCommunityIter {
                inner: self.value(),
            })
        } else {
            Err(BgpError::BadLength)
        }
    }
}

impl<'a> fmt::Debug for ExtendedCommunities<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.clone().communities() {
            Ok(iter) => fmt.debug_list().entries(iter).finish(),
            Err(err) => err.fmt(fmt)
        }
    }
}

pub trait ExtendedComm<'a> {
    fn type_high(&self) -> u8;
    fn type_low(&self) -> u8;
    fn value(&self) -> &'a [u8];
}

macro_rules! define_ext_comm {
    ($comm_name:ident) => {
        pub struct $comm_name<'a> {
            inner: &'a [u8],
        }

        impl<'a> ExtendedComm<'a> for $comm_name<'a> {
            fn type_high(&self) -> u8 {
                self.inner[0]
            }

            fn type_low(&self) -> u8 {
                self.inner[1]
            }

            fn value(&self) -> &'a [u8] {
                &self.inner[2..]
            }
        }

        impl<'a> fmt::Debug for $comm_name<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.write_str(stringify!($comm_name))
            }
        }
    }
}

define_ext_comm!(ExtCommTwoOctetAsSpecific);
define_ext_comm!(ExtCommIpv4AddrSpecific);
define_ext_comm!(ExtCommFourOctetAsSpecific);
define_ext_comm!(ExtCommOpaque);
define_ext_comm!(ExtCommRouteTarget);
define_ext_comm!(ExtCommRouteOrigin);
define_ext_comm!(ExtCommQosMarking);
define_ext_comm!(ExtCommCosCapability);
define_ext_comm!(ExtCommEvpn);
define_ext_comm!(ExtCommFlowSpec);
define_ext_comm!(ExtCommExperimental);
define_ext_comm!(ExtCommOther);

#[derive(Debug)]
pub enum ExtendedCommunity<'a> {
    TwoOctetAsSpecific(ExtCommTwoOctetAsSpecific<'a>),
    Ipv4AddrSpecific(ExtCommIpv4AddrSpecific<'a>),
    FourOctetAsSpecific(ExtCommFourOctetAsSpecific<'a>),
    Opaque(ExtCommOpaque<'a>),
    RouteTarget(ExtCommRouteTarget<'a>),
    RouteOrigin(ExtCommRouteOrigin<'a>),
    QosMarking(ExtCommQosMarking<'a>),
    CosCapability(ExtCommCosCapability<'a>),
    Evpn(ExtCommEvpn<'a>),
    FlowSpec(ExtCommFlowSpec<'a>),
    Experimental(ExtCommExperimental<'a>),
    Other(ExtCommOther<'a>),
}


pub struct ExtendedCommunityIter<'a> {
    inner: &'a [u8],
}

impl<'a> Iterator for ExtendedCommunityIter<'a> {
    type Item = ExtendedCommunity<'a>;

    fn next(&mut self) -> Option<ExtendedCommunity<'a>> {
        if self.inner.is_empty() {
            return None;
        }

        let slice = &self.inner[..8];
        self.inner = &self.inner[8..];

        let extcomm_type = slice[0];
        let extcomm_subtype = slice[1];
        let ret = match (extcomm_type, extcomm_subtype) {
            (0, 2) => ExtendedCommunity::RouteTarget(ExtCommRouteTarget{inner: &self.inner}),
            (0, 3) => ExtendedCommunity::RouteOrigin(ExtCommRouteOrigin{inner: &self.inner}),
            (0, _) => ExtendedCommunity::TwoOctetAsSpecific(ExtCommTwoOctetAsSpecific{inner: &self.inner}),
            (1, _) => ExtendedCommunity::Ipv4AddrSpecific(ExtCommIpv4AddrSpecific{inner: &self.inner}),
            (2, 2) => ExtendedCommunity::RouteTarget(ExtCommRouteTarget{inner: &self.inner}),
            (2, 3) => ExtendedCommunity::RouteOrigin(ExtCommRouteOrigin{inner: &self.inner}),
            (2, _) => ExtendedCommunity::FourOctetAsSpecific(ExtCommFourOctetAsSpecific{inner: &self.inner}),
            (3, _) => ExtendedCommunity::Opaque(ExtCommOpaque{inner: &self.inner}),
            (4, _) => ExtendedCommunity::QosMarking(ExtCommQosMarking{inner: &self.inner}),
            (5, _) => ExtendedCommunity::CosCapability(ExtCommCosCapability{inner: &self.inner}),
            (6, _) => ExtendedCommunity::Evpn(ExtCommEvpn{inner: &self.inner}),
            (8, _) => ExtendedCommunity::FlowSpec(ExtCommFlowSpec{inner: &self.inner}),
            (0x80...0x8f, _) => ExtendedCommunity::Experimental(ExtCommExperimental{inner: &self.inner}),
            (_, _) => ExtendedCommunity::Other(ExtCommOther{inner: &self.inner}),
            
        };
        Some(ret)
    }
}

define_path_attr!(As4Path, doc="AsPath with four-byte-asns");

impl<'a> As4Path<'a> {

    pub fn segments(&self) -> AsPathIter {
        AsPathIter{
            inner: self.value(),
            error: false,
            four_byte: true,
        }
    }
}

impl<'a> fmt::Debug for As4Path<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.segments().fmt(fmt)
    }
}

define_path_attr!(As4Aggregator, doc="Four-byte ASN version of Aggregator");

impl<'a> As4Aggregator<'a> {

    /// The last AS number that formed the aggregate route
    pub fn aut_num(&self) -> u32 {
        (self.value()[0] as u32) << 24
            | (self.value()[1] as u32) << 16
            | (self.value()[2] as u32) << 8
            | self.value()[3] as u32
    }

    /// The IP address of the BGP speaker that formed the aggregate route
    /// (encoded as 4 octets).  This SHOULD be the same address as
    /// the one used for the BGP Identifier of the speaker.
    pub fn ident(&self) -> u32 {
        (self.value()[4] as u32) << 24
            | (self.value()[5] as u32) << 16
            | (self.value()[6] as u32) << 8
            | self.value()[7] as u32
    }
}

impl<'a> fmt::Debug for As4Aggregator<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("AS{}, {}.{}.{}.{}", self.aut_num(),
                                   self.value()[4], self.value()[5],
                                   self.value()[6], self.value()[7],))
    }
}

define_path_attr!(PmsiTunnel, derive(Debug), doc="");
define_path_attr!(TunnelEncapAttr, derive(Debug), doc="");
define_path_attr!(TrafficEngineering, derive(Debug), doc="");
define_path_attr!(Ipv6AddrSpecificExtCommunity, derive(Debug), doc="");
define_path_attr!(Aigp, derive(Debug), doc="The Accumulated IGP Metric Attribute");
define_path_attr!(PeDistinguisherLabels, derive(Debug), doc="");
define_path_attr!(BgpLs, derive(Debug), doc="North-Bound Distribution of Link-State and TE Information");
define_path_attr!(AttrSet, derive(Debug), doc="");
define_path_attr!(Other, derive(Debug), doc="");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_as_set() {
        let bytes = &[0x40, 0x02, 0x0a, 0x02, 0x01, 0x00, 0x1e, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x14];
        let as_path = AsPath{inner: bytes};
        let mut segments = as_path.segments();
        match segments.next() {
            Some(Ok(AsPathSegment::AsSequence(seq))) => {
                let mut asns = seq.aut_nums().unwrap();
                assert_eq!(asns.next().unwrap(), 30);
                let next = asns.next();
                assert!(next.is_none(), "expected None, got {:?}", next);
            },
            _ => panic!("expected AS_SEQUENCE")
        }
        match segments.next() {
            Some(Ok(AsPathSegment::AsSet(set))) => {
                let mut asns = set.aut_nums().unwrap();
                assert_eq!(asns.next().unwrap(), 10);
                assert_eq!(asns.next().unwrap(), 20);
                assert!(asns.next().is_none());
            }
            _ => panic!("expected AS_SET")
        }
        assert!(segments.next().is_none());
    }

}
