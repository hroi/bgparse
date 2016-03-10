//! When a BGP speaker [RFC4271] that supports capabilities advertisement
//! sends an OPEN message to its BGP peer, the message MAY include an
//! Optional Parameter, called Capabilities.  The parameter lists the
//! capabilities supported by the speaker.

use types::*;

#[derive(Debug)]
pub enum Capability<'a> {
    /// Multiprotocol Extensions. RFC 4760.
    MultiProtocol(MultiProtocol<'a>),
    /// Route Refresh Capability. RFC 2918.
    RouteRefresh(RouteRefresh<'a>),
    /// Outbound Route Filtering Capability. RFC 5291.
    Orf(Orf<'a>),
    /// Carrying Label Information. RFC 3107.
    MultipleRoutes(MultipleRoutes<'a>),
    /// Advertising IPv4 Network Layer Reachability Information with an IPv6 Next Hop. RFC 5549.
    ExtendedNextHopEncoding(ExtendedNextHopEncoding<'a>),
    /// Graceful Restart Mechanism. RFC 4724.
    GracefulRestart(GracefulRestart<'a>),
    /// BGP Support for Four-Octet Autonomous System (AS) Number Space. RFC 6793.
    FourByteASN(FourByteASN<'a>),
    /// Dynamic Capability. draft-ietf-idr-dynamic-cap.
    DynamicCapability(DynamicCapability<'a>),
    /// Multisession BGP. draft-ietf-idr-bgp-multisession.
    MultiSession(MultiSession<'a>),
    /// Advertisement of Multiple Paths in BGP. draft-ietf-idr-add-paths.
    AddPath(AddPath<'a>),
    /// Enhanced Route Refresh Capability. RFC 7313.
    EnhancedRouteRefresh(EnhancedRouteRefresh<'a>),
    /// Private use capability codes.
    Private(Private<'a>),
    /// Unassigned capability codes.
    Other(Other<'a>),
}

impl<'a> Capability<'a> {

    #[cfg_attr(feature="clippy", allow(match_same_arms))]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Capability<'a>> {
        if bytes.len() < 2 { return Err(BgpError::BadLength) }
        let capability_type = bytes[0];
        let capability_len  = bytes[1] as usize;
        if bytes.len() != capability_len + 2 {
            return Err(BgpError::BadLength);
        }
        let subslice = &bytes[..];
        match (capability_type, capability_len) {
            ( 0, _) => Err(BgpError::Invalid),
            ( 1, 4) => Ok(Capability::MultiProtocol(MultiProtocol{inner: subslice})),
            ( 1, _) => Err(BgpError::Invalid),
            ( 2, _) => Ok(Capability::RouteRefresh(RouteRefresh{inner: subslice})),
            ( 3, _) => Ok(Capability::Orf(Orf{inner: subslice})),
            ( 4, _) => Ok(Capability::MultipleRoutes(MultipleRoutes{inner: subslice})),
            ( 5, _) => Ok(Capability::ExtendedNextHopEncoding(ExtendedNextHopEncoding{inner: subslice})),
            (64, _) => Ok(Capability::GracefulRestart(GracefulRestart{inner: subslice})),
            (65, 4) => Ok(Capability::FourByteASN(FourByteASN{inner: subslice})),
            (65, _) => Err(BgpError::Invalid),
            (67, _) => Ok(Capability::DynamicCapability(DynamicCapability{inner: subslice})),
            (68, _) => Ok(Capability::MultiSession(MultiSession{inner: subslice})),
            (69, 4) => Ok(Capability::AddPath(AddPath{inner: subslice})),
            (69, _) => Err(BgpError::Invalid),
            (70, _) => Ok(Capability::EnhancedRouteRefresh(EnhancedRouteRefresh{inner: subslice})),
            (128...255, _) =>
                  Ok(Capability::Private(Private{inner: subslice})),
            __ => Ok(Capability::Other(Other{inner: subslice})),
        }
    }
}

pub trait CapabilityCode {
    fn code(&self) -> u8;
}

macro_rules! define_capability {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name<'a> {
            pub inner: &'a [u8],
        }

        impl<'a> CapabilityCode for $name<'a> {
            fn code(&self) -> u8 {
                self.inner[0]
            }
        }
    }
}

define_capability!(MultiProtocol);
define_capability!(RouteRefresh);
define_capability!(Orf);
define_capability!(MultipleRoutes);
define_capability!(ExtendedNextHopEncoding);
define_capability!(GracefulRestart);
define_capability!(FourByteASN);
define_capability!(DynamicCapability);
define_capability!(MultiSession);
define_capability!(AddPath);
define_capability!(EnhancedRouteRefresh);
define_capability!(Private);
define_capability!(Other);

impl<'a> MultiProtocol<'a> {
    pub fn afi(&self) -> Afi {
        Afi::from((self.inner[2] as u16) << 8 | self.inner[3] as u16)
    }

    pub fn safi(&self) -> Safi {
        Safi::from(self.inner[5])
    }
}

#[derive(Debug,PartialEq)]
pub struct AddPathDirection(u8);

pub const ADDPATH_DIRECTION_RECEIVE: AddPathDirection = AddPathDirection(1);
pub const ADDPATH_DIRECTION_SEND: AddPathDirection = AddPathDirection(2);
pub const ADDPATH_DIRECTION_BOTH: AddPathDirection = AddPathDirection(3);

impl<'a> AddPath<'a> {
    pub fn afi(&self) -> Afi {
        Afi::from((self.inner[2] as u16) << 8 | self.inner[3] as u16)
    }

    pub fn safi(&self) -> Safi {
        Safi::from(self.inner[4])
    }

    pub fn direction(&self) -> AddPathDirection {
        AddPathDirection(self.inner[5])
    }
}

impl<'a> FourByteASN<'a> {
    pub fn aut_num(&self) -> u32 {
        (self.inner[2] as u32) << 24
            | (self.inner[3] as u32) << 16
            | (self.inner[4] as u32) << 8
            | (self.inner[5] as u32)
    }
}
// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]


// }
