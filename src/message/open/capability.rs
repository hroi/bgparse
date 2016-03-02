use types::*;
use core::fmt;

pub struct AddPathDirection(u8);

impl From<u8> for AddPathDirection {
    fn from(other: u8) -> AddPathDirection {
        AddPathDirection(other)
    }
}

impl fmt::Debug for AddPathDirection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1 => write!(f, "receive"),
            2 => write!(f, "send"),
            3 => write!(f, "both"),
            n => write!(f, "unknown({})", n),
        }
    }
}

#[derive(Debug)]
pub struct Capability<'a> {
    pub inner: &'a [u8],
}

#[derive(Debug)]
pub enum CapabilityType {
    Reserved,
    MultiProtocol(Afi, Safi),
    RouteRefresh,
    Orf,
    MultipleRoutes,
    ExtendedNextHopEncoding,
    GracefulRestart,
    FourByteASN(u32),
    DynamicCapability,
    MultiSession,
    AddPath(Afi, Safi, AddPathDirection),
    EnhancedRouteRefresh,
    Private(u8),
    Other(u8),
}

impl<'a> Capability<'a> {
    pub fn new(inner: &'a [u8]) -> Capability {
        Capability { inner: inner }
    }

    pub fn capability_type(&self) -> CapabilityType {
        match self.inner[0] {
            0 => CapabilityType::Reserved,
            1 => {
                CapabilityType::MultiProtocol(Afi::from((self.inner[2] as u16) << 8 |
                                                        (self.inner[3] as u16)),
                                              Safi::from(self.inner[5]))
            }
            2 => CapabilityType::RouteRefresh,
            3 => CapabilityType::Orf,
            4 => CapabilityType::MultipleRoutes,
            5 => CapabilityType::ExtendedNextHopEncoding,
            64 => CapabilityType::GracefulRestart,
            65 => CapabilityType::FourByteASN((self.inner[2] as u32) << 24
                                              | (self.inner[3] as u32) << 16
                                              | (self.inner[4] as u32) <<  8
                                              | self.inner[5] as u32),
            67 => CapabilityType::DynamicCapability,
            68 => CapabilityType::MultiSession,
            69 => {
                CapabilityType::AddPath(Afi::from((self.inner[2] as u16) << 8 |
                                                  (self.inner[3] as u16)),
                                        Safi::from(self.inner[4]),
                                        AddPathDirection::from(self.inner[5]))
            }
            70 => CapabilityType::EnhancedRouteRefresh,
            n @ 128...255 => CapabilityType::Private(n),
            n => CapabilityType::Other(n),
        }
    }
}
