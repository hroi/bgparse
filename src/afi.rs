use core::fmt;

#[derive(PartialEq, Clone, Copy)]
pub struct Afi(u16);

/// IP version 4
pub const AFI_IPV4: Afi = Afi(1);
/// IP version 6
pub const AFI_IPV6: Afi = Afi(2);
/// L2VPN
pub const AFI_L2VPN: Afi = Afi(25);
/// Multi-Topology IPv4
pub const AFI_MT_IPV4: Afi = Afi(29);
/// Multi-Topology IPv6
pub const AFI_MT_IPV6: Afi = Afi(30);
/// BGP Link-State and TE Information
pub const AFI_BGP_LS: Afi = Afi(16388);

impl From<u16> for Afi {
    fn from(other: u16) -> Afi {
        Afi(other)
    }
}

impl fmt::Debug for Afi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1 => write!(f, "ipv4"),
            2 => write!(f, "ipv6"),
            n => write!(f, "unknown({})", n),
        }
    }
}
