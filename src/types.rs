pub use core::result;
use core::fmt;

pub const VALID_BGP_MARKER: [u8; 16] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

#[derive(PartialEq)]
pub struct Prefix<'a> {
    pub inner: &'a [u8],
}

impl<'a> fmt::Debug for Prefix<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let masklen = self.inner[0];
        if masklen == 0 {
            return fmt.write_str("0/0");
        }

        let mut print_period = false;
        for octet in &self.inner[1..] {
            if print_period {
                try!(fmt.write_str("."));
            }
            print_period = true;
            try!(octet.fmt(fmt));
        }
        try!(fmt.write_str("/"));
        masklen.fmt(fmt)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BgpError {
    BadLength,
    Invalid,
}

pub type Result<T> = result::Result<T, BgpError>;

impl fmt::Display for BgpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}


#[derive(PartialEq, Clone, Copy)]
pub struct Afi(u16);

pub const AFI_IPV4: Afi = Afi(1);
pub const AFI_IPV6: Afi = Afi(2);

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

/// Network Layer Reachability Information used for unicast forwarding [RFC4760]
pub const SAFI_UNICAST: Safi = Safi(1);
/// 2    Network Layer Reachability Information used for multicast forwarding              [RFC4760]
pub const SAFI_MULTICAST: Safi = Safi(2);
// 3    Reserved                                                                          [RFC4760]
/// 4    Network Layer Reachability Information (NLRI) with MPLS Labels                    [RFC3107]
pub const SAFI_MPLS_LABEL: Safi = Safi(4);
/// 5    MCAST-VPN                                                                         [RFC6514]
pub const SAFI_MCAST_VPN: Safi = Safi(5);
/// 6    Network Layer Reachability Information used for Dynamic Placement of              [RFC7267]
pub const SAFI_MULTISEGMENT_PW: Safi = Safi(6);
/// 7    Encapsulation SAFI                                                                [RFC5512]
pub const SAFI_ENCAP: Safi = Safi(7);
/// 8    MCAST-VPLS                                                                        [RFC7117]
pub const SAFI_MCAST_VPLS: Safi = Safi(8);
// 9-63   Unassigned
/// 64    Tunnel SAFI [Gargi_Nalawade][draft-nalawade-kapoor-tunnel-safi-01]
pub const SAFI_TUNNEL: Safi = Safi(64);
/// 65    Virtual Private LAN Service (VPLS)                                                [RFC4761][RFC6074]
pub const SAFI_VPLS: Safi = Safi(65);
/// 66    BGP MDT SAFI                                                                      [RFC6037]
pub const SAFI_MDT: Safi = Safi(66);
/// 67    BGP 4over6 SAFI                                                                   [RFC5747]
pub const SAFI_4OVER6: Safi = Safi(67);
/// 68    BGP 6over4 SAFI                                                                   [Yong_Cui]
pub const SAFI_6OVER4: Safi = Safi(68);
/// 69    Layer-1 VPN auto-discovery information                                            [RFC5195]
pub const SAFI_L1_AUTODISC: Safi = Safi(69);
/// 70    BGP EVPNs                                                                         [RFC7432]
pub const SAFI_EVPN: Safi = Safi(70);
/// 71    BGP-LS                                                                            [RFC-ietf-idr-ls-distribution-13]
pub const SAFI_LS: Safi = Safi(71);
/// 72    BGP-LS-VPN                                                                        [RFC-ietf-idr-ls-distribution-13]
pub const SAFI_LS_VPN: Safi = Safi(72);
// 73-127  Unassigned
/// 128   MPLS-labeled VPN address                                                          [RFC4364]
pub const SAFI_MPLS_LABELED_VPN_ADDR: Safi = Safi(128);
/// 129   Multicast for BGP/MPLS IP Virtual Private Networks (VPNs)                         [RFC6513][RFC6514]
pub const SAFI_MPLS_IP_VPN: Safi = Safi(129);

// 130-131 Reserved                                                                          [RFC4760]
/// 132   Route Target constrains                                                           [RFC4684]
pub const SAFI_RT_CONSTRAINT: Safi = Safi(132);
/// 133   IPv4 dissemination of flow specification rules                                    [RFC5575]
pub const SAFI_IPV4_FLOWSPEC: Safi = Safi(133);
/// 134   VPNv4 dissemination of flow specification rules                                   [RFC5575]
pub const SAFI_VPNV4_FLOWSPEC: Safi = Safi(134);
// 135-139 Reserved                                                                          [RFC4760]
/// 140   VPN auto-discovery                                                                [draft-ietf-l3vpn-bgpvpn-auto]
pub const SAFI_VPNV_AUTODISC: Safi = Safi(134);
// 141-240 Reserved                                                                          [RFC4760]
// 241-254 Reserved for Private Use                                                          [RFC4760]
// 255   Reserved                                                                          [RFC4760]


#[derive(PartialEq, Clone, Copy)]
pub struct Safi(u8);

impl From<u8> for Safi {
    fn from(other: u8) -> Safi {
        Safi(other)
    }
}

impl fmt::Debug for Safi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            1 => write!(f, "unicast"),
            2 => write!(f, "multicast"),
            n => write!(f, "unknown({})", n),
        }
    }
}
