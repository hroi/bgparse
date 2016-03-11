//! BGP Monitoring Protocol

use bgp;
use types::*;

#[derive(Debug)]
pub struct PerPeer<'a> {
    inner: &'a [u8],
}

impl<'a> PerPeer<'a> {
    pub fn peer_type(&self) -> u8 {
        self.inner[0]
    }

    fn peer_flags(&self) -> u8 {
        self.inner[1]
    }

    pub fn flag_ipv6(&self) -> bool {
        self.peer_flags() & BMP_FLAG_IPV6 > 0
    }

    pub fn flag_l(&self) -> bool {
        self.peer_flags() & BMP_FLAG_L > 0
    }

    pub fn flag_legacy_asn(&self) -> bool {
        self.peer_flags() & BMP_FLAG_LEGACY_AS > 0
    }

    pub fn peer_distinguisher(&self) -> &'a[u8] {
        &self.inner[2..10]
    }

    pub fn peer_address(&self) -> &'a [u8] {
        &self.inner[10..26]
    }

    pub fn peer_as(&self) -> u32 {
        (self.inner[26] as u32) << 24
        | (self.inner[27] as u32) << 16
        | (self.inner[28] as u32) << 8
        | (self.inner[29] as u32)
    }

    pub fn peer_id(&self) -> u32 {
        (self.inner[30] as u32) << 24
        | (self.inner[31] as u32) << 16
        | (self.inner[32] as u32) << 8
        | (self.inner[33] as u32)
    }

    pub fn timestamp(&self) -> (u32, u32) {
        let seconds
            = (self.inner[34] as u32) << 24
            | (self.inner[35] as u32) << 16
            | (self.inner[36] as u32) << 8
            | (self.inner[37] as u32);
        let micros
            = (self.inner[38] as u32) << 24
            | (self.inner[39] as u32) << 16
            | (self.inner[40] as u32) << 8
            | (self.inner[41] as u32);
        (seconds, micros)
    }

}

#[derive(Debug)]
pub struct MessageIter<'a> {
    inner: &'a [u8],
    four_byte_asn: bool,
    add_path: bool,
    error: bool,
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = Result<bgp::Message<'a>>;

    fn next(&mut self) -> Option<Result<bgp::Message<'a>>> {
        if self.inner.is_empty() || self.error {
            return None;
        }

        if self.inner.len() < 19 {
            self.error = true;
            return Some(Err(BgpError::BadLength));
        }

        let message_len  = (self.inner[16] as usize) << 8 | (self.inner[17] as usize);
        if self.inner.len() < message_len {
            self.error = true;
            return Some(Err(BgpError::BadLength));
        }

        let slice = &self.inner[..message_len];
        self.inner = &self.inner[message_len..];

        Some(bgp::Message::from_bytes(slice,
                                      self.four_byte_asn,
                                      self.add_path))
    }
}
pub trait PeerInfo {
    fn peer_info(&self) -> PerPeer;
}

pub trait Messages {
    fn messages(&self, four_byte_asn: bool, add_path: bool) -> MessageIter;
}

macro_rules! def_bmptype {
    ($bmptype:ident) => {
        #[derive(PartialEq,Debug)]
        pub struct $bmptype<'a> {
            inner: &'a [u8],
        }
    };
    ($bmptype:ident PeerInfo) => {
        impl<'a> PeerInfo for $bmptype<'a> {
            fn peer_info(&self) -> PerPeer {
                PerPeer {
                    inner: &self.inner[6..6+42],
                }
            }
        }
    };
    ($bmptype:ident (Messages $offset:expr) ) => {
        impl<'a> Messages for $bmptype<'a> {
            fn messages(&self, four_byte_asn: bool, add_path: bool) -> MessageIter {
                MessageIter {
                    inner: &self.inner[$offset..],
                    four_byte_asn: four_byte_asn,
                    add_path: add_path,
                    error: false,
                }
            }
        }
    };
    ($bmptype:ident, $( $tok:tt ),*) => {
        def_bmptype!($bmptype);
        $( def_bmptype!( $bmptype $tok ); )*
    };
}

def_bmptype!(RouteMonitoring, PeerInfo, (Messages 48+20));
def_bmptype!(StatisticsReport, PeerInfo);
def_bmptype!(PeerDownNotification);
def_bmptype!(PeerUpNotification, PeerInfo, (Messages 48+20));
def_bmptype!(Initiation);
def_bmptype!(Termination);
def_bmptype!(RouteMirroring, PeerInfo, (Messages 48+20));

#[derive(Debug)]
pub enum Bmp<'a> {
    /// Route Monitoring (RM): Used to provide an initial dump of all
    /// routes received from a peer as well as an ongoing mechanism that
    /// sends the incremental routes advertised and withdrawn by a peer to
    /// the monitoring station.
    RouteMonitoring(RouteMonitoring<'a>),
    /// Stats Reports (SR): An ongoing dump of statistics that can be used
    /// by the monitoring station as a high level indication of the
    /// activity going on in the router.
    StatisticsReport(StatisticsReport<'a>),
    PeerDownNotification(PeerDownNotification<'a>),
    /// Peer Up Notification: A message sent to indicate a peering session
    /// has come up.  The message includes information regarding the data
    /// exchanged between the peers in their OPEN messages as well as
    /// information about the peering TCP session itself.  In addition to
    /// being sent whenever a peer transitions to ESTABLISHED state, a
    /// Peer Up Notification is sent for each peer in ESTABLISHED state
    /// when the BMP session itself comes up.
    PeerUpNotification(PeerUpNotification<'a>),
    /// Initiation: A means for the monitored router to inform the
    /// monitoring station of its vendor, software version, and so on.
    Initiation(Initiation<'a>),
    /// Termination: A means for the monitored router to inform the
    /// monitoring station of why it is closing a BMP session.
    Termination(Termination<'a>),
    /// Route Mirroring: a means for the monitored router to send verbatim
    /// duplicates of messages as received.  Can be used to exactly mirror
    /// a monitored BGP session.  Can also be used to report malformed BGP
    /// PDUs.
    RouteMirroring(RouteMirroring<'a>),
}

pub const BMP_MSG_ROUTEMON:    u8 = 0;
pub const BMP_MSG_STATREPORT:  u8 = 1;
pub const BMP_MSG_PEERDOWN:    u8 = 2;
pub const BMP_MSG_PEERUP:      u8 = 3;
pub const BMP_MSG_INIT:        u8 = 4;
pub const BMP_MSG_TERM:        u8 = 5;
pub const BMP_MSG_ROUTEMIRROR: u8 = 6;

pub const BMP_PEER_GLOBAL:     u8 = 0;
pub const BMP_PEER_RD:         u8 = 1;
pub const BMP_PEER_LOCAL:      u8 = 2;

/// The V flag indicates the the Peer address is an IPv6 address.
/// For IPv4 peers this is set to 0.
pub const BMP_FLAG_IPV6:       u8 = 0b10000000;
/// The L flag, if set to 1, indicates the message reflects the
/// post-policy Adj-RIB-In (i.e., its path attributes reflect the
/// application of inbound policy).  It is set to 0 if the message
/// reflects the pre-policy Adj-RIB-In.  Locally-sourced routes
/// also carry an L flag of 1.  See Section 5 for further detail.
/// This flag has no significance when used with route mirroring
/// messages (Section 4.7).
pub const BMP_FLAG_L:          u8 = 0b01000000;
/// The A flag, if set to 1, indicates the message is formatted
/// using the legacy two-byte AS_PATH format.  If set to 0, the
/// message is formatted using the four-byte AS_PATH format
/// [RFC6793].  A BMP speaker MAY choose to propagate the AS_PATH
/// information as received from its peer, or it MAY choose to
/// reformat all AS_PATH information into four-byte format
/// regardless of how it was received from the peer.  In the latter
/// case, AS4_PATH or AS4_AGGREGATOR path attributes SHOULD NOT be
/// sent in the BMP UPDATE message.  This flag has no significance
/// when used with route mirroring messages (Section 4.7).
pub const BMP_FLAG_LEGACY_AS:  u8 = 0b00100000;

impl<'a> Bmp<'a> {

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Bmp<'a>> {
        if bytes.len() < 6 {
            return Err(BgpError::BadLength)
        }

        let version = bytes[0];
        if version != 3 {
            return Err(BgpError::Invalid)
        }

        let message_length
            = (bytes[1] as usize) << 24
            | (bytes[2] as usize) << 16
            | (bytes[3] as usize) << 8
            | bytes[4] as usize;
        if bytes.len() != message_length {
            return Err(BgpError::BadLength);
        }

        let bmp_type = bytes[5];
        match bmp_type{
            BMP_MSG_ROUTEMON    => Ok(Bmp::RouteMonitoring(RouteMonitoring{inner: bytes})),
            BMP_MSG_STATREPORT  => Ok(Bmp::StatisticsReport(StatisticsReport{inner: bytes})),
            BMP_MSG_PEERDOWN    => Ok(Bmp::PeerDownNotification(PeerDownNotification{inner: bytes})),
            BMP_MSG_PEERUP      => Ok(Bmp::PeerUpNotification(PeerUpNotification{inner: bytes})),
            BMP_MSG_INIT        => Ok(Bmp::Initiation(Initiation{inner: bytes})),
            BMP_MSG_TERM        => Ok(Bmp::Termination(Termination{inner: bytes})),
            BMP_MSG_ROUTEMIRROR => Ok(Bmp::RouteMirroring(RouteMirroring{inner: bytes})),
            _ => Err(BgpError::Invalid)
        }
    }

}

#[cfg(test)]
mod test {

    use super::*;
    use bgp;

    #[test]
    fn parse_peer_up() {
        let bytes = &[0x03, // version = 3
                      0x00, 0x00, 0x00, 0xba, // length = 186
                      0x03, // type = open
                      // start per peer header
                      0x00, // peer type = Global Instance Peer
                      0x00, // peer flags
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // peer disinguisher 0:0
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // peer address
                      0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65, // peer address cont.. = 10.255.0.101
                      0x00, 0x00, 0x80, 0xa6, // asn = 32934
                      0x0a, 0x0a, 0x0a, 0x01, // peer bgp id
                      0x54, 0xa2, 0x0e, 0x0b, // timestamp seconds
                      0x00, 0x0e, 0x0c, 0x20, // timestamp microseconds
                      // end per peer
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // local address
                      0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x53, // local address cont.. = 10.255.0.83
                      0x90, 0x6e, // local port
                      0x00, 0xb3, // remote port
                      // begin messages
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0x00, 0x3b, 0x01, 0x04, 0x00, 0x64, 0x00, 0xb4,
                      0x0a, 0x0a, 0x0a, 0x67, 0x1e, 0x02, 0x06, 0x01,
                      0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80,
                      0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x06, 0x41,
                      0x04, 0x00, 0x00, 0x00, 0x64, 0x02, 0x04, 0x40,
                      0x02, 0x00, 0x78,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0x00, 0x3b, 0x01, 0x04, 0x80, 0xa6, 0x00, 0x5a,
                      0x0a, 0x0a, 0x0a, 0x01, 0x1e, 0x02, 0x06, 0x01,
                      0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80,
                      0x00, 0x02, 0x02, 0x02, 0x00, 0x02, 0x04, 0x40,
                      0x02, 0x00, 0x78, 0x02, 0x06, 0x41, 0x04, 0x00,
                      0x00, 0x80, 0xa6, ];
        let bmp = Bmp::from_bytes(bytes).unwrap();
        match bmp {
            Bmp::PeerUpNotification(peerup) => {
                let peer_info = peerup.peer_info();
                assert_eq!(peer_info.flag_ipv6(), false);
                assert_eq!(peer_info.flag_l(), false);
                assert_eq!(peer_info.flag_legacy_asn(), false);

                assert_eq!(peer_info.peer_distinguisher(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ]);
                assert_eq!(peer_info.peer_address(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                       0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x00, 0x65,]);
                assert_eq!(peer_info.peer_as(), 32934);
                assert_eq!(peer_info.peer_id(), 0x0a0a0a01);

                assert_eq!(peer_info.timestamp(), (0x54a20e0b, 0x000e0c20));

                let mut messages = peerup.messages(false, false);
                match messages.next().unwrap() {
                    Ok(bgp::Message::Open(open)) => {
                        assert_eq!(open.aut_num(), 100);
                    }
                    x => panic!("Expected Message::Open, got {:?}", x)
                }
                match messages.next().unwrap() {
                    Ok(bgp::Message::Open(open)) => {
                        assert_eq!(open.aut_num(),32934);
                    }
                    x => panic!("Expected Message::Open, got {:?}", x)
                }
                assert!(messages.next().is_none());
            },
            foobar => panic!("expected {}, got {:?}", stringify!(Bmp::PeerUpNotification), foobar)
        }
    }

}
