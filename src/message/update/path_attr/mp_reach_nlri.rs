use super::*;
use types::*;
use core::fmt;


/// Multi Protocol Network Layer Reachability Information
#[derive(Debug)]
pub enum MpReachNlri<'a> {
    Ipv4Unicast(Ipv4ReachNlri<'a>),
    Ipv4Multicast(Ipv4ReachNlri<'a>),
    Ipv6Unicast(Ipv6ReachNlri<'a>),
    Ipv6Multicast(Ipv6ReachNlri<'a>),
    Other(OtherReachNlri<'a>),
}

impl<'a> MpReachNlri<'a> {

    pub fn from_bytes(bytes: &'a [u8]) -> Result<MpReachNlri<'a>> {
        if bytes.len() < 4 {
            return Err(BgpError::BadLength);
        }

        let flags = bytes[0];
        let value = if flags & FLAG_EXT_LEN > 0 { &bytes[4..] } else { &bytes[3..]};

        let afi = Afi::from((value[0] as u16) << 8 | value[1] as u16);
        let safi = Safi::from(value[2]);
        let reach = match (afi, safi) {
            (AFI_IPV4, SAFI_UNICAST) => MpReachNlri::Ipv4Unicast(Ipv4ReachNlri{inner: value}),
            (AFI_IPV4, SAFI_MULTICAST) => MpReachNlri::Ipv4Multicast(Ipv4ReachNlri{inner: value}),
            (AFI_IPV6, SAFI_UNICAST) => MpReachNlri::Ipv6Unicast(Ipv6ReachNlri{inner: value}),
            (AFI_IPV6, SAFI_MULTICAST) => MpReachNlri::Ipv6Multicast(Ipv6ReachNlri{inner: value}),
            _ => MpReachNlri::Other(OtherReachNlri{inner: value}),
        };
        Ok(reach)
    }
}

macro_rules! impl_reach_ip_nlri {
    ($reach_nlri:ident, $nlri:ident, $nlri_iter:ident, $nexthop: ident, $prefix:ident) => {

        pub struct $reach_nlri<'a> {
            inner: &'a [u8],
        }

        pub struct $nlri<'a> {
            inner: &'a [u8],
        }

        #[derive(Clone)]
        pub struct $nlri_iter<'a> {
            inner: &'a [u8],
            error: bool,
        }

        pub struct $nexthop<'a> {
            inner: &'a [u8],
        }

        impl<'a> $nlri<'a> {
            pub fn prefix(&self) -> $prefix<'a> {
                $prefix{inner: self.inner}
            }
        }

        impl<'a> fmt::Debug for $nlri<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                self.prefix().fmt(fmt)
            }
        }

        impl<'a> $reach_nlri<'a> {

            fn nexthop_len(&self) -> usize {
                self.inner[3] as usize
            }

            pub fn nexthop(&self) -> $nexthop<'a> {
                $nexthop {
                    inner: &self.inner[4..][..self.nexthop_len()],
                }
            }

            pub fn nlris(&self) -> $nlri_iter<'a> {
                let offset = 2 + 1 + 1 + self.nexthop_len() + 1;
                $nlri_iter{inner: &self.inner[offset..], error: false}
            }
        }

        impl<'a> fmt::Debug for $reach_nlri<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.debug_struct(stringify!($reach_nlri))
                    .field("nexthop", &self.nexthop())
                    .field("nlris", &self.nlris())
                // .field("inner", &self.inner)
                    .finish()
            }
        }

        impl<'a> Iterator for $nlri_iter<'a> {
            type Item = Result<$nlri<'a>>;

            fn next(&mut self) -> Option<Result<$nlri<'a>>> {
                if self.error || self.inner.is_empty() {
                    return None;
                }

                let mask_len = self.inner[0] as usize;
                assert!(mask_len <= 128);
                let byte_len = (mask_len+15) / 8;
                if self.inner.len() < byte_len {
                    self.error = true;
                    return Some(Err(BgpError::BadLength));
                }
                let slice = &self.inner[..byte_len];
                let nlri = $nlri{inner: slice};
                self.inner = &self.inner[byte_len..];
                Some(Ok(nlri))
            }
        }

        impl<'a> fmt::Debug for $nlri_iter<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.debug_list().entries(self.clone()).finish()
            }
        }

    }
}

impl_reach_ip_nlri!(Ipv4ReachNlri, Ipv4Nlri, Ipv4NlriIter, Ipv4Nexthop, Ipv4Prefix);

impl<'a> fmt::Debug for Ipv4Nexthop<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_fmt(format_args!("{}.{}.{}.{}",
                                   self.inner[0], self.inner[1], self.inner[2], self.inner[3]))
    }
}

impl_reach_ip_nlri!(Ipv6ReachNlri, Ipv6Nlri, Ipv6NlriIter, Ipv6Nexthop, Ipv6Prefix);

impl<'a> fmt::Debug for Ipv6Nexthop<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        assert_eq!(self.inner.len(), 32);
        let (global, link_local) = self.inner.split_at(16);
        fmt.write_fmt(format_args!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}/{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                   global[0], global[1], global[2], global[3],
                                   global[4], global[5], global[6], global[7],
                                   global[8], global[9], global[10], global[11],
                                   global[12], global[13], global[14], global[15],

                                   link_local[0], link_local[1], link_local[2], link_local[3],
                                   link_local[4], link_local[5], link_local[6], link_local[7],
                                   link_local[8], link_local[9], link_local[10], link_local[11],
                                   link_local[12], link_local[13], link_local[14], link_local[15],
        ))
    }
}

#[derive(Debug)]
pub struct OtherReachNlri<'a> {
    inner: &'a [u8]
}


#[cfg(test)]
mod test {

    use super::*;
    use types::*;
    #[test]
    fn parse_mp_nlri_multicast() {
	      // path_attrs: [Origin(Igp),
        //              AsPath(Ok([3549, 3356, 137, 137, 137, 8978])),
        //              MultiExitDisc(13814),
        //              Communities(Ok([3549:2017, 3549:30840])),
        //              MpReachNlri(MpReachNlri {
        //                  nexthop: MpNextHop {
        //                      inner: [], afi: ipv4
        //                  },
        //                  nlris: Ipv4Multicast(193.43.128.19.212.77.0/22),
        //                  inner: [144, 14, 0, 17, 0, 1, 2, 4, 208, 51, 134, 246, 0, 22, 193, 43, 128, 19, 212, 77, 0] })]

        let bytes = &[//144,   // flags
                      //14,    // type
                      //0, 17, // length
                      // 0, 1,  // afi
                      // 2,     // safi
                      // 4,     // nexthop length
                      // 208, 51, 134, 246, // nexthop
                      // 0,     // reserved
                      22,    // prefixlength 1
                      193, 43, 128, // prefix 1
                      19,    // prefixlength 2
                      212, 77, 0 // prefix 2
        ];
        let mut iter = Ipv4NlriIter{inner: bytes, error: false};
        assert_eq!(iter.next().unwrap().unwrap().prefix(), Ipv4Prefix{inner: &[22, 193, 43, 128]});
        assert_eq!(iter.next().unwrap().unwrap().prefix(), Ipv4Prefix{inner: &[19, 212, 77, 0]});
        assert!(iter.next().is_none());
    }
}
