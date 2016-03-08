
use super::*;
use types::*;
use core::fmt;

define_path_attr!(MpReachNlri, doc="Multi Protocol Network Layer Reachability Information");

impl<'a> MpReachNlri<'a> {

    pub fn from_bytes(bytes: &'a [u8]) -> MpReachNlri {
        MpReachNlri {
            inner: bytes,
        }
    }

    fn afi(&self) -> Afi {
        Afi::from((self.value()[0] as u16) << 8 | self.value()[1] as u16)
    }

    fn safi(&self) -> Safi {
        Safi::from(self.value()[2])
    }

    fn nexthop_len(&self) -> usize {
        self.value()[3] as usize
    }

    pub fn nexthop(&self) -> MpNextHop<'a> {
        MpNextHop {
            inner: &self.value()[4..self.nexthop_len()],
            afi: self.afi(),
        }
    }

    pub fn nlris(&self) -> MpNlriIter<'a> {
        let offset = 2 + 1 + 1 + self.nexthop_len() + 1;
        match (self.afi(), self.safi()) {
            (AFI_IPV4, SAFI_UNICAST) =>
                MpNlriIter::Ipv4Unicast(Ipv4UnicastNlriIter{inner: &self.value()[offset..], error: false}),
            (AFI_IPV4, SAFI_MULTICAST) =>
                MpNlriIter::Ipv4Multicast(Ipv4MulticastNlriIter{inner: &self.value()[offset..], error: false}),
            (AFI_IPV6, SAFI_UNICAST) =>
                MpNlriIter::Ipv6Unicast(Ipv6UnicastNlriIter{inner: &self.value()[offset..], error: false}),
            (AFI_IPV6, SAFI_MULTICAST) =>
                MpNlriIter::Ipv6Multicast(Ipv6MulticastNlriIter{inner: &self.value()[offset..], error: false}),
            _ => MpNlriIter::Other(OtherNlriIter{inner: &self.value()[offset..], error: false}),
        }
    }
}

impl<'a> fmt::Debug for MpReachNlri<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("MpReachNlri")
            .field("nexthop", &self.nexthop())
            .field("nlris", &self.nlris())
            // .field("inner", &self.inner)
            .finish()
    }
}

#[derive(Debug)]
pub enum MpNlriIter<'a> {
    Ipv4Unicast(Ipv4UnicastNlriIter<'a>),
    Ipv6Unicast(Ipv6UnicastNlriIter<'a>),
    Ipv4Multicast(Ipv4MulticastNlriIter<'a>),
    Ipv6Multicast(Ipv6MulticastNlriIter<'a>),
    Other(OtherNlriIter<'a>)
}


#[derive(Debug)]
pub struct MpNextHop<'a> {
    inner: &'a [u8],
    afi: Afi,
}


macro_rules! impl_mp_nlri {
    ($item:ident, $iter:ident) => {

        #[derive(Clone)]
        pub struct $item<'a> {
            inner: &'a [u8],
        }

        impl<'a> fmt::Debug for $item<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                self.prefix().fmt(fmt)
            }
        }

        impl<'a> $item<'a> {
            pub fn prefix(&self) -> Prefix<'a> {
                Prefix{inner: self.inner}
            }
        }

        #[derive(Clone)]
        pub struct $iter<'a> {
            inner: &'a [u8],
            error: bool,
        }

        impl<'a> Iterator for $iter<'a> {
            type Item = Result<$item<'a>>;

            fn next(&mut self) -> Option<Result<$item<'a>>> {
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
                let nlri = $item{inner: slice};
                self.inner = &self.inner[byte_len..];
                Some(Ok(nlri))
            }
        }

        impl<'a> fmt::Debug for $iter<'a> {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.debug_list().entries(self.clone()).finish()
            }
        }

    }
}

impl_mp_nlri!(Ipv4UnicastNlri, Ipv4UnicastNlriIter);
impl_mp_nlri!(Ipv6UnicastNlri, Ipv6UnicastNlriIter);
impl_mp_nlri!(Ipv4MulticastNlri, Ipv4MulticastNlriIter);
impl_mp_nlri!(Ipv6MulticastNlri, Ipv6MulticastNlriIter);
impl_mp_nlri!(OtherNlri, OtherNlriIter);


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
        let mut iter = Ipv4MulticastNlriIter{inner: bytes, error: false};
        assert_eq!(iter.next().unwrap().unwrap().prefix(), Prefix{inner: &[22, 193, 43, 128]});
        assert_eq!(iter.next().unwrap().unwrap().prefix(), Prefix{inner: &[19, 212, 77, 0]});
        assert!(iter.next().is_none());
    }
}
