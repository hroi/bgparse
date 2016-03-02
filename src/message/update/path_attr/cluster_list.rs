use types::*;

/// Cluster-list is a new optional, non-transitive BGP attribute of Type
/// code 10. It is a sequence of CLUSTER_ID values representing the
/// reflection path that the route has passed.
#[derive(PartialEq, Debug)]
pub struct ClusterList<'a> {
    pub inner: &'a [u8],
}

impl<'a> ClusterList<'a> {
    pub fn new(inner: &'a [u8]) -> ClusterList {
        ClusterList{inner: inner}
    }

    pub fn ids(&self) -> ClusterListIter {
        ClusterListIter{
            inner: self.inner,
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

