pub mod open;
pub mod update;

use types::*;
use self::open::*;
use self::update::*;

#[derive(Debug)]
pub enum Message<'a> {
    Open(Open<'a>),
    Update(Update<'a>),
    Notification,
    KeepAlive,
    Refresh,
}


impl<'a> Message<'a> {
    pub fn from_bytes(raw: &'a [u8]) -> Result<Message> {
        if raw.len() < 19 || raw.len() > 4096 {
            return Err(BgpError::BadLength);
        }
        let (marker, message) = raw.split_at(16);
        if marker != VALID_BGP_MARKER {
            return Err(BgpError::Invalid);
        }
        let (length, msg_type) = message[..3].split_at(2);
        let length = (length[0] as u16) << 8 | (length[1] as u16);
        if length as usize != raw.len() {
            return Err(BgpError::BadLength);
        }
        match msg_type[0] {
            1 => Ok(Message::Open(try!(Open::new(&message[3..])))),
            2 => Ok(Message::Update(try!(Update::new(&message[3..])))),
            3 => Ok(Message::Notification),
            4 => Ok(Message::KeepAlive),
            5 => Ok(Message::Refresh),
            _ => Err(BgpError::Invalid),
        }
    }
}
