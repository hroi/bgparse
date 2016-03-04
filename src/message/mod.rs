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

        let message_len  = (message[0] as usize) << 8 | (message[1] as usize);
        let message_type = message[2];

        if message_len != raw.len() {
            return Err(BgpError::BadLength);
        }
        match message_type {
            1 => Ok(Message::Open(try!(Open::from_bytes(raw)))),
            2 => Ok(Message::Update(try!(Update::from_bytes(raw)))),
            3 => Ok(Message::Notification),
            4 => Ok(Message::KeepAlive),
            5 => Ok(Message::Refresh),
            _ => Err(BgpError::Invalid),
        }
    }
}
