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

// pub enum ParseResult<'a> {
//     Done(usize, Message<'a>),
//     Incomplete(usize),
//     Error(BgpError)
// }

impl<'a> Message<'a> {

    // pub fn parse(raw: &'a [u8]) -> ParseResult<'a> {
    //     if raw.len() < 19 {
    //         return ParseResult::Incomplete(19 - raw.len());
    //     }

    //     let (marker, message) = raw.split_at(16);

    //     if marker != VALID_BGP_MARKER {
    //         return ParseResult::Error(BgpError::Invalid);
    //     }

    //     let message_len  = (message[0] as usize) << 8 | (message[1] as usize);
    //     let message_type = message[2];

    //     if message_len > 4096 {
    //         return ParseResult::Error(BgpError::BadLength);
    //     }

    //     if raw.len() >= message_len {
    //         match message_type {
    //             1 => {
    //                 match Open::from_bytes(raw) {
    //                     Ok(open) =>
    //                         ParseResult::Done(message_len, Message::Open(open)),
    //                     Err(err) =>
    //                         ParseResult::Error(err)
    //                 }
    //             }
    //             2 => {
    //                 match Update::from_bytes(raw) {
    //                     Ok(open) =>
    //                         ParseResult::Done(message_len, Message::Update(open)),
    //                     Err(err) =>
    //                         ParseResult::Error(err)
    //                 }
    //             }
    //             3 => ParseResult::Done(message_len, Message::Notification),
    //             4 => ParseResult::Done(message_len, Message::KeepAlive),
    //             5 => ParseResult::Done(message_len, Message::Refresh),
    //             _ => ParseResult::Error(BgpError::Invalid),
    //         }
    //     } else {
    //         ParseResult::Incomplete(message_len - raw.len())
    //     }
    // }

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
