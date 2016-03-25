//! A NOTIFICATION message is sent when an error condition is detected.
//! The BGP connection is closed immediately after it is sent.

use types::*;

#[derive(Debug)]
pub enum Notification<'a> {
    // message header errors
    /// The expected value of the Marker field of the message header is all
    /// ones.  If the Marker field of the message header is not as expected,
    /// then a synchronization error has occurred and the Error Subcode MUST
    /// be set to Connection Not Synchronized.
    ConnectionNotSynchronised(&'a [u8]),
    /// If at least one of the following is true:
    ///
    /// - if the Length field of the message header is less than 19 or
    /// greater than 4096, or
    ///
    /// - if the Length field of an OPEN message is less than the minimum
    /// length of the OPEN message, or
    ///
    /// - if the Length field of an UPDATE message is less than the
    /// minimum length of the UPDATE message, or
    ///
    /// - if the Length field of a KEEPALIVE message is not equal to 19, or
    ///
    /// - if the Length field of a NOTIFICATION message is less than the
    /// minimum length of the NOTIFICATION message,
    ///
    /// then the Error Subcode MUST be set to Bad Message Length.  The Data
    /// field MUST contain the erroneous Length field.
    BadMessageLength(&'a [u8]),
    /// If the Type field of the message header is not recognized, then the
    /// Error Subcode MUST be set to Bad Message Type.  The Data field MUST
    /// contain the erroneous Type field.
    BadMessageType(&'a [u8]),

    // open message errors
    /// If the version number in the Version field of the received OPEN
    /// message is not supported, then the Error Subcode MUST be set to
    /// Unsupported Version Number.  The Data field is a 2-octet unsigned
    /// integer, which indicates the largest, locally-supported version
    /// number less than the version the remote BGP peer bid (as indicated in
    /// the received OPEN message), or if the smallest, locally-supported
    /// version number is greater than the version the remote BGP peer bid,
    /// then the smallest, locally-supported version number.
    UnsupportedVersionNumber(&'a [u8]),
    /// If the Autonomous System field of the OPEN message is unacceptable,
    /// then the Error Subcode MUST be set to Bad Peer AS.  The determination
    /// of acceptable Autonomous System numbers is outside the scope of this
    /// protocol.
    BadPeerAs(&'a [u8]),
    /// If the BGP Identifier field of the OPEN message is syntactically
    /// incorrect, then the Error Subcode MUST be set to Bad BGP Identifier.
    /// Syntactic correctness means that the BGP Identifier field represents
    /// a valid unicast IP host address.
    BadBgpIdentifier(&'a [u8]),
    /// If one of the Optional Parameters in the OPEN message is not
    /// recognized, then the Error Subcode MUST be set to Unsupported
    /// Optional Parameters.
    UnsupportedOptionalParameter(&'a [u8]),
    /// Deprecated
    AuthenticationFailure(&'a [u8]), // deprecated
    /// If the Hold Time field of the OPEN message is unacceptable, then the
    /// Error Subcode MUST be set to Unacceptable Hold Time.  An
    /// implementation MUST reject Hold Time values of one or two seconds.
    /// An implementation MAY reject any proposed Hold Time.  An
    /// implementation that accepts a Hold Time MUST use the negotiated value
    /// for the Hold Time.
    UnacceptableHoldTime(&'a [u8]),

    // update message errors
    /// Error checking of an UPDATE message begins by examining the path
    /// attributes.  If the Withdrawn Routes Length or Total Attribute Length
    /// is too large (i.e., if Withdrawn Routes Length + Total Attribute
    /// Length + 23 exceeds the message Length), then the Error Subcode MUST
    /// be set to Malformed Attribute List.
    ///
    /// If an optional attribute is recognized, then the value of this
    /// attribute MUST be checked.  If an error is detected, the attribute
    /// MUST be discarded, and the Error Subcode MUST be set to Optional
    /// Attribute Error.  The Data field MUST contain the attribute (type,
    ///                                                              length, and value).
    ///
    /// If any attribute appears more than once in the UPDATE message, then
    /// the Error Subcode MUST be set to Malformed Attribute List.
    MalformedAttributeList(&'a [u8]),
    /// If any of the well-known mandatory attributes are not recognized,
    /// then the Error Subcode MUST be set to Unrecognized Well-known
    /// Attribute.  The Data field MUST contain the unrecognized attribute
    /// (type, length, and value).
    UnrecognizedWellKnownAttribute(&'a [u8]),
    /// If any of the well-known mandatory attributes are not present, then
    /// the Error Subcode MUST be set to Missing Well-known Attribute.  The
    /// Data field MUST contain the Attribute Type Code of the missing,
    /// well-known attribute.
    MissingWellKnownAttribute(&'a [u8]),
    /// If any recognized attribute has Attribute Flags that conflict with
    /// the Attribute Type Code, then the Error Subcode MUST be set to
    /// Attribute Flags Error.  The Data field MUST contain the erroneous
    /// attribute (type, length, and value).
    AttributeFlagsError(&'a [u8]),
    /// If any recognized attribute has an Attribute Length that conflicts
    /// with the expected length (based on the attribute type code), then the
    /// Error Subcode MUST be set to Attribute Length Error.  The Data field
    /// MUST contain the erroneous attribute (type, length, and value).
    AttributeLengthError(&'a [u8]),
    /// If the ORIGIN attribute has an undefined value, then the Error Sub-
    /// code MUST be set to Invalid Origin Attribute.  The Data field MUST
    /// contain the unrecognized attribute (type, length, and value).
    InvalidOriginAttribute(&'a [u8]),
    /// Deprecated
    AsRoutingLoop(&'a [u8]), // deprecated
    /// If the NEXT_HOP attribute field is syntactically incorrect, then the
    /// Error Subcode MUST be set to Invalid NEXT_HOP Attribute.  The Data
    /// field MUST contain the incorrect attribute (type, length, and value).
    /// Syntactic correctness means that the NEXT_HOP attribute represents a
    /// valid IP host address.
    ///
    /// The IP address in the NEXT_HOP MUST meet the following criteria to be
    /// considered semantically correct:
    ///
    ///  a) It MUST NOT be the IP address of the receiving speaker.
    ///
    ///  b) In the case of an EBGP, where the sender and receiver are one
    ///     IP hop away from each other, either the IP address in the
    ///     NEXT_HOP MUST be the sender's IP address that is used to
    ///     establish the BGP connection, or the interface associated with
    ///     the NEXT_HOP IP address MUST share a common subnet with the
    ///     receiving BGP speaker.
    ///
    /// If the NEXT_HOP attribute is semantically incorrect, the error SHOULD
    /// be logged, and the route SHOULD be ignored.  In this case, a
    /// NOTIFICATION message SHOULD NOT be sent, and the connection SHOULD
    /// NOT be closed.
    InvalidNextHopAttribute(&'a [u8]),
    /// If an optional attribute is recognized, then the value of this
    /// attribute MUST be checked.  If an error is detected, the attribute
    /// MUST be discarded, and the Error Subcode MUST be set to Optional
    /// Attribute Error.  The Data field MUST contain the attribute (type,
    /// length, and value).
    OptionalAttributeError(&'a [u8]),
    /// The NLRI field in the UPDATE message is checked for syntactic
    /// validity.  If the field is syntactically incorrect, then the Error
    /// Subcode MUST be set to Invalid Network Field.
    ///
    /// If a prefix in the NLRI field is semantically incorrect (e.g., an
    /// unexpected multicast IP address), an error SHOULD be logged locally,
    /// and the prefix SHOULD be ignored.
    InvalidNetworkField(&'a [u8]),
    /// The AS_PATH attribute is checked for syntactic correctness.  If the
    /// path is syntactically incorrect, then the Error Subcode MUST be set
    /// to Malformed AS_PATH.
    /// If the UPDATE message is received from an external peer, the local
    /// system MAY check whether the leftmost (with respect to the position
    /// of octets in the protocol message) AS in the AS_PATH attribute is
    /// equal to the autonomous system number of the peer that sent the
    /// message.  If the check determines this is not the case, the Error
    /// Subcode MUST be set to Malformed AS_PATH.
    MalformedAsPath(&'a [u8]),
    /// If a system does not receive successive KEEPALIVE, UPDATE, and/or
    /// NOTIFICATION messages within the period specified in the Hold Time
    /// field of the OPEN message, then the NOTIFICATION message with the
    /// Hold Timer Expired Error Code is sent and the BGP connection is
    /// closed.
    HoldTimerExpired(&'a [u8]),
    /// Any error detected by the BGP Finite State Machine (e.g., receipt of
    /// an unexpected event) is indicated by sending the NOTIFICATION message
    /// with the Error Code Finite State Machine Error.
    FiniteStateMachineError(&'a [u8]),
    /// In the absence of any fatal errors (that are indicated in this
    /// section), a BGP peer MAY choose, at any given time, to close its BGP
    /// connection by sending the NOTIFICATION message with the Error Code
    /// Cease.  However, the Cease NOTIFICATION message MUST NOT be used when
    /// a fatal error indicated by this section does exist.
    ///
    /// A BGP speaker MAY support the ability to impose a locally-configured,
    /// upper bound on the number of address prefixes the speaker is willing
    /// to accept from a neighbor.  When the upper bound is reached, the
    /// speaker, under control of local configuration, either (a) discards
    /// new address prefixes from the neighbor (while maintaining the BGP
    /// connection with the neighbor), or (b) terminates the BGP connection
    /// with the neighbor.  If the BGP speaker decides to terminate its BGP
    /// connection with a neighbor because the number of address prefixes
    /// received from the neighbor exceeds the locally-configured, upper
    /// bound, then the speaker MUST send the neighbor a NOTIFICATION message
    /// with the Error Code Cease.  The speaker MAY also log this locally.
    Cease(&'a [u8]),
}

impl<'a> Notification<'a> {

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Notification<'a>> {
        if bytes.len() < 2 {
            return Err(BgpError::BadLength);
        }

        let error_code = bytes[0];
        let error_subcode = bytes[1];
        let data = &bytes[2..];

        let notification = match (error_code, error_subcode) {
            (1,1) => Notification::ConnectionNotSynchronised(data),
            (1,2) => Notification::BadMessageLength(data),
            (1,3) => Notification::BadMessageType(data),

            (2,1) => Notification::UnsupportedVersionNumber(data),
            (2,2) => Notification::BadPeerAs(data),
            (2,3) => Notification::BadBgpIdentifier(data),
            (2,4) => Notification::UnsupportedOptionalParameter(data),
            (2,5) => Notification::AuthenticationFailure(data),
            (2,6) => Notification::UnacceptableHoldTime(data),

            (3,1) => Notification::MalformedAttributeList(data),
            (3,2) => Notification::UnrecognizedWellKnownAttribute(data),
            (3,3) => Notification::MissingWellKnownAttribute(data),
            (3,4) => Notification::AttributeFlagsError(data),
            (3,5) => Notification::AttributeLengthError(data),
            (3,6) => Notification::InvalidOriginAttribute(data),
            (3,7) => Notification::AsRoutingLoop(data),
            (3,8) => Notification::InvalidNextHopAttribute(data),
            (3,9) => Notification::OptionalAttributeError(data),
            (3,10) => Notification::InvalidNetworkField(data),
            (3,11) => Notification::MalformedAsPath(data),

            (4,_) => Notification::HoldTimerExpired(data),
            (5,_) => Notification::FiniteStateMachineError(data),
            (6,_) => Notification::Cease(data),
            _ => return Err(BgpError::Invalid),
        };
        Ok(notification)
    }
}
