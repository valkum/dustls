use rustls::{
    internal::msgs::{base::Payload, enums::ContentType, message::MessageError},
    ProtocolVersion, Reader,
};

use crate::u48;

use super::message::{Message, MessagePayload};

// A TLS Frame sent over the wire, named DTLSCiphertext in the standard.
pub struct OpaqueMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub epoch: u16,
    pub seq: u48,
    pub payload: Payload,
}

impl OpaqueMessage {
    /// `MessageError` allows callers to distinguish between valid prefixes (might
    /// become valid if we read more data) and invalid data.
    pub fn read(r: &mut Reader) -> Result<Self, MessageError> {
        let typ = ContentType::read(r).ok_or(MessageError::TooShortForHeader)?;
        let version = ProtocolVersion::read(r).ok_or(MessageError::TooShortForHeader)?;
        let epoch = u16::read(r).ok_or(MessageError::TooShortForHeader)?;
        let seq = u48::read(r).ok_or(MessageError::TooShortForHeader)?;
        let len = u16::read(r).ok_or(MessageError::TooShortForHeader)?;

        // Reject undersize messages
        //  implemented per section 5.1 of RFC8446 (TLSv1.3)
        //              per section 6.2.1 of RFC5246 (TLSv1.2)
        if typ != ContentType::ApplicationData && len == 0 {
            return Err(MessageError::IllegalLength);
        }

        // Reject oversize messages
        if len >= Self::MAX_PAYLOAD {
            return Err(MessageError::IllegalLength);
        }

        // Don't accept any new content-types.
        if let ContentType::Unknown(_) = typ {
            return Err(MessageError::IllegalContentType);
        }

        // Accept only versions 0x03XX for any XX.
        match version {
            ProtocolVersion::Unknown(ref v) if (v & 0xff00) != 0x0300 => {
                return Err(MessageError::IllegalProtocolVersion);
            }
            _ => {}
        };

        let mut sub = r
            .sub(len as usize)
            .ok_or(MessageError::TooShortForLength)?;
        let payload = Payload::read(&mut sub);

        Ok(Self {
            typ,
            version,
            epoch,
            seq,
            payload,
        })
    }

    pub fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.typ.encode(&mut buf);
        self.version.encode(&mut buf);
        self.epoch.encode(&mut buf);
        self.seq.encode(&mut buf);
        (self.payload.0.len() as u16).encode(&mut buf);
        self.payload.encode(&mut buf);
        buf
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `OpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> PlainMessage {
        PlainMessage {
            version: self.version,
            typ: self.typ,
            epoch: self.epoch,
            seq: self.seq,
            payload: self.payload,
        }
    }

    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;

    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}

// This is not possbile as we need to inject epoch and seq.
// impl From<Message> for PlainMessage {
//     fn from(msg: Message) -> Self {
//         let typ = msg.payload.content_type();
//         let payload = match msg.payload {
//             MessagePayload::ApplicationData(payload) => payload,
//             _ => {
//                 let mut buf = Vec::new();
//                 msg.payload.encode(&mut buf);
//                 Payload(buf)
//             }
//         };

//         Self {
//             typ,
//             version: msg.version,

//             payload,
//         }
//     }
// }

// A Decrypted TLS frame, named
pub struct PlainMessage {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub epoch: u16,
    pub seq: u48,
    pub payload: Payload,
}
