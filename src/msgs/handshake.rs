use rustls::internal::msgs::base::{PayloadU16, Payload, PayloadU24};
use rustls::internal::msgs::codec::{self, Codec, Reader};
use rustls::CipherSuite;

use rustls::internal::msgs::enums::ExtensionType;
use rustls::internal::msgs::handshake::{ECPointFormatList, NamedGroups, SupportedSignatureSchemes, ServerNameRequest, ClientSessionTicket, ProtocolNameList, ProtocolVersions, KeyShareEntries, PSKKeyExchangeModes, PresharedKeyOffer, CertificateStatusRequest, UnknownExtension};
use rustls::internal::msgs::{base as r_base, enums as r_enums, handshake as r_handshake};



#[derive(Clone, Debug)]
pub enum ClientExtension {
    ECPointFormats(ECPointFormatList),
    NamedGroups(NamedGroups),
    SignatureAlgorithms(SupportedSignatureSchemes),
    ServerName(ServerNameRequest),
    SessionTicket(ClientSessionTicket),
    Protocols(ProtocolNameList),
    SupportedVersions(ProtocolVersions),
    KeyShare(KeyShareEntries),
    PresharedKeyModes(PSKKeyExchangeModes),
    PresharedKey(PresharedKeyOffer),
    Cookie(PayloadU16),
    ExtendedMasterSecretRequest,
    CertificateStatusRequest(CertificateStatusRequest),
    SignedCertificateTimestampRequest,
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    UseSRTP,
    Unknown(UnknownExtension),
}


impl ClientExtension {
    pub fn get_type(&self) -> ExtensionType {
        match *self {
            Self::ECPointFormats(_) => ExtensionType::ECPointFormats,
            Self::NamedGroups(_) => ExtensionType::EllipticCurves,
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::SessionTicket(_) => ExtensionType::SessionTicket,
            Self::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PresharedKeyModes(_) => ExtensionType::PSKKeyExchangeModes,
            Self::PresharedKey(_) => ExtensionType::PreSharedKey,
            Self::Cookie(_) => ExtensionType::Cookie,
            Self::ExtendedMasterSecretRequest => ExtensionType::ExtendedMasterSecret,
            Self::CertificateStatusRequest(_) => ExtensionType::StatusRequest,
            Self::SignedCertificateTimestampRequest => ExtensionType::SCT,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            Self::UserSRTP => ExtensionType::UseSRTP,
            Self::Unknown(ref r) => r.typ,

        }
    }
}

impl Codec for ClientExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.get_type().encode(bytes);

        let mut sub: Vec<u8> = Vec::new();
        match *self {
            Self::ECPointFormats(ref r) => r.encode(&mut sub),
            Self::NamedGroups(ref r) => r.encode(&mut sub),
            Self::SignatureAlgorithms(ref r) => r.encode(&mut sub),
            Self::ServerName(ref r) => r.encode(&mut sub),
            Self::SessionTicket(ClientSessionTicket::Request)
            | Self::ExtendedMasterSecretRequest
            | Self::SignedCertificateTimestampRequest
            | Self::EarlyData
            | Self::UseSRTP => {}
            Self::SessionTicket(ClientSessionTicket::Offer(ref r)) => r.encode(&mut sub),
            Self::Protocols(ref r) => r.encode(&mut sub),
            Self::SupportedVersions(ref r) => r.encode(&mut sub),
            Self::KeyShare(ref r) => r.encode(&mut sub),
            Self::PresharedKeyModes(ref r) => r.encode(&mut sub),
            Self::PresharedKey(ref r) => r.encode(&mut sub),
            Self::Cookie(ref r) => r.encode(&mut sub),
            Self::CertificateStatusRequest(ref r) => r.encode(&mut sub),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                sub.extend_from_slice(r)
            }

            Self::Unknown(ref r) => r.encode(&mut sub),
        }

        (sub.len() as u16).encode(bytes);
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => {
                Self::ECPointFormats(ECPointFormatList::read(&mut sub)?)
            }
            ExtensionType::EllipticCurves => Self::NamedGroups(NamedGroups::read(&mut sub)?),
            ExtensionType::SignatureAlgorithms => {
                let schemes = SupportedSignatureSchemes::read(&mut sub)?;
                Self::SignatureAlgorithms(schemes)
            }
            ExtensionType::ServerName => Self::ServerName(ServerNameRequest::read(&mut sub)?),
            ExtensionType::SessionTicket => {
                if sub.any_left() {
                    let contents = Payload::read(&mut sub);
                    Self::SessionTicket(ClientSessionTicket::Offer(contents))
                } else {
                    Self::SessionTicket(ClientSessionTicket::Request)
                }
            }
            ExtensionType::ALProtocolNegotiation => {
                Self::Protocols(ProtocolNameList::read(&mut sub)?)
            }
            ExtensionType::SupportedVersions => {
                Self::SupportedVersions(ProtocolVersions::read(&mut sub)?)
            }
            ExtensionType::KeyShare => Self::KeyShare(KeyShareEntries::read(&mut sub)?),
            ExtensionType::PSKKeyExchangeModes => {
                Self::PresharedKeyModes(PSKKeyExchangeModes::read(&mut sub)?)
            }
            ExtensionType::PreSharedKey => Self::PresharedKey(PresharedKeyOffer::read(&mut sub)?),
            ExtensionType::Cookie => Self::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret if !sub.any_left() => {
                Self::ExtendedMasterSecretRequest
            }
            ExtensionType::StatusRequest => {
                let csr = CertificateStatusRequest::read(&mut sub)?;
                Self::CertificateStatusRequest(csr)
            }
            ExtensionType::SCT if !sub.any_left() => Self::SignedCertificateTimestampRequest,
            ExtensionType::TransportParameters => Self::TransportParameters(sub.rest().to_vec()),
            ExtensionType::TransportParametersDraft => {
                Self::TransportParametersDraft(sub.rest().to_vec())
            }
            ExtensionType::EarlyData if !sub.any_left() => Self::EarlyData,
            ExtensionType::UseSRTP if !sub.any_left() => Self::UseSRTP,
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            Some(ext)
        }
    }
}




#[derive(Debug)]
pub struct ClientHelloPayload {
    pub client_version: rustls::ProtocolVersion,
    pub random: r_handshake::Random,
    pub session_id: r_handshake::SessionID,
    // max len 225
    pub cookie: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<r_enums::Compression>,
    pub extensions: Vec<r_handshake::ClientExtension>,
}

impl Codec for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);
        self.session_id.encode(bytes);
        codec::encode_vec_u8(bytes, &self.cookie);
        codec::encode_vec_u16(bytes, &self.cipher_suites);
        codec::encode_vec_u8(bytes, &self.compression_methods);

        if !self.extensions.is_empty() {
            codec::encode_vec_u16(bytes, &self.extensions);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let mut ret = Self {
            client_version: rustls::ProtocolVersion::read(r)?,
            random: r_handshake::Random::read(r)?,
            session_id: r_handshake::SessionID::read(r)?,
            cookie: codec::read_vec_u8::<u8>(r)?,
            cipher_suites: codec::read_vec_u16::<CipherSuite>(r)?,
            compression_methods: codec::read_vec_u8::<r_enums::Compression>(r)?,
            extensions: Vec::new(),
        };

        if r.any_left() {
            ret.extensions = codec::read_vec_u16::<r_handshake::ClientExtension>(r)?;
        }

        if r.any_left() || ret.extensions.is_empty() {
            None
        } else {
            Some(ret)
        }
    }
}

#[derive(Debug)]
pub struct HelloVerifyRequestPayload {
    pub server_version: rustls::ProtocolVersion,
    // max len 225
    pub cookie: Vec<u8>,
}

impl Codec for HelloVerifyRequestPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.server_version.encode(bytes);
        codec::encode_vec_u8(bytes, &self.cookie);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let ret = Self {
            server_version: rustls::ProtocolVersion::read(r)?,
            cookie: codec::read_vec_u8::<u8>(r)?,
        };

        if r.any_left() {
            None
        } else {
            Some(ret)
        }
    }
}




// Taken from Rustls, some payloads are taken from Rustls directly, some commented out (because they signal TLSv1.3), ClientHello substituted for a DTLS variant, and HelloVerifyRequest added.
#[derive(Debug)]
pub enum HandshakePayload {
    HelloRequest,
    ClientHello(ClientHelloPayload),
    HelloVerifyRequest(HelloVerifyRequestPayload),
    ServerHello(r_handshake::ServerHelloPayload),
    // HelloRetryRequest(HelloRetryRequest),
    Certificate(r_handshake::CertificatePayload),
    // CertificateTLS13(CertificatePayloadTLS13),
    ServerKeyExchange(r_handshake::ServerKeyExchangePayload),
    CertificateRequest(r_handshake::CertificateRequestPayload),
    // CertificateRequestTLS13(CertificateRequestPayloadTLS13),
    CertificateVerify(r_handshake::DigitallySignedStruct),
    ServerHelloDone,
    // EarlyData,
    // EndOfEarlyData,
    ClientKeyExchange(r_base::Payload),
    // NewSessionTicket(NewSessionTicketPayload),
    // NewSessionTicketTLS13(NewSessionTicketPayloadTLS13),
    // EncryptedExtensions(EncryptedExtensions),
    // KeyUpdate(KeyUpdateRequest),
    Finished(r_base::Payload),
    // CertificateStatus(CertificateStatus),
    // MessageHash(Payload),
    Unknown(r_base::Payload),
}

impl HandshakePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            HandshakePayload::HelloRequest | HandshakePayload::ServerHelloDone => {}
            HandshakePayload::ClientHello(ref x) => x.encode(bytes),
            HandshakePayload::HelloVerifyRequest(ref x) => x.encode(bytes),
            HandshakePayload::ServerHello(ref x) => x.encode(bytes),
            HandshakePayload::Certificate(ref x) => x.encode(bytes),
            HandshakePayload::ServerKeyExchange(ref x) => x.encode(bytes),
            HandshakePayload::ClientKeyExchange(ref x) => x.encode(bytes),
            HandshakePayload::CertificateRequest(ref x) => x.encode(bytes),
            HandshakePayload::CertificateVerify(ref x) => x.encode(bytes),
            HandshakePayload::Finished(ref x) => x.encode(bytes),
            HandshakePayload::Unknown(ref x) => x.encode(bytes),
        }
    }
}



#[derive(Debug)]
pub enum HandshakeMessagePayload {
    Full {
        typ: r_enums::HandshakeType,
        message_seq: PayloadU16,
        payload: HandshakePayload,
    },
    Fragmented {
        typ: r_enums::HandshakeType,
        message_seq: PayloadU16,
        fragment_offset: PayloadU24,
        fragment_length: PayloadU24,
        payload: HandshakePayload,
    }

}

impl Codec for HandshakeMessagePayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        let (typ, message_seq, fragment_offset, fragment_length, payload) = match self {
            HandshakeMessagePayload::Full { typ, message_seq, payload } => (typ, message_seq, 0, None, payload),
            HandshakeMessagePayload::Fragmented { typ, message_seq, fragment_offset, fragment_length, payload } => (typ, message_seq, fragment_offset, Some(fragment_length), payload),
        };

        // encode payload to learn length
        let mut sub: Vec<u8> = Vec::new();
        self.payload.encode(&mut sub);

        // output type, length, message_seq, fragment_offset, fragment_length and encoded payload
        match self.typ {
            r_enums::HandshakeType::HelloRetryRequest => r_enums::HandshakeType::ServerHello,
            _ => self.typ,
        }
        .encode(bytes);
        codec::u24(sub.len() as u32).encode(bytes);
        message_seq.encode(bytes);
        fragment_offset.encode(bytes);
        if let Some(fragment_length) = fragment_length {
            fragment_length.encode(bytes);
        } else {
            codec::u24(sub.len() as u32).encode(bytes);
        }
        bytes.append(&mut sub);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        Self::read_version(r, r_enums::ProtocolVersion::DTLSv1_2)
    }
}

impl HandshakeMessagePayload {
    // taken from rustls
    pub fn read_version(r: &mut Reader, _: rustls::ProtocolVersion) -> Option<Self> {
        use r_enums::{HandshakeType, ProtocolVersion};

        let typ = HandshakeType::read(r)?;
        let len = codec::u24::read(r)?.0 as usize;
        let message_seq = u16::read(r)?;
        let fragment_offset = codec::u24::read(r)?;
        let fragment_length = codec::u24::read(r)?;
        let mut sub = r.sub(len)?;

        let payload = match typ {
            HandshakeType::HelloRequest if sub.left() == 0 => HandshakePayload::HelloRequest,
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHelloPayload::read(&mut sub)?)
            }
            HandshakeType::HelloVerifyRequest => {
                HandshakePayload::HelloVerifyRequest(HelloVerifyRequestPayload::read(&mut sub)?)
            }
            HandshakeType::ServerHello => {
                let version = ProtocolVersion::read(&mut sub)?;
                let random = r_handshake::Random::read(&mut sub)?;

                let mut shp = r_handshake::ServerHelloPayload::read(&mut sub)?;
                shp.legacy_version = version;
                shp.random = random;
                HandshakePayload::ServerHello(shp)
            }
            HandshakeType::Certificate => {
                HandshakePayload::Certificate(r_handshake::CertificatePayload::read(&mut sub)?)
            }
            HandshakeType::ServerKeyExchange => {
                let p = r_handshake::ServerKeyExchangePayload::read(&mut sub)?;
                HandshakePayload::ServerKeyExchange(p)
            }
            HandshakeType::ServerHelloDone => {
                if sub.any_left() {
                    return None;
                }
                HandshakePayload::ServerHelloDone
            }
            HandshakeType::ClientKeyExchange => {
                HandshakePayload::ClientKeyExchange(r_base::Payload::read(&mut sub))
            }
            HandshakeType::CertificateRequest => {
                let p = r_handshake::CertificateRequestPayload::read(&mut sub)?;
                HandshakePayload::CertificateRequest(p)
            }
            HandshakeType::CertificateVerify => HandshakePayload::CertificateVerify(
                r_handshake::DigitallySignedStruct::read(&mut sub)?,
            ),
            HandshakeType::Finished => HandshakePayload::Finished(r_base::Payload::read(&mut sub)),
            HandshakeType::MessageHash => {
                // does not appear on the wire
                return None;
            }
            HandshakeType::HelloRetryRequest => {
                // not legal on wire
                return None;
            }
            _ => HandshakePayload::Unknown(r_base::Payload::read(&mut sub)),
        };

        if sub.any_left() {
            None
        } else {
            if len == fragment_length {
                Some(Self::Full{typ, message_seq, payload})
            } else {

                Some(Self::Fragmented { typ, message_seq, fragment_offset, fragment_length, payload })
            }
        }
    }

    pub fn build_key_update_notify() -> Self {
        Self {
            typ: r_enums::HandshakeType::KeyUpdate,
            payload: HandshakePayload::KeyUpdate(r_enums::KeyUpdateRequest::UpdateNotRequested),
        }
    }

    pub fn get_encoding_for_binder_signing(&self) -> Vec<u8> {
        let mut ret = self.get_encoding();

        let binder_len = match self.payload {
            HandshakePayload::ClientHello(ref ch) => match ch.extensions.last() {
                Some(ClientExtension::PresharedKey(ref offer)) => {
                    let mut binders_encoding = Vec::new();
                    offer
                        .binders
                        .encode(&mut binders_encoding);
                    binders_encoding.len()
                }
                _ => 0,
            },
            _ => 0,
        };

        let ret_len = ret.len() - binder_len;
        ret.truncate(ret_len);
        ret
    }

    pub fn build_handshake_hash(hash: &[u8]) -> Self {
        Self {
            typ: r_enums::HandshakeType::MessageHash,
            payload: HandshakePayload::MessageHash(Payload::new(hash.to_vec())),
        }
    }
}