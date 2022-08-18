use log;
#[macro_use]
mod check {
    macro_rules! require_handshake_msg(
        ( $m:expr, $handshake_type:path, $payload_type:path ) => (
          match &$m.payload {
              MessagePayload::Handshake(rustls::internal::msgs::handshake::HandshakeMessagePayload {
                  payload: $payload_type(hm),
                  ..
              }) => Ok(hm),
              payload => Err(rustls::internal::check::inappropriate_handshake_message(
                  payload,
                  &[rustls::internal::msgs::enums::ContentType::Handshake],
                  &[$handshake_type]))
          }
        )
      );
}
mod builder;
mod c_u48;
mod conn;
mod dtls12;
mod error;
mod hs;
mod msgs;
mod suites;
mod versions;


pub use crate::dtls12::Tls12CipherSuite;
pub use crate::suites::{ALL_DTLS_READY_CIPHER_SUITES, DEFAULT_CIPHER_SUITES};

pub mod client {
    pub(super) mod builder;
    mod client_conn;
    mod dtls12;
    mod hs;
    mod common;

    pub use client_conn::{ClientConfig, ClientConnection, ClientConnectionData};
}

// pub mod server {
//     pub(super) mod builder;
//     mod server_conn;
//     mod hs;
//     mod dtls12;
//     pub use server_conn::{ServerConfig, ServerConnection, ServerConnectionData};
// }

pub use client::{ClientConfig, ClientConnection};

pub use c_u48::u48;

