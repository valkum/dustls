use rustls::internal::msgs as r_msgs;

use super::handshake;



// Represents the protocol layer

// Taken from rustls
#[derive(Debug)]
pub enum MessagePayload {
    Alert(r_msgs::alert::AlertMessagePayload),
    Handshake(handshake::HandshakeMessagePayload),
    ChangeCipherSpec(r_msgs::ccs::ChangeCipherSpecPayload),
    ApplicationData(r_msgs::base::Payload),
}

/// A message with decoded payload
#[derive(Debug)]
pub struct Message {
    pub version: rustls::ProtocolVersion,
    pub payload: MessagePayload,
}
