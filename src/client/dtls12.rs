pub(super) use server_hello::CompleteServerHelloHandling;

mod server_hello {
    use std::sync::Arc;

    use log::debug;
    use rustls::ServerName;
    use rustls::Tls12CipherSuite;
    use rustls::internal::conn::ConnectionRandoms;
    use rustls::internal::conn::Side;
    use rustls::internal::hash_hs::HandshakeHash;
    use rustls::internal::msgs::enums::ExtensionType;
    use rustls::internal::msgs::persist;
    use rustls::internal::tls12::ConnectionSecrets;
    use crate::ClientConfig;
    use crate::client::hs;
    use crate::client::hs::ClientContext;
    use crate::error::Error;
    use rustls::internal::msgs::handshake::HasServerExtensions;
    use rustls::internal::msgs::handshake::ServerHelloPayload;
    use super::*;

    pub(in crate::client) struct CompleteServerHelloHandling {
        pub(in crate::client) config: Arc<ClientConfig>,
        pub(in crate::client) resuming_session: Option<persist::Tls12ClientSessionValue>,
        pub(in crate::client) server_name: ServerName,
        pub(in crate::client) randoms: ConnectionRandoms,
        pub(in crate::client) using_ems: bool,
        pub(in crate::client) transcript: HandshakeHash,
    }
    impl CompleteServerHelloHandling {
        pub(in crate::client) fn handle_server_hello(
            mut self,
            cx: &mut ClientContext,
            suite: &'static Tls12CipherSuite,
            server_hello: &ServerHelloPayload,
            tls13_supported: bool,
        ) -> hs::NextStateOrError {
            server_hello
                .random
                .write_slice(&mut self.randoms.server);

            // Look for TLS1.3 downgrade signal in server random
            // both the server random and TLS12_DOWNGRADE_SENTINEL are
            // public values and don't require constant time comparison
            let has_downgrade_marker = self.randoms.server[24..] == crate::dtls12::DOWNGRADE_SENTINEL;
            if tls13_supported && has_downgrade_marker {
                return Err(cx
                    .common
                    .illegal_param("downgrade to TLS1.2 when TLS1.3 is supported"));
            }

            // Doing EMS?
            self.using_ems = server_hello.ems_support_acked();

            // Might the server send a ticket?
            let must_issue_new_ticket = if server_hello
                .find_extension(ExtensionType::SessionTicket)
                .is_some()
            {
                debug!("Server supports tickets");
                true
            } else {
                false
            };

            // Might the server send a CertificateStatus between Certificate and
            // ServerKeyExchange?
            let may_send_cert_status = server_hello
                .find_extension(ExtensionType::StatusRequest)
                .is_some();
            if may_send_cert_status {
                debug!("Server may staple OCSP response");
            }

            // Save any sent SCTs for verification against the certificate.
            let server_cert_sct_list = if let Some(sct_list) = server_hello.get_sct_list() {
                debug!("Server sent {:?} SCTs", sct_list.len());

                if hs::sct_list_is_invalid(sct_list) {
                    let error_msg = "server sent invalid SCT list".to_string();
                    return Err(Error::PeerMisbehavedError(error_msg));
                }
                Some(sct_list.clone())
            } else {
                None
            };

            // See if we're successfully resuming.
            if let Some(ref resuming) = self.resuming_session {
                if resuming.session_id == server_hello.session_id {
                    debug!("Server agreed to resume");

                    // Is the server telling lies about the ciphersuite?
                    if resuming.suite() != suite {
                        let error_msg =
                            "abbreviated handshake offered, but with varied cs".to_string();
                        return Err(Error::PeerMisbehavedError(error_msg));
                    }

                    // And about EMS support?
                    if resuming.extended_ms() != self.using_ems {
                        let error_msg = "server varied ems support over resume".to_string();
                        return Err(Error::PeerMisbehavedError(error_msg));
                    }

                    let secrets =
                        ConnectionSecrets::new_resume(self.randoms, suite, resuming.secret());
                    self.config.key_log.log(
                        "CLIENT_RANDOM",
                        &secrets.randoms.client,
                        &secrets.master_secret,
                    );
                    cx.common
                        .start_encryption_tls12(&secrets, Side::Client);

                    // Since we're resuming, we verified the certificate and
                    // proof of possession in the prior session.
                    cx.common.peer_certificates = Some(resuming.server_cert_chain().to_vec());
                    let cert_verified = verify::ServerCertVerified::assertion();
                    let sig_verified = verify::HandshakeSignatureValid::assertion();

                    return if must_issue_new_ticket {
                        Ok(Box::new(ExpectNewTicket {
                            config: self.config,
                            secrets,
                            resuming_session: self.resuming_session,
                            session_id: server_hello.session_id,
                            server_name: self.server_name,
                            using_ems: self.using_ems,
                            transcript: self.transcript,
                            resuming: true,
                            cert_verified,
                            sig_verified,
                        }))
                    } else {
                        Ok(Box::new(ExpectCcs {
                            config: self.config,
                            secrets,
                            resuming_session: self.resuming_session,
                            session_id: server_hello.session_id,
                            server_name: self.server_name,
                            using_ems: self.using_ems,
                            transcript: self.transcript,
                            ticket: None,
                            resuming: true,
                            cert_verified,
                            sig_verified,
                        }))
                    };
                }
            }

            Ok(Box::new(ExpectCertificate {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: server_hello.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite,
                may_send_cert_status,
                must_issue_new_ticket,
                server_cert_sct_list,
            }))
        }
    }
}