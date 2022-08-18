use log::trace;
use rustls::internal::msgs::{enums::ExtensionType, handshake::ServerExtension};

pub(super) struct ClientHelloDetails {
    pub(super) sent_extensions: Vec<ExtensionType>,
}

impl ClientHelloDetails {
    pub(super) fn new() -> Self {
        Self {
            sent_extensions: Vec::new(),
        }
    }

    pub(super) fn server_may_send_sct_list(&self) -> bool {
        self.sent_extensions
            .contains(&ExtensionType::SCT)
    }

    pub(super) fn server_sent_unsolicited_extensions(
        &self,
        received_exts: &[ServerExtension],
        allowed_unsolicited: &[ExtensionType],
    ) -> bool {
        for ext in received_exts {
            let ext_type = ext.get_type();
            if !self.sent_extensions.contains(&ext_type) && !allowed_unsolicited.contains(&ext_type)
            {
                trace!("Unsolicited extension {:?}", ext_type);
                return true;
            }
        }

        false
    }
}
