use crate::builder::{ConfigBuilder, WantsCipherSuites};
use crate::conn::Protocol;
use crate::error::Error;
use crate::msgs::handshake::ClientExtension;
use rustls::client::ServerCertVerifier;

use rustls::SupportedKxGroup;
use rustls::internal::conn::Side;
use rustls::{CommonState, ConnectionCommon, ServerName};
// #[cfg(feature = "logging")]
use crate::log::trace;
// use crate::msgs::enums::CipherSuite;
// use crate::msgs::enums::ProtocolVersion;
// use crate::msgs::enums::SignatureScheme;
// use crate::msgs::handshake::ClientExtension;
use crate::suites::SupportedCipherSuite;
use rustls::{sign, CipherSuite, ProtocolVersion, SignatureScheme};
// use crate::verify;
use crate::versions;
use rustls::KeyLog;

use super::hs;

use std::convert::TryFrom;
use std::error::Error as StdError;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{fmt, io, mem};

/// A trait for the ability to store client session data.
/// The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding session.
///
/// `put` is a mutating operation; this isn't expressed
/// in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common
/// choice.
pub trait StoresClientSessions: Send + Sync {
    /// Stores a new `value` for `key`.  Returns `true`
    /// if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Returns the latest value for `key`.  Returns `None`
    /// if there's no such value.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// A trait for the ability to choose a certificate chain and
/// private key for the purposes of client authentication.
pub trait ResolvesClientCert: Send + Sync {
    /// With the server-supplied acceptable issuers in `acceptable_issuers`,
    /// the server's supported signature schemes in `sigschemes`,
    /// return a certificate chain and signing key to authenticate.
    ///
    /// `acceptable_issuers` is undecoded and unverified by the rustls
    /// library, but it should be expected to contain a DER encodings
    /// of X501 NAMEs.
    ///
    /// Return None to continue the handshake without any client
    /// authentication.  The server may reject the handshake later
    /// if it requires authentication.
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>>;

    /// Return true if any certificates at all are available.
    fn has_certs(&self) -> bool;
}

/// Common configuration for (typically) all connections made by
/// a program.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
///
/// These must be created via the [`ClientConfig::builder()`] function.
///
/// # Defaults
///
/// * [`ClientConfig::max_fragment_size`]: the default is `None`: TLS packets are not fragmented to a specific size.
/// * [`ClientConfig::session_storage`]: the default stores 256 sessions in memory.
/// * [`ClientConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ClientConfig::key_log`]: key material is not logged.
#[derive(Clone)]
pub struct ClientConfig {
    /// List of ciphersuites, in preference order.
    pub(super) cipher_suites: Vec<SupportedCipherSuite>,

    /// List of supported key exchange algorithms, in preference order -- the
    /// first element is the highest priority.
    ///
    /// The first element in this list is the _default key share algorithm_,
    /// and in TLS1.3 a key share for it is sent in the client hello.
    pub(super) kx_groups: Vec<&'static SupportedKxGroup>,

    /// Which ALPN protocols we include in our client hello.
    /// If empty, no ALPN extension is sent.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// How we store session data or tickets.
    pub session_storage: Arc<dyn StoresClientSessions>,

    /// The maximum size of TLS message we'll emit.  If None, we don't limit TLS
    /// message lengths except to the 2**16 limit specified in the standard.
    ///
    /// rustls enforces an arbitrary minimum of 32 bytes for this field.
    /// Out of range values are reported as errors from ClientConnection::new.
    ///
    /// Setting this value to the TCP MSS may improve latency for stream-y workloads.
    pub max_fragment_size: Option<usize>,

    /// How to decide what client auth certificate/keys to use.
    pub client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,

    /// Whether to support RFC5077 tickets.  You must provide a working
    /// `session_storage` member for this to have any meaningful
    /// effect.
    ///
    /// The default is true.
    pub enable_tickets: bool,

    /// Supported versions, in no particular order.  The default
    /// is all supported versions.
    pub(super) versions: versions::EnabledVersions,

    /// Whether to send the Server Name Indication (SNI) extension
    /// during the client handshake.
    ///
    /// The default is true.
    pub enable_sni: bool,

    /// How to verify the server certificate chain.
    pub(super) verifier: Arc<dyn ServerCertVerifier>,

    /// How to output key material for debugging.  The default
    /// does nothing.
    pub key_log: Arc<dyn KeyLog>,

    /// Whether to send data on the first flight ("early data") in
    /// TLS 1.3 handshakes.
    ///
    /// The default is false.
    pub enable_early_data: bool,
}

impl ClientConfig {
    /// Create a builder to build up the client configuration.
    ///
    /// For more information, see the [`ConfigBuilder`] documentation.
    pub fn builder() -> ConfigBuilder<Self, WantsCipherSuites> {
        ConfigBuilder {
            state: WantsCipherSuites(()),
            side: PhantomData::default(),
        }
    }

    #[doc(hidden)]
    /// We support a given TLS version if it's quoted in the configured
    /// versions *and* at least one ciphersuite for this version is
    /// also configured.
    pub fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.versions.contains(v)
            && self
                .cipher_suites
                .iter()
                .any(|cs| cs.version().version == v)
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    #[cfg(feature = "dangerous_configuration")]
    pub fn dangerous(&mut self) -> danger::DangerousClientConfig {
        danger::DangerousClientConfig { cfg: self }
    }

    pub(super) fn find_cipher_suite(&self, suite: CipherSuite) -> Option<SupportedCipherSuite> {
        self.cipher_suites
            .iter()
            .copied()
            .find(|&scs| scs.suite() == suite)
    }
}

#[derive(Debug, PartialEq)]
enum EarlyDataState {
    Disabled,
    Ready,
    Accepted,
    AcceptedFinished,
    Rejected,
}

pub(super) struct EarlyData {
    state: EarlyDataState,
    left: usize,
}

impl EarlyData {
    fn new() -> Self {
        Self {
            left: 0,
            state: EarlyDataState::Disabled,
        }
    }

    pub(super) fn is_enabled(&self) -> bool {
        matches!(self.state, EarlyDataState::Ready | EarlyDataState::Accepted)
    }

    fn is_accepted(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Accepted | EarlyDataState::AcceptedFinished
        )
    }

    pub(super) fn enable(&mut self, max_data: usize) {
        assert_eq!(self.state, EarlyDataState::Disabled);
        self.state = EarlyDataState::Ready;
        self.left = max_data;
    }

    pub(super) fn rejected(&mut self) {
        trace!("EarlyData rejected");
        self.state = EarlyDataState::Rejected;
    }

    pub(super) fn accepted(&mut self) {
        trace!("EarlyData accepted");
        assert_eq!(self.state, EarlyDataState::Ready);
        self.state = EarlyDataState::Accepted;
    }

    pub(super) fn finished(&mut self) {
        trace!("EarlyData finished");
        self.state = match self.state {
            EarlyDataState::Accepted => EarlyDataState::AcceptedFinished,
            _ => panic!("bad EarlyData state"),
        }
    }

    fn check_write(&mut self, sz: usize) -> io::Result<usize> {
        match self.state {
            EarlyDataState::Disabled => unreachable!(),
            EarlyDataState::Ready | EarlyDataState::Accepted => {
                let take = if self.left < sz {
                    mem::replace(&mut self.left, 0)
                } else {
                    self.left -= sz;
                    sz
                };

                Ok(take)
            }
            EarlyDataState::Rejected | EarlyDataState::AcceptedFinished => {
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
        }
    }

    fn bytes_left(&self) -> usize {
        self.left
    }
}

/// Stub that implements io::Write and dispatches to `write_early_data`.
pub struct WriteEarlyData<'a> {
    sess: &'a mut ClientConnection,
}

impl<'a> WriteEarlyData<'a> {
    fn new(sess: &'a mut ClientConnection) -> WriteEarlyData<'a> {
        WriteEarlyData { sess }
    }

    /// How many bytes you may send.  Writes will become short
    /// once this reaches zero.
    pub fn bytes_left(&self) -> usize {
        self.sess.inner.data.early_data.bytes_left()
    }
}

impl<'a> io::Write for WriteEarlyData<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sess.write_early_data(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// This represents a single TLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon<ClientConnectionData>,
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClientConnection").finish()
    }
}

impl ClientConnection {
    /// Make a new ClientConnection.  `config` controls how
    /// we behave in the TLS protocol, `name` is the
    /// name of the server we want to talk to.
    pub fn new(config: Arc<ClientConfig>, name: ServerName) -> Result<Self, Error> {
        Self::new_inner(config, name, Vec::new(), Protocol::Tcp)
    }

    fn new_inner(
        config: Arc<ClientConfig>,
        name: ServerName,
        extra_exts: Vec<ClientExtension>,
        proto: Protocol,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(config.max_fragment_size, Side::Client)?;
        common_state.protocol = proto;
        let mut data = ClientConnectionData::new();

        let mut cx = hs::ClientContext {
            common: &mut common_state,
            data: &mut data,
        };

        let state = hs::start_handshake(name, extra_exts, config, &mut cx)?;
        let inner = ConnectionCommon::new(state, data, common_state);

        Ok(Self { inner })
    }

    /// Returns an `io::Write` implementer you can write bytes to
    /// to send TLS1.3 early data (a.k.a. "0-RTT data") to the server.
    ///
    /// This returns None in many circumstances when the capability to
    /// send early data is not available, including but not limited to:
    ///
    /// - The server hasn't been talked to previously.
    /// - The server does not support resumption.
    /// - The server does not support early data.
    /// - The resumption data for the server has expired.
    ///
    /// The server specifies a maximum amount of early data.  You can
    /// learn this limit through the returned object, and writes through
    /// it will process only this many bytes.
    ///
    /// The server can choose not to accept any sent early data --
    /// in this case the data is lost but the connection continues.  You
    /// can tell this happened using `is_early_data_accepted`.
    pub fn early_data(&mut self) -> Option<WriteEarlyData> {
        if self.inner.data.early_data.is_enabled() {
            Some(WriteEarlyData::new(self))
        } else {
            None
        }
    }

    /// Returns True if the server signalled it will process early data.
    ///
    /// If you sent early data and this returns false at the end of the
    /// handshake then the server will not process the data.  This
    /// is not an error, but you may wish to resend the data.
    pub fn is_early_data_accepted(&self) -> bool {
        self.inner.data.early_data.is_accepted()
    }

    fn write_early_data(&mut self, data: &[u8]) -> io::Result<usize> {
        self.inner
            .data
            .early_data
            .check_write(data.len())
            .map(|sz| self.inner.common_state.send_early_plaintext(&data[..sz]))
    }
}

impl Deref for ClientConnection {
    type Target = ConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[doc(hidden)]
impl<'a> TryFrom<&'a mut rustls::Connection> for &'a mut ClientConnection {
    type Error = ();

    fn try_from(value: &'a mut rustls::Connection) -> Result<Self, Self::Error> {
        use rustls::Connection::*;
        match value {
            Client(conn) => Ok(conn),
            Server(_) => Err(()),
        }
    }
}

impl From<ClientConnection> for rustls::Connection {
    fn from(conn: ClientConnection) -> Self {
        Self::Client(conn)
    }
}

/// State associated with a client connection.
pub struct ClientConnectionData {
    pub(super) early_data: EarlyData,
    pub(super) resumption_ciphersuite: Option<SupportedCipherSuite>,
}

impl ClientConnectionData {
    fn new() -> Self {
        Self {
            early_data: EarlyData::new(),
            resumption_ciphersuite: None,
        }
    }
}

impl rustls::SideData for ClientConnectionData {}
