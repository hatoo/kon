use http_body_util::{BodyExt, Full};
use hyper::http;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::prelude::*;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    time::Instant,
};
use thiserror::Error;
use tokio::net::TcpStream;
use url::{ParseError, Url};

use crate::{
    url_generator::{UrlGenerator, UrlGeneratorError},
    ConnectToEntry,
};

type SendRequestHttp1 = hyper::client::conn::http1::SendRequest<Full<&'static [u8]>>;
type SendRequestHttp2 = hyper::client::conn::http2::SendRequest<Full<&'static [u8]>>;

#[derive(Debug, Clone, Copy)]
pub struct ConnectionTime {
    pub dns_lookup: std::time::Instant,
    pub dialup: std::time::Instant,
}

#[derive(Debug, Clone)]
/// a result for a request
pub struct RequestResult {
    // When the query should started
    pub start_latency_correction: Option<std::time::Instant>,
    /// When the query started
    pub start: std::time::Instant,
    /// DNS + dialup
    /// None when reuse connection
    pub connection_time: Option<ConnectionTime>,
    /// When the query ends
    pub end: std::time::Instant,
    /// HTTP status
    pub status: http::StatusCode,
    /// Length of body
    pub len_bytes: usize,
}

impl RequestResult {
    /// Duration the request takes.
    pub fn duration(&self) -> std::time::Duration {
        self.end - self.start_latency_correction.unwrap_or(self.start)
    }
}

pub struct Dns {
    pub connect_to: Vec<ConnectToEntry>,
    pub resolver:
        hickory_resolver::AsyncResolver<hickory_resolver::name_server::TokioConnectionProvider>,
}

impl Dns {
    /// Perform a DNS lookup for a given url and returns (ip_addr, port)
    async fn lookup<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(std::net::IpAddr, u16), ClientError> {
        let host = url.host_str().ok_or(ClientError::HostNotFound)?;
        let port = url
            .port_or_known_default()
            .ok_or(ClientError::PortNotFound)?;

        // Try to find an override (passed via `--connect-to`) that applies to this (host, port)
        let (host, port) = if let Some(entry) = self
            .connect_to
            .iter()
            .find(|entry| entry.requested_port == port && entry.requested_host == host)
        {
            (entry.target_host.as_str(), entry.target_port)
        } else {
            (host, port)
        };

        let host = if host.starts_with('[') && host.ends_with(']') {
            // host is [ipv6] format
            // remove first [ and last ]
            &host[1..host.len() - 1]
        } else {
            host
        };

        // Perform actual DNS lookup, either on the original (host, port), or
        // on the (host, port) specified with `--connect-to`.
        let addrs = self
            .resolver
            .lookup_ip(host)
            .await
            .map_err(Box::new)?
            .iter()
            .collect::<Vec<_>>();

        let addr = *addrs.choose(rng).ok_or(ClientError::DNSNoRecord)?;

        Ok((addr, port))
    }
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("failed to get port from URL")]
    PortNotFound,
    #[error("failed to get host from URL")]
    HostNotFound,
    #[error("No record returned from DNS")]
    DNSNoRecord,
    #[error("Redirection limit has reached")]
    TooManyRedirect,
    #[error(transparent)]
    // Use Box here because ResolveError is big.
    ResolveError(#[from] Box<hickory_resolver::error::ResolveError>),

    #[cfg(feature = "native-tls")]
    #[error(transparent)]
    NativeTlsError(#[from] native_tls::Error),

    #[cfg(feature = "rustls")]
    #[error(transparent)]
    RustlsError(#[from] rustls::Error),

    #[cfg(feature = "rustls")]
    #[error(transparent)]
    InvalidDnsName(#[from] rustls_pki_types::InvalidDnsNameError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    HttpError(#[from] http::Error),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error(transparent)]
    InvalidUriParts(#[from] http::uri::InvalidUriParts),
    #[error(transparent)]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("Failed to get header from builder")]
    GetHeaderFromBuilderError,
    #[error(transparent)]
    HeaderToStrError(#[from] http::header::ToStrError),
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),
    #[error("timeout")]
    Timeout,
    #[error("aborted due to deadline")]
    Deadline,
    #[error(transparent)]
    UrlGeneratorError(#[from] UrlGeneratorError),
    #[error(transparent)]
    UrlParseError(#[from] ParseError),
}

pub struct Client {
    pub http_version: http::Version,
    pub url_generator: UrlGenerator,
    pub method: http::Method,
    pub headers: http::header::HeaderMap,
    pub body: Option<&'static [u8]>,
    pub dns: Dns,
    pub timeout: Option<std::time::Duration>,
    pub redirect_limit: usize,
    pub disable_keepalive: bool,
    pub insecure: bool,
    #[cfg(unix)]
    pub unix_socket: Option<std::path::PathBuf>,
    #[cfg(feature = "vsock")]
    pub vsock_addr: Option<tokio_vsock::VsockAddr>,
    #[cfg(feature = "rustls")]
    pub root_cert_store: Arc<rustls::RootCertStore>,
}

struct ClientStateHttp1 {
    rng: StdRng,
    send_request: Option<SendRequestHttp1>,
}

impl Default for ClientStateHttp1 {
    fn default() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            send_request: None,
        }
    }
}

struct ClientStateHttp2 {
    rng: StdRng,
    send_request: SendRequestHttp2,
}

impl Clone for ClientStateHttp2 {
    fn clone(&self) -> Self {
        Self {
            rng: StdRng::from_entropy(),
            send_request: self.send_request.clone(),
        }
    }
}

pub enum QueryLimit {
    Qps(usize),
    Burst(std::time::Duration, usize),
}

// To avoid dynamic dispatch
// I'm not sure how much this is effective
enum Stream {
    Tcp(TcpStream),
    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    Tls(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls")]
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(feature = "vsock")]
    Vsock(tokio_vsock::VsockStream),
}

impl Stream {
    async fn handshake_http1(self) -> Result<SendRequestHttp1, ClientError> {
        match self {
            Stream::Tcp(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            Stream::Tls(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            #[cfg(unix)]
            Stream::Unix(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            #[cfg(feature = "vsock")]
            Stream::Vsock(stream) => {
                let (send_request, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
        }
    }
    async fn handshake_http2(self) -> Result<SendRequestHttp2, ClientError> {
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder
            // from nghttp2's default
            .initial_stream_window_size((1 << 30) - 1)
            .initial_connection_window_size((1 << 30) - 1);

        match self {
            Stream::Tcp(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            Stream::Tls(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            #[cfg(unix)]
            Stream::Unix(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
            #[cfg(feature = "vsock")]
            Stream::Vsock(stream) => {
                let (send_request, conn) = builder.handshake(TokioIo::new(stream)).await?;
                tokio::spawn(conn);
                Ok(send_request)
            }
        }
    }
}

impl Client {
    fn is_http2(&self) -> bool {
        self.http_version == http::Version::HTTP_2
    }

    /// Perform a DNS lookup to cache it
    /// This is useful to avoid DNS lookup latency at the first concurrent requests
    pub async fn pre_lookup(&self) -> Result<(), ClientError> {
        // If the client is using a unix socket, we don't need to do a DNS lookup
        #[cfg(unix)]
        if self.unix_socket.is_some() {
            return Ok(());
        }
        // If the client is using a vsock address, we don't need to do a DNS lookup
        #[cfg(feature = "vsock")]
        if self.vsock_addr.is_some() {
            return Ok(());
        }

        let mut rng = StdRng::from_entropy();
        let url = self.url_generator.generate(&mut rng)?;

        // It automatically caches the result
        self.dns.lookup(&url, &mut rng).await?;
        Ok(())
    }

    async fn client<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(Instant, Stream), ClientError> {
        // TODO: Allow the connect timeout to be configured
        let timeout_duration = tokio::time::Duration::from_secs(5);

        if url.scheme() == "https" {
            let addr = self.dns.lookup(url, rng).await?;
            let dns_lookup = Instant::now();
            // If we do not put a timeout here then the connections attempts will
            // linger long past the configured timeout
            let stream = tokio::time::timeout(timeout_duration, self.tls_client(addr, url)).await;
            return match stream {
                Ok(Ok(stream)) => Ok((dns_lookup, stream)),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(ClientError::Timeout),
            };
        }
        #[cfg(unix)]
        if let Some(socket_path) = &self.unix_socket {
            let dns_lookup = Instant::now();
            let stream = tokio::time::timeout(
                timeout_duration,
                tokio::net::UnixStream::connect(socket_path),
            )
            .await;
            return match stream {
                Ok(Ok(stream)) => Ok((dns_lookup, Stream::Unix(stream))),
                Ok(Err(err)) => Err(ClientError::IoError(err)),
                Err(_) => Err(ClientError::Timeout),
            };
        }
        #[cfg(feature = "vsock")]
        if let Some(addr) = self.vsock_addr {
            let dns_lookup = Instant::now();
            let stream =
                tokio::time::timeout(timeout_duration, tokio_vsock::VsockStream::connect(addr))
                    .await;
            return match stream {
                Ok(Ok(stream)) => Ok((dns_lookup, Stream::Vsock(stream))),
                Ok(Err(err)) => Err(ClientError::IoError(err)),
                Err(_) => Err(ClientError::Timeout),
            };
        }
        let addr = self.dns.lookup(url, rng).await?;
        let dns_lookup = Instant::now();
        let stream =
            tokio::time::timeout(timeout_duration, tokio::net::TcpStream::connect(addr)).await;
        match stream {
            Ok(Ok(stream)) => {
                stream.set_nodelay(true)?;
                Ok((dns_lookup, Stream::Tcp(stream)))
            }
            Ok(Err(err)) => Err(ClientError::IoError(err)),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    async fn tls_client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &Url,
    ) -> Result<Stream, ClientError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let mut connector_builder = native_tls::TlsConnector::builder();
        if self.insecure {
            connector_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        if self.is_http2() {
            connector_builder.request_alpns(&["h2"]);
        }

        let connector = tokio_native_tls::TlsConnector::from(connector_builder.build()?);
        let stream = connector
            .connect(url.host_str().ok_or(ClientError::HostNotFound)?, stream)
            .await?;

        Ok(Stream::Tls(stream))
    }

    #[cfg(feature = "rustls")]
    async fn tls_client(
        &self,
        addr: (std::net::IpAddr, u16),
        url: &Url,
    ) -> Result<Stream, ClientError> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(self.root_cert_store.clone())
            .with_no_client_auth();
        if self.insecure {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(AcceptAnyServerCert));
        }
        if self.is_http2() {
            config.alpn_protocols = vec![b"h2".to_vec()];
        }
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let domain = rustls_pki_types::ServerName::try_from(
            url.host_str().ok_or(ClientError::HostNotFound)?,
        )?;
        let stream = connector.connect(domain.to_owned(), stream).await?;

        Ok(Stream::Tls(stream))
    }

    async fn client_http1<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(Instant, SendRequestHttp1), ClientError> {
        let (dns_lookup, stream) = self.client(url, rng).await?;
        Ok((dns_lookup, stream.handshake_http1().await?))
    }

    fn request(&self, url: &Url) -> Result<http::Request<Full<&'static [u8]>>, ClientError> {
        let mut builder = http::Request::builder()
            .uri(if self.is_http2() {
                &url[..]
            } else {
                &url[url::Position::BeforePath..]
            })
            .method(self.method.clone())
            .version(self.http_version);

        *builder
            .headers_mut()
            .ok_or(ClientError::GetHeaderFromBuilderError)? = self.headers.clone();

        if let Some(body) = self.body {
            Ok(builder.body(Full::new(body))?)
        } else {
            Ok(builder.body(Full::default())?)
        }
    }

    async fn work_http1(
        &self,
        client_state: &mut ClientStateHttp1,
    ) -> Result<RequestResult, ClientError> {
        let do_req = async {
            let url = self.url_generator.generate(&mut client_state.rng)?;
            let mut start = std::time::Instant::now();
            let mut connection_time: Option<ConnectionTime> = None;

            let mut send_request = if let Some(send_request) = client_state.send_request.take() {
                send_request
            } else {
                let (dns_lookup, send_request) =
                    self.client_http1(&url, &mut client_state.rng).await?;
                let dialup = std::time::Instant::now();

                connection_time = Some(ConnectionTime { dns_lookup, dialup });
                send_request
            };
            while send_request.ready().await.is_err() {
                // This gets hit when the connection for HTTP/1.1 faults
                // This re-connects
                start = std::time::Instant::now();
                let (dns_lookup, send_request_) =
                    self.client_http1(&url, &mut client_state.rng).await?;
                send_request = send_request_;
                let dialup = std::time::Instant::now();
                connection_time = Some(ConnectionTime { dns_lookup, dialup });
            }
            let request = self.request(&url)?;
            match send_request.send_request(request).await {
                Ok(res) => {
                    let (parts, mut stream) = res.into_parts();
                    let mut status = parts.status;

                    let mut len_sum = 0;
                    while let Some(chunk) = stream.frame().await {
                        len_sum += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
                    }

                    if self.redirect_limit != 0 {
                        if let Some(location) = parts.headers.get("Location") {
                            let (send_request_redirect, new_status, len) = self
                                .redirect(
                                    send_request,
                                    &url,
                                    location,
                                    self.redirect_limit,
                                    &mut client_state.rng,
                                )
                                .await?;

                            send_request = send_request_redirect;
                            status = new_status;
                            len_sum = len;
                        }
                    }

                    let end = std::time::Instant::now();

                    let result = RequestResult {
                        start_latency_correction: None,
                        start,
                        end,
                        status,
                        len_bytes: len_sum,
                        connection_time,
                    };

                    if !self.disable_keepalive {
                        client_state.send_request = Some(send_request);
                    }

                    Ok::<_, ClientError>(result)
                }
                Err(e) => {
                    client_state.send_request = Some(send_request);
                    Err(e.into())
                }
            }
        };

        if let Some(timeout) = self.timeout {
            tokio::select! {
                res = do_req => {
                    res
                }
                _ = tokio::time::sleep(timeout) => {
                    Err(ClientError::Timeout)
                }
            }
        } else {
            do_req.await
        }
    }
    async fn connect_http2<R: Rng>(
        &self,
        url: &Url,
        rng: &mut R,
    ) -> Result<(ConnectionTime, SendRequestHttp2), ClientError> {
        let (dns_lookup, stream) = self.client(url, rng).await?;
        let send_request = stream.handshake_http2().await?;
        let dialup = std::time::Instant::now();
        Ok((ConnectionTime { dns_lookup, dialup }, send_request))
    }

    async fn work_http2(
        &self,
        client_state: &mut ClientStateHttp2,
    ) -> Result<RequestResult, ClientError> {
        let do_req = async {
            let url = self.url_generator.generate(&mut client_state.rng)?;
            let start = std::time::Instant::now();
            let connection_time: Option<ConnectionTime> = None;

            let request = self.request(&url)?;
            match client_state.send_request.send_request(request).await {
                Ok(res) => {
                    let (parts, mut stream) = res.into_parts();
                    let status = parts.status;

                    let mut len_sum = 0;
                    while let Some(chunk) = stream.frame().await {
                        len_sum += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
                    }

                    let end = std::time::Instant::now();

                    let result = RequestResult {
                        start_latency_correction: None,
                        start,
                        end,
                        status,
                        len_bytes: len_sum,
                        connection_time,
                    };

                    Ok::<_, ClientError>(result)
                }
                Err(e) => Err(e.into()),
            }
        };

        if let Some(timeout) = self.timeout {
            tokio::select! {
                res = do_req => {
                    res
                }
                _ = tokio::time::sleep(timeout) => {
                    Err(ClientError::Timeout)
                }
            }
        } else {
            do_req.await
        }
    }

    #[allow(clippy::type_complexity)]
    async fn redirect<R: Rng + Send>(
        &self,
        send_request: SendRequestHttp1,
        base_url: &Url,
        location: &http::header::HeaderValue,
        limit: usize,
        rng: &mut R,
    ) -> Result<(SendRequestHttp1, http::StatusCode, usize), ClientError> {
        if limit == 0 {
            return Err(ClientError::TooManyRedirect);
        }
        let url = match Url::parse(location.to_str()?) {
            Ok(url) => url,
            Err(ParseError::RelativeUrlWithoutBase) => Url::options()
                .base_url(Some(base_url))
                .parse(location.to_str()?)?,
            Err(err) => Err(err)?,
        };

        let (mut send_request, send_request_base) =
            if base_url.authority() == url.authority() && !self.disable_keepalive {
                // reuse connection
                (send_request, None)
            } else {
                let (_dns_lookup, stream) = self.client_http1(&url, rng).await?;
                (stream, Some(send_request))
            };

        while send_request.ready().await.is_err() {
            let (_dns_lookup, stream) = self.client_http1(&url, rng).await?;
            send_request = stream;
        }

        let mut request = self.request(&url)?;
        if url.authority() != base_url.authority() {
            request.headers_mut().insert(
                http::header::HOST,
                http::HeaderValue::from_str(url.authority())?,
            );
        }
        let res = send_request.send_request(request).await?;
        let (parts, mut stream) = res.into_parts();
        let mut status = parts.status;

        let mut len_sum = 0;
        while let Some(chunk) = stream.frame().await {
            len_sum += chunk?.data_ref().map(|d| d.len()).unwrap_or_default();
        }

        if let Some(location) = parts.headers.get("Location") {
            let (send_request_redirect, new_status, len) =
                Box::pin(self.redirect(send_request, &url, location, limit - 1, rng)).await?;
            send_request = send_request_redirect;
            status = new_status;
            len_sum = len;
        }

        if let Some(send_request_base) = send_request_base {
            Ok((send_request_base, status, len_sum))
        } else {
            Ok((send_request, status, len_sum))
        }
    }
}

/// A server certificate verifier that accepts any certificate.
#[cfg(feature = "rustls")]
#[derive(Debug)]
struct AcceptAnyServerCert;

#[cfg(feature = "rustls")]
impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Check error and decide whether to cancel the connection
fn is_cancel_error(res: &Result<RequestResult, ClientError>) -> bool {
    matches!(res, Err(ClientError::Deadline)) || is_too_many_open_files(res)
}

/// Check error was "Too many open file"
fn is_too_many_open_files(res: &Result<RequestResult, ClientError>) -> bool {
    res.as_ref()
        .err()
        .map(|err| match err {
            ClientError::IoError(io_error) => io_error.raw_os_error() == Some(libc::EMFILE),
            _ => false,
        })
        .unwrap_or(false)
}

/// Check error was any Hyper error (primarily for HTTP2 connection errors)
fn is_hyper_error(res: &Result<RequestResult, ClientError>) -> bool {
    res.as_ref()
        .err()
        .map(|err| match err {
            // REVIEW: IoErrors, if indicating the underlying connection has failed,
            // should also cause a stop of HTTP2 requests
            ClientError::IoError(_) => true,
            ClientError::HyperError(_) => true,
            _ => false,
        })
        .unwrap_or(false)
}

async fn setup_http2(client: &Client) -> Result<(ConnectionTime, ClientStateHttp2), ClientError> {
    let mut rng = StdRng::from_entropy();
    let url = client.url_generator.generate(&mut rng)?;
    let (connection_time, send_request) = client.connect_http2(&url, &mut rng).await?;

    let client_state = ClientStateHttp2 { rng, send_request };

    Ok((connection_time, client_state))
}

async fn work_http2_once(
    client: &Client,
    client_state: &mut ClientStateHttp2,
    report_tx: &batch_channel::Sender<Result<RequestResult, ClientError>>,
    connection_time: ConnectionTime,
    start_latency_correction: Option<Instant>,
) -> (bool, bool) {
    let mut res = client.work_http2(client_state).await;
    let is_cancel = is_cancel_error(&res);
    let is_reconnect = is_hyper_error(&res);
    set_connection_time(&mut res, connection_time);
    if let Some(start_latency_correction) = start_latency_correction {
        set_start_latency_correction(&mut res, start_latency_correction);
    }
    report_tx.send(res).await.unwrap();
    (is_cancel, is_reconnect)
}

fn set_connection_time<E>(res: &mut Result<RequestResult, E>, connection_time: ConnectionTime) {
    if let Ok(res) = res {
        res.connection_time = Some(connection_time);
    }
}

fn set_start_latency_correction<E>(
    res: &mut Result<RequestResult, E>,
    start_latency_correction: std::time::Instant,
) {
    if let Ok(res) = res {
        res.start_latency_correction = Some(start_latency_correction);
    }
}

/// Run n tasks by m workers
pub async fn work_debug(
    client: Client,
    _report_tx: flume::Sender<Result<RequestResult, ClientError>>,
) -> Result<(), ClientError> {
    let mut rng = StdRng::from_entropy();
    let url = client.url_generator.generate(&mut rng)?;
    println!("URL: {}", url);

    let request = client.request(&url)?;

    println!("{:#?}", request);

    let response = if client.is_http2() {
        let (_, mut client_state) = client.connect_http2(&url, &mut rng).await?;
        client_state.send_request(request).await?
    } else {
        let (_dns_lookup, mut send_request) = client.client_http1(&url, &mut rng).await?;

        send_request.send_request(request).await?
    };

    let (parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();

    let response = http::Response::from_parts(parts, body);

    println!("{:#?}", response);

    Ok(())
}

/// Run n tasks by m workers
pub async fn work(
    client: Client,
    report_tx: batch_channel::Sender<Result<RequestResult, ClientError>>,
    n_tasks: usize,
    n_connections: usize,
    n_http2_parallel: usize,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(0));

    let client = Arc::new(client);

    if client.is_http2() {
        let futures = (0..n_connections)
            .map(|_| {
                let report_tx = report_tx.clone();
                let counter = counter.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    loop {
                        match setup_http2(&client).await {
                            Ok((connection_time, client_state)) => {
                                let futures = (0..n_http2_parallel)
                                    .map(|_| {
                                        let report_tx = report_tx.clone();
                                        let counter = counter.clone();
                                        let client = client.clone();

                                        let mut client_state = client_state.clone();
                                        tokio::spawn(async move {
                                            while counter.fetch_add(1, Ordering::Relaxed) < n_tasks
                                            {
                                                let (is_cancel, is_reconnect) = work_http2_once(
                                                    &client,
                                                    &mut client_state,
                                                    &report_tx,
                                                    connection_time,
                                                    None,
                                                )
                                                .await;

                                                if is_cancel || is_reconnect {
                                                    return is_cancel;
                                                }
                                            }

                                            true
                                        })
                                    })
                                    .collect::<Vec<_>>();

                                let mut connection_gone = false;
                                for f in futures {
                                    match f.await {
                                        Ok(true) => {
                                            // All works done
                                            connection_gone = true;
                                        }
                                        Err(_) => {
                                            // Unexpected
                                            connection_gone = true;
                                        }
                                        _ => {}
                                    }
                                }

                                if connection_gone {
                                    return;
                                }
                            }
                            Err(err) => {
                                if counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                                    report_tx.send(Err(err)).await.unwrap();
                                } else {
                                    return;
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        for f in futures {
            let _ = f.await;
        }
    } else {
        let futures = (0..n_connections)
            .map(|_| {
                let report_tx = report_tx.clone();
                let counter = counter.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    let mut client_state = ClientStateHttp1::default();
                    while counter.fetch_add(1, Ordering::Relaxed) < n_tasks {
                        let res = client.work_http1(&mut client_state).await;
                        let is_cancel = is_cancel_error(&res);
                        report_tx.send(res).await.unwrap();
                        if is_cancel {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        for f in futures {
            let _ = f.await;
        }
    };
}

/// n tasks by m workers limit to qps works in a second
pub async fn work_with_qps(
    client: Client,
    report_tx: batch_channel::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    n_tasks: usize,
    n_connections: usize,
    n_http2_parallel: usize,
) {
    let (tx, rx) = batch_channel::unbounded();

    let work_queue = async move {
        match query_limit {
            QueryLimit::Qps(qps) => {
                let start = std::time::Instant::now();
                for i in 0..n_tasks {
                    tokio::time::sleep_until(
                        (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
                    )
                    .await;
                    tx.send(()).await?;
                }
            }
            QueryLimit::Burst(duration, rate) => {
                let mut n = 0;
                // Handle via rate till n_tasks out of bound
                while n + rate < n_tasks {
                    tokio::time::sleep(duration).await;
                    for _ in 0..rate {
                        tx.send(()).await?;
                    }
                    n += rate;
                }
                // Handle the remaining tasks
                if n_tasks > n {
                    tokio::time::sleep(duration).await;
                    for _ in 0..n_tasks - n {
                        tx.send(()).await?;
                    }
                }
            }
        }
        // tx gone
        drop(tx);
        Ok::<(), batch_channel::SendError<_>>(())
    };

    let client = Arc::new(client);

    if client.is_http2() {
        let futures = (0..n_connections)
            .map(|_| {
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    loop {
                        match setup_http2(&client).await {
                            Ok((connection_time, client_state)) => {
                                let futures = (0..n_http2_parallel)
                                    .map(|_| {
                                        let report_tx = report_tx.clone();
                                        let rx = rx.clone();
                                        let client = client.clone();
                                        let mut client_state = client_state.clone();
                                        tokio::spawn(async move {
                                            while let Some(()) = rx.recv().await {
                                                let (is_cancel, is_reconnect) = work_http2_once(
                                                    &client,
                                                    &mut client_state,
                                                    &report_tx,
                                                    connection_time,
                                                    None,
                                                )
                                                .await;

                                                if is_cancel || is_reconnect {
                                                    return is_cancel;
                                                }
                                            }
                                            true
                                        })
                                    })
                                    .collect::<Vec<_>>();
                                let mut connection_gone = false;
                                for f in futures {
                                    match f.await {
                                        Ok(true) => {
                                            // All works done
                                            connection_gone = true;
                                        }
                                        Err(_) => {
                                            // Unexpected
                                            connection_gone = true;
                                        }
                                        _ => {}
                                    }
                                }
                                if connection_gone {
                                    return;
                                }
                            }
                            Err(err) => {
                                // Consume a task
                                if let Some(()) = rx.recv().await {
                                    report_tx.send(Err(err)).await.unwrap();
                                } else {
                                    return;
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        work_queue.await.unwrap();
        for f in futures {
            let _ = f.await;
        }
    } else {
        let futures = (0..n_connections)
            .map(|_| {
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    let mut client_state = ClientStateHttp1::default();
                    while let Some(()) = rx.recv().await {
                        let res = client.work_http1(&mut client_state).await;
                        let is_cancel = is_cancel_error(&res);
                        report_tx.send(res).await.unwrap();
                        if is_cancel {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        work_queue.await.unwrap();
        for f in futures {
            let _ = f.await;
        }
    };
}

/// n tasks by m workers limit to qps works in a second with latency correction
pub async fn work_with_qps_latency_correction(
    client: Client,
    report_tx: batch_channel::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    n_tasks: usize,
    n_connections: usize,
    n_http2_parallel: usize,
) {
    let (tx, rx) = batch_channel::unbounded();

    let work_queue = async move {
        match query_limit {
            QueryLimit::Qps(qps) => {
                let start = std::time::Instant::now();
                for i in 0..n_tasks {
                    tokio::time::sleep_until(
                        (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
                    )
                    .await;
                    tx.send(std::time::Instant::now()).await?;
                }
            }
            QueryLimit::Burst(duration, rate) => {
                let mut n = 0;
                // Handle via rate till n_tasks out of bound
                while n + rate < n_tasks {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    for _ in 0..rate {
                        tx.send(now).await?;
                    }
                    n += rate;
                }
                // Handle the remaining tasks
                if n_tasks > n {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    for _ in 0..n_tasks - n {
                        tx.send(now).await?;
                    }
                }
            }
        }

        // tx gone
        drop(tx);
        Ok::<(), batch_channel::SendError<_>>(())
    };

    let client = Arc::new(client);

    if client.is_http2() {
        let futures = (0..n_connections)
            .map(|_| {
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    loop {
                        match setup_http2(&client).await {
                            Ok((connection_time, client_state)) => {
                                let futures = (0..n_http2_parallel)
                                    .map(|_| {
                                        let report_tx = report_tx.clone();
                                        let rx = rx.clone();
                                        let client = client.clone();
                                        let mut client_state = client_state.clone();
                                        tokio::spawn(async move {
                                            while let Some(start) = rx.recv().await {
                                                let (is_cancel, is_reconnect) = work_http2_once(
                                                    &client,
                                                    &mut client_state,
                                                    &report_tx,
                                                    connection_time,
                                                    Some(start),
                                                )
                                                .await;

                                                if is_cancel || is_reconnect {
                                                    return is_cancel;
                                                }
                                            }
                                            true
                                        })
                                    })
                                    .collect::<Vec<_>>();
                                let mut connection_gone = false;
                                for f in futures {
                                    match f.await {
                                        Ok(true) => {
                                            // All works done
                                            connection_gone = true;
                                        }
                                        Err(_) => {
                                            // Unexpected
                                            connection_gone = true;
                                        }
                                        _ => {}
                                    }
                                }
                                if connection_gone {
                                    return;
                                }
                            }
                            Err(err) => {
                                // Consume a task
                                if rx.recv().await.is_some() {
                                    report_tx.send(Err(err)).await.unwrap();
                                } else {
                                    return;
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        work_queue.await.unwrap();
        for f in futures {
            let _ = f.await;
        }
    } else {
        let futures = (0..n_connections)
            .map(|_| {
                let client = client.clone();
                let mut client_state = ClientStateHttp1::default();
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                tokio::spawn(async move {
                    while let Some(start) = rx.recv().await {
                        let mut res = client.work_http1(&mut client_state).await;
                        set_start_latency_correction(&mut res, start);
                        let is_cancel = is_cancel_error(&res);
                        report_tx.send(res).await.unwrap();
                        if is_cancel {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        work_queue.await.unwrap();
        for f in futures {
            let _ = f.await;
        }
    };
}

/// Run until dead_line by n workers
pub async fn work_until(
    client: Client,
    report_tx: batch_channel::Sender<Result<RequestResult, ClientError>>,
    dead_line: std::time::Instant,
    n_connections: usize,
    n_http2_parallel: usize,
    wait_ongoing_requests_after_deadline: bool,
) {
    let client = Arc::new(client);
    if client.is_http2() {
        // Using semaphore to control the deadline
        // Maybe there is a better concurrent primitive to do this
        let s = Arc::new(tokio::sync::Semaphore::new(0));

        let futures = (0..n_connections)
            .map(|_| {
                let client = client.clone();
                let report_tx = report_tx.clone();
                let s = s.clone();
                tokio::spawn(async move {
                    let s = s.clone();
                    // Keep trying to establish or re-establish connections up to the deadline
                    loop {
                        match setup_http2(&client).await {
                            Ok((connection_time, client_state)) => {
                                // Setup the parallel workers for each HTTP2 connection
                                let futures = (0..n_http2_parallel)
                                    .map(|_| {
                                        let client = client.clone();
                                        let report_tx = report_tx.clone();
                                        let mut client_state = client_state.clone();
                                        let s = s.clone();
                                        tokio::spawn(async move {
                                            // This is where HTTP2 loops to make all the requests for a given client and worker
                                            loop {
                                                let (is_cancel, is_reconnect) = work_http2_once(
                                                    &client,
                                                    &mut client_state,
                                                    &report_tx,
                                                    connection_time,
                                                    None,
                                                )
                                                .await;

                                                let is_cancel = is_cancel || s.is_closed();
                                                if is_cancel || is_reconnect {
                                                    break is_cancel;
                                                }
                                            }
                                        })
                                    })
                                    .collect::<Vec<_>>();

                                let mut connection_gone = false;
                                for f in futures {
                                    tokio::select! {
                                        r = f => {
                                            match r {
                                                Ok(true) => {
                                                    // All works done
                                                    connection_gone = true;
                                                }
                                                Err(_) => {
                                                    // Unexpected
                                                    connection_gone = true;
                                                }
                                                _ => {}
                                            }
                                        }
                                        _ = s.acquire() => {
                                            report_tx.send(Err(ClientError::Deadline)).await.unwrap();
                                            connection_gone = true;
                                        }
                                    }
                                }
                                if connection_gone {
                                    return;
                                }
                            }

                            Err(err) => {
                                report_tx.send(Err(err)).await.unwrap();
                                if s.is_closed() {
                                    break;
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        tokio::time::sleep_until(dead_line.into()).await;
        s.close();

        for f in futures {
            let _ = f.await;
        }
    } else {
        let is_end = Arc::new(AtomicBool::new(false));

        let futures = (0..n_connections)
            .map(|_| {
                let client = client.clone();
                let report_tx = report_tx.clone();
                let mut client_state = ClientStateHttp1::default();
                let is_end = is_end.clone();
                tokio::spawn(async move {
                    loop {
                        let res = client.work_http1(&mut client_state).await;
                        let is_cancel = is_cancel_error(&res);
                        report_tx.send(res).await.unwrap();
                        if is_cancel || is_end.load(Relaxed) {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        tokio::time::sleep_until(dead_line.into()).await;
        is_end.store(true, Relaxed);

        if wait_ongoing_requests_after_deadline {
            for f in futures {
                let _ = f.await;
            }
        } else {
            for f in futures {
                f.abort();
                if let Err(e) = f.await {
                    if e.is_cancelled() {
                        report_tx.send(Err(ClientError::Deadline)).await.unwrap();
                    }
                }
            }
        }
    };
}

/// Run until dead_line by n workers limit to qps works in a second
#[allow(clippy::too_many_arguments)]
pub async fn work_until_with_qps(
    client: Client,
    report_tx: batch_channel::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_connections: usize,
    n_http2_parallel: usize,
    wait_ongoing_requests_after_deadline: bool,
) {
    let rx = match query_limit {
        QueryLimit::Qps(qps) => {
            let (tx, rx) = batch_channel::bounded(qps);
            tokio::spawn(async move {
                for i in 0.. {
                    if std::time::Instant::now() > dead_line {
                        break;
                    }
                    tokio::time::sleep_until(
                        (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
                    )
                    .await;
                    let _ = tx.send(());
                }
                // tx gone
            });
            rx
        }
        QueryLimit::Burst(duration, rate) => {
            let (tx, rx) = batch_channel::unbounded();
            tokio::spawn(async move {
                // Handle via rate till deadline is reached
                for _ in 0.. {
                    if std::time::Instant::now() > dead_line {
                        break;
                    }

                    tokio::time::sleep(duration).await;
                    for _ in 0..rate {
                        let _ = tx.send(());
                    }
                }
                // tx gone
            });
            rx
        }
    };

    let client = Arc::new(client);

    if client.is_http2() {
        let s = Arc::new(tokio::sync::Semaphore::new(0));

        let futures = (0..n_connections)
            .map(|_| {
                let client = client.clone();
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                let s = s.clone();
                tokio::spawn(async move {
                    loop {
                        match setup_http2(&client).await {
                            Ok((connection_time, client_state)) => {
                                let futures = (0..n_http2_parallel)
                                    .map(|_| {
                                        let client = client.clone();
                                        let report_tx = report_tx.clone();
                                        let rx = rx.clone();
                                        let mut client_state = client_state.clone();
                                        let s = s.clone();
                                        tokio::spawn(async move {
                                            while let Some(()) = rx.recv().await {
                                                let (is_cancel, is_reconnect) = work_http2_once(
                                                    &client,
                                                    &mut client_state,
                                                    &report_tx,
                                                    connection_time,
                                                    None,
                                                )
                                                .await;

                                                let is_cancel = is_cancel || s.is_closed();
                                                if is_cancel || is_reconnect {
                                                    return is_cancel;
                                                }
                                            }
                                            true
                                        })
                                    })
                                    .collect::<Vec<_>>();
                                let mut connection_gone = false;
                                for f in futures {
                                    tokio::select! {
                                        r = f => {
                                            match r {
                                                Ok(true) => {
                                                    // All works done
                                                    connection_gone = true;
                                                }
                                                Err(_) => {
                                                    // Unexpected
                                                    connection_gone = true;
                                                }
                                                _ => {}
                                            }
                                        }
                                        _ = s.acquire() => {
                                            report_tx.send(Err(ClientError::Deadline)).await.unwrap();
                                            connection_gone = true;
                                        }
                                    }
                                }
                                if connection_gone {
                                    return;
                                }
                            }
                            Err(err) => {
                                // Consume a task
                                if rx.recv().await.is_some() {
                                    report_tx.send(Err(err)).await.unwrap();
                                } else {
                                    return;
                                }

                                if s.is_closed() {
                                    return;
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        tokio::time::sleep_until(dead_line.into()).await;
        s.close();

        for f in futures {
            let _ = f.await;
        }
    } else {
        let is_end = Arc::new(AtomicBool::new(false));

        let futures = (0..n_connections)
            .map(|_| {
                let client = client.clone();
                let mut client_state = ClientStateHttp1::default();
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                let is_end = is_end.clone();
                tokio::spawn(async move {
                    while let Some(()) = rx.recv().await {
                        let res = client.work_http1(&mut client_state).await;
                        let is_cancel = is_cancel_error(&res);
                        report_tx.send(res).await.unwrap();
                        if is_cancel || is_end.load(Relaxed) {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        tokio::time::sleep_until(dead_line.into()).await;
        is_end.store(true, Relaxed);

        if wait_ongoing_requests_after_deadline {
            for f in futures {
                let _ = f.await;
            }
        } else {
            for f in futures {
                f.abort();
                if let Err(e) = f.await {
                    if e.is_cancelled() {
                        report_tx.send(Err(ClientError::Deadline)).await.unwrap();
                    }
                }
            }
        }
    }
}

/// Run until dead_line by n workers limit to qps works in a second with latency correction
#[allow(clippy::too_many_arguments)]
pub async fn work_until_with_qps_latency_correction(
    client: Client,
    report_tx: batch_channel::Sender<Result<RequestResult, ClientError>>,
    query_limit: QueryLimit,
    start: std::time::Instant,
    dead_line: std::time::Instant,
    n_connections: usize,
    n_http2_parallel: usize,
    wait_ongoing_requests_after_deadline: bool,
) {
    let (tx, rx) = batch_channel::unbounded();
    match query_limit {
        QueryLimit::Qps(qps) => {
            tokio::spawn(async move {
                for i in 0.. {
                    tokio::time::sleep_until(
                        (start + i as u32 * std::time::Duration::from_secs(1) / qps as u32).into(),
                    )
                    .await;
                    let now = std::time::Instant::now();
                    if now > dead_line {
                        break;
                    }
                    let _ = tx.send(now);
                }
                // tx gone
            });
        }
        QueryLimit::Burst(duration, rate) => {
            tokio::spawn(async move {
                // Handle via rate till deadline is reached
                loop {
                    tokio::time::sleep(duration).await;
                    let now = std::time::Instant::now();
                    if now > dead_line {
                        break;
                    }

                    for _ in 0..rate {
                        let _ = tx.send(now);
                    }
                }
                // tx gone
            });
        }
    };

    let client = Arc::new(client);

    if client.is_http2() {
        let s = Arc::new(tokio::sync::Semaphore::new(0));

        let futures = (0..n_connections)
            .map(|_| {
                let client = client.clone();
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                let s = s.clone();
                tokio::spawn(async move {
                    loop {
                        match setup_http2(&client).await {
                            Ok((connection_time, client_state)) => {
                                let futures = (0..n_http2_parallel)
                                    .map(|_| {
                                        let client = client.clone();
                                        let report_tx = report_tx.clone();
                                        let rx = rx.clone();
                                        let mut client_state = client_state.clone();
                                        let s = s.clone();
                                        tokio::spawn(async move {
                                            while let Some(start) = rx.recv().await {
                                                let (is_cancel, is_reconnect) = work_http2_once(
                                                    &client,
                                                    &mut client_state,
                                                    &report_tx,
                                                    connection_time,
                                                    Some(start),
                                                )
                                                .await;
                                                let is_cancel = is_cancel || s.is_closed();
                                                if is_cancel || is_reconnect {
                                                    return is_cancel;
                                                }
                                            }
                                            true
                                        })
                                    })
                                    .collect::<Vec<_>>();
                                let mut connection_gone = false;
                                for f in futures {
                                    tokio::select! {
                                        r = f => {
                                            match r {
                                                Ok(true) => {
                                                    // All works done
                                                    connection_gone = true;
                                                }
                                                Err(_) => {
                                                    // Unexpected
                                                    connection_gone = true;
                                                }
                                                _ => {}
                                            }
                                        }
                                        _ = s.acquire() => {
                                            report_tx.send(Err(ClientError::Deadline)).await.unwrap();
                                            connection_gone = true;
                                        }
                                    }
                                }
                                if connection_gone {
                                    return;
                                }
                            }

                            Err(err) => {
                                if rx.recv().await.is_some() {
                                    report_tx.send(Err(err)).await.unwrap();
                                } else {
                                    return;
                                }

                                if s.is_closed() {
                                    return;
                                }
                            }
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        tokio::time::sleep_until(dead_line.into()).await;
        s.close();

        for f in futures {
            let _ = f.await;
        }
    } else {
        let is_end = Arc::new(AtomicBool::new(false));

        let futures = (0..n_connections)
            .map(|_| {
                let client = client.clone();
                let mut client_state = ClientStateHttp1::default();
                let report_tx = report_tx.clone();
                let rx = rx.clone();
                let is_end = is_end.clone();
                tokio::spawn(async move {
                    while let Some(start) = rx.recv().await {
                        let mut res = client.work_http1(&mut client_state).await;
                        set_start_latency_correction(&mut res, start);
                        let is_cancel = is_cancel_error(&res);
                        report_tx.send(res).await.unwrap();
                        if is_cancel || is_end.load(Relaxed) {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        tokio::time::sleep_until(dead_line.into()).await;
        is_end.store(true, Relaxed);

        if wait_ongoing_requests_after_deadline {
            for f in futures {
                let _ = f.await;
            }
        } else {
            for f in futures {
                f.abort();
                if let Err(e) = f.await {
                    if e.is_cancelled() {
                        report_tx.send(Err(ClientError::Deadline)).await.unwrap();
                    }
                }
            }
        }
    }
}
