use anyhow::Context;
use rand::seq::SliceRandom;
use std::str::FromStr;
use tokio::prelude::*;
use tokio::stream::StreamExt;
use url::Url;

trait AsyncRW: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncRW for T {}

pub struct ClientBuilder {
    url: Url,
}

impl ClientBuilder {
    pub fn build(&self) -> Client {
        Client {
            url: self.url.clone(),
            rng: rand::thread_rng(),
            resolver: None,
            send_request: None,
        }
    }
}

pub struct Client {
    url: Url,
    rng: rand::rngs::ThreadRng,
    resolver: Option<
        trust_dns_resolver::AsyncResolver<
            trust_dns_resolver::name_server::GenericConnection,
            trust_dns_resolver::name_server::GenericConnectionProvider<
                trust_dns_resolver::name_server::TokioRuntime,
            >,
        >,
    >,
    send_request: Option<hyper::client::conn::SendRequest<hyper::Body>>,
}

impl Client {
    async fn lookup_ip(&mut self) -> anyhow::Result<std::net::IpAddr> {
        let resolver = if let Some(resolver) = self.resolver.take() {
            resolver
        } else {
            trust_dns_resolver::AsyncResolver::tokio(Default::default(), Default::default()).await?
        };

        let addrs = resolver
            .lookup_ip(self.url.host_str().context("get host")?)
            .await?
            .iter()
            .collect::<Vec<_>>();

        let addr = *addrs.choose(&mut self.rng).context("get addr")?;

        self.resolver = Some(resolver);

        Ok(addr)
    }

    async fn send_request(
        &mut self,
    ) -> anyhow::Result<hyper::client::conn::SendRequest<hyper::Body>> {
        let addr = (
            self.lookup_ip().await?,
            self.url.port().context("get port")?,
        );
        if self.url.scheme() == "https" {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            let connector = native_tls::TlsConnector::new()?;
            let connector = tokio_tls::TlsConnector::from(connector);
            let stream = connector
                .connect(self.url.domain().context("get domain")?, stream)
                .await?;
            let (send, conn) = hyper::client::conn::handshake(stream).await?;
            tokio::spawn(conn);
            Ok(send)
        } else {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            let (send, conn) = hyper::client::conn::handshake(stream).await?;
            tokio::spawn(conn);
            Ok(send)
        }
    }

    pub async fn work(&mut self) -> anyhow::Result<crate::RequestResult> {
        let start = std::time::Instant::now();
        let mut send_request = if let Some(send_request) = self.send_request.take() {
            send_request
        } else {
            self.send_request().await?
        };

        let request = http::Request::builder()
            .version(http::Version::HTTP_11)
            .uri(http::uri::Uri::from_str(&self.url.to_string())?)
            .body(hyper::Body::empty())?;
        let res = send_request.send_request(request).await?;

        let status = res.status();
        let mut len_sum = 0;

        let mut stream = res.into_body();
        while let Some(chunk) = stream.next().await {
            len_sum += chunk?.len();
        }
        let end = std::time::Instant::now();

        let result = crate::RequestResult {
            start,
            end,
            status,
            len_bytes: len_sum,
        };

        self.send_request = Some(send_request);

        Ok(result)
    }
}

/// Run n tasks by m workers
/// Currently We use Fn() -> F as "task generator".
/// Any replacement?
pub async fn work<T, F: std::future::Future<Output = T>, B: Fn() -> W, W: FnMut() -> F>(
    builder: B,
    n_tasks: usize,
    n_workers: usize,
) -> Vec<Vec<T>> {
    let injector = crossbeam::deque::Injector::new();

    for _ in 0..n_tasks {
        injector.push(());
    }

    futures::future::join_all((0..n_workers).map(|_| async {
        let mut w = builder();
        let mut ret = Vec::new();
        while let crossbeam::deque::Steal::Success(()) = injector.steal() {
            ret.push(w().await);
        }
        ret
    }))
    .await
}