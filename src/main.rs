use anyhow::Context;
use clap::Parser;
use crossterm::tty::IsTty;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use humantime::Duration;
use hyper::http::{
    self,
    header::{HeaderName, HeaderValue},
};
use printer::PrintMode;
use rand::prelude::*;
use rand_regex::Regex;
use ratatui::crossterm;
use result_data::ResultData;
use std::{convert::Infallible, env, io::Read, str::FromStr, usize};
use url::Url;
use url_generator::UrlGenerator;

mod client;
mod db;
mod histogram;
mod monitor;
mod printer;
mod result_data;
mod timescale;
mod url_generator;

#[cfg(unix)]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(arg_required_else_help(true))]
struct Opts {
    #[arg(help = "Target URL.")]
    url: String,
    #[arg(
        help = "Number of requests to run.",
        short = 'n',
        default_value = "200"
    )]
    n_requests: usize,
    #[arg(
        help = "Number of connections to run concurrently. You may should increase limit to number of open files for larger `-c`.",
        short = 'c',
        default_value = "50"
    )]
    n_connections: usize,
    #[arg(
        help = "Number of parallel requests to send on HTTP/2. `oha` will run c * p concurrent workers in total.",
        short = 'p',
        default_value = "1"
    )]
    n_http2_parallel: usize,
    #[arg(
        help = "Duration of application to send requests. If duration is specified, n is ignored.
On HTTP/1, When the duration is reached, ongoing requests are aborted and counted as \"aborted due to deadline\"
You can change this behavior with `-w` option.
Currently, on HTTP/2, When the duration is reached, ongoing requests are waited. `-w` option is ignored.
Examples: -z 10s -z 3m.",
        short = 'z'
    )]
    duration: Option<Duration>,
    #[arg(
        help = "When the duration is reached, ongoing requests are waited",
        short,
        long,
        default_value = "false"
    )]
    wait_ongoing_requests_after_deadline: bool,
    #[arg(help = "Rate limit for all, in queries per second (QPS)", short = 'q')]
    query_per_second: Option<usize>,
    #[arg(
        help = "Introduce delay between a predefined number of requests.
Note: If qps is specified, burst will be ignored",
        long = "burst-delay"
    )]
    burst_duration: Option<Duration>,
    #[arg(
        help = "Rates of requests for burst. Default is 1
Note: If qps is specified, burst will be ignored",
        long = "burst-rate"
    )]
    burst_requests: Option<usize>,

    #[arg(
        help = "Generate URL by rand_regex crate but dot is disabled for each query e.g. http://127.0.0.1/[a-z][a-z][0-9]. Currently dynamic scheme, host and port with keep-alive are not works well. See https://docs.rs/rand_regex/latest/rand_regex/struct.Regex.html for details of syntax.",
        default_value = "false",
        long
    )]
    rand_regex_url: bool,
    #[arg(
        help = "A parameter for the '--rand-regex-url'. The max_repeat parameter gives the maximum extra repeat counts the x*, x+ and x{n,} operators will become.",
        default_value = "4",
        long
    )]
    max_repeat: u32,
    #[arg(
        help = "Dump target Urls <DUMP_URLS> times to debug --rand-regex-url",
        long
    )]
    dump_urls: Option<usize>,
    #[arg(
        help = "Correct latency to avoid coordinated omission problem. It's ignored if -q is not set.",
        long = "latency-correction"
    )]
    latency_correction: bool,
    #[arg(help = "No realtime tui", long = "no-tui")]
    no_tui: bool,
    #[arg(help = "Print results as JSON", short, long)]
    json: bool,
    #[arg(help = "Frame per second for tui.", default_value = "16", long = "fps")]
    fps: usize,
    #[arg(
        help = "HTTP method",
        short = 'm',
        long = "method",
        default_value = "GET"
    )]
    method: http::Method,
    #[arg(help = "Custom HTTP header. Examples: -H \"foo: bar\"", short = 'H')]
    headers: Vec<String>,
    #[arg(help = "Timeout for each request. Default to infinite.", short = 't')]
    timeout: Option<humantime::Duration>,
    #[arg(help = "HTTP Accept Header.", short = 'A')]
    accept_header: Option<String>,
    #[arg(help = "HTTP request body.", short = 'd')]
    body_string: Option<String>,
    #[arg(help = "HTTP request body from file.", short = 'D')]
    body_path: Option<std::path::PathBuf>,
    #[arg(help = "Content-Type.", short = 'T')]
    content_type: Option<String>,
    #[arg(help = "Basic authentication, username:password", short = 'a')]
    basic_auth: Option<String>,
    /*
    #[arg(help = "HTTP proxy", short = "x")]
    proxy: Option<String>,
    */
    #[arg(
        help = "HTTP version. Available values 0.9, 1.0, 1.1.",
        long = "http-version"
    )]
    http_version: Option<String>,
    #[arg(help = "Use HTTP/2. Shorthand for --http-version=2", long = "http2")]
    http2: bool,
    #[arg(help = "HTTP Host header", long = "host")]
    host: Option<String>,
    #[arg(help = "Disable compression.", long = "disable-compression")]
    disable_compression: bool,
    #[arg(
        help = "Limit for number of Redirect. Set 0 for no redirection. Redirection isn't supported for HTTP/2.",
        default_value = "10",
        short = 'r',
        long = "redirect"
    )]
    redirect: usize,
    #[arg(
        help = "Disable keep-alive, prevents re-use of TCP connections between different HTTP requests. This isn't supported for HTTP/2.",
        long = "disable-keepalive"
    )]
    disable_keepalive: bool,
    #[arg(
        help = "*Not* perform a DNS lookup at beginning to cache it",
        long = "no-pre-lookup",
        default_value = "false"
    )]
    no_pre_lookup: bool,
    #[arg(help = "Lookup only ipv6.", long = "ipv6")]
    ipv6: bool,
    #[arg(help = "Lookup only ipv4.", long = "ipv4")]
    ipv4: bool,
    #[arg(help = "Accept invalid certs.", long = "insecure")]
    insecure: bool,
    #[arg(
        help = "Override DNS resolution and default port numbers with strings like 'example.org:443:localhost:8443'",
        long = "connect-to"
    )]
    connect_to: Vec<ConnectToEntry>,
    #[arg(help = "Disable the color scheme.", long = "disable-color")]
    disable_color: bool,
    #[cfg(unix)]
    #[arg(
        help = "Connect to a unix socket instead of the domain in the URL. Only for non-HTTPS URLs.",
        long = "unix-socket",
        group = "socket-type"
    )]
    unix_socket: Option<std::path::PathBuf>,
    #[cfg(feature = "vsock")]
    #[arg(
        help = "Connect to a VSOCK socket using 'cid:port' instead of the domain in the URL. Only for non-HTTPS URLs.",
        long = "vsock-addr",
        group = "socket-type"
    )]
    vsock_addr: Option<VsockAddr>,
    #[arg(
        help = "Include a response status code successful or not successful breakdown for the time histogram and distribution statistics",
        long = "stats-success-breakdown"
    )]
    stats_success_breakdown: bool,
    #[arg(
        help = "Write succeeded requests to sqlite database url E.G test.db",
        long = "db-url"
    )]
    db_url: Option<String>,
    #[arg(
        long,
        help = "Perform a single request and dump the request and response"
    )]
    debug: bool,
}

/// An entry specified by `connect-to` to override DNS resolution and default
/// port numbers. For example, `example.org:80:localhost:5000` will connect to
/// `localhost:5000` whenever `http://example.org` is requested.
#[derive(Clone, Debug)]
pub struct ConnectToEntry {
    pub requested_host: String,
    pub requested_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl FromStr for ConnectToEntry {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expected_syntax: &str = "syntax for --connect-to is host:port:target_host:target_port";

        let (s, target_port) = s.rsplit_once(':').ok_or(expected_syntax)?;
        let (s, target_host) = if s.ends_with(']') {
            // ipv6
            let i = s.rfind(":[").ok_or(expected_syntax)?;
            (&s[..i], &s[i + 1..])
        } else {
            s.rsplit_once(':').ok_or(expected_syntax)?
        };
        let (requested_host, requested_port) = s.rsplit_once(':').ok_or(expected_syntax)?;

        Ok(ConnectToEntry {
            requested_host: requested_host.into(),
            requested_port: requested_port.parse().map_err(|err| {
                format!("requested port must be an u16, but got {requested_port}: {err}")
            })?,
            target_host: target_host.into(),
            target_port: target_port.parse().map_err(|err| {
                format!("target port must be an u16, but got {target_port}: {err}")
            })?,
        })
    }
}

/// A wrapper around a [`tokio_vsock::VsockAddr`] that provides a parser for clap
#[derive(Debug, Clone)]
#[repr(transparent)]
#[cfg(feature = "vsock")]
struct VsockAddr(tokio_vsock::VsockAddr);

#[cfg(feature = "vsock")]
impl FromStr for VsockAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (cid, port) = s
            .split_once(':')
            .ok_or("syntax for --vsock-addr is cid:port")?;
        Ok(Self(tokio_vsock::VsockAddr::new(
            cid.parse()
                .map_err(|err| format!("cid must be a u32, but got {cid}: {err}"))?,
            port.parse()
                .map_err(|err| format!("port must be a u32, but got {port}: {err}"))?,
        )))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut opts: Opts = Opts::parse();

    let http_version: http::Version = match (opts.http2, opts.http_version) {
        (true, Some(_)) => anyhow::bail!("--http2 and --http-version are exclusive"),
        (true, None) => http::Version::HTTP_2,
        (false, Some(http_version)) => match http_version.trim() {
            "0.9" => http::Version::HTTP_09,
            "1.0" => http::Version::HTTP_10,
            "1.1" => http::Version::HTTP_11,
            "2.0" | "2" => http::Version::HTTP_2,
            "3.0" | "3" => anyhow::bail!("HTTP/3 is not supported yet."),
            _ => anyhow::bail!("Unknown HTTP version. Valid versions are 0.9, 1.0, 1.1, 2."),
        },
        (false, None) => http::Version::HTTP_11,
    };

    let url_generator = if opts.rand_regex_url {
        // Almost URL has dot in domain, so disable dot in regex for convenience.
        let dot_disabled: String = opts
            .url
            .chars()
            .map(|c| {
                if c == '.' {
                    regex_syntax::escape(".")
                } else {
                    c.to_string()
                }
            })
            .collect();
        UrlGenerator::new_dynamic(Regex::compile(&dot_disabled, opts.max_repeat)?)
    } else {
        UrlGenerator::new_static(Url::parse(&opts.url)?)
    };

    if let Some(n) = opts.dump_urls {
        let mut rng = thread_rng();
        for _ in 0..n {
            let url = url_generator.generate(&mut rng)?;
            println!("{}", url);
        }
        return Ok(());
    }

    let url = url_generator.generate(&mut thread_rng())?;

    let headers = {
        let mut headers: http::header::HeaderMap = Default::default();

        // Accept all
        headers.insert(
            http::header::ACCEPT,
            http::header::HeaderValue::from_static("*/*"),
        );

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding
        if !opts.disable_compression {
            headers.insert(
                http::header::ACCEPT_ENCODING,
                http::header::HeaderValue::from_static("gzip, compress, deflate, br"),
            );
        }

        // User agent
        headers
            .entry(http::header::USER_AGENT)
            .or_insert(HeaderValue::from_static(concat!(
                "oha/",
                env!("CARGO_PKG_VERSION")
            )));

        if let Some(h) = opts.accept_header {
            headers.insert(http::header::ACCEPT, HeaderValue::from_bytes(h.as_bytes())?);
        }

        if let Some(h) = opts.content_type {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_bytes(h.as_bytes())?,
            );
        }

        if let Some(h) = opts.host {
            headers.insert(http::header::HOST, HeaderValue::from_bytes(h.as_bytes())?);
        } else if http_version != http::Version::HTTP_2 {
            headers.insert(
                http::header::HOST,
                http::header::HeaderValue::from_str(url.authority())?,
            );
        }

        if let Some(auth) = opts.basic_auth {
            let u_p = auth.splitn(2, ':').collect::<Vec<_>>();
            anyhow::ensure!(u_p.len() == 2, anyhow::anyhow!("Parse auth"));
            let mut header_value = b"Basic ".to_vec();
            {
                use std::io::Write;
                let username = u_p[0];
                let password = if u_p[1].is_empty() {
                    None
                } else {
                    Some(u_p[1])
                };
                let mut encoder = base64::write::EncoderWriter::new(
                    &mut header_value,
                    &base64::engine::general_purpose::STANDARD,
                );
                // The unwraps here are fine because Vec::write* is infallible.
                write!(encoder, "{username}:").unwrap();
                if let Some(password) = password {
                    write!(encoder, "{password}").unwrap();
                }
            }

            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_bytes(&header_value)?,
            );
        }

        if opts.disable_keepalive && http_version == http::Version::HTTP_11 {
            headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        }

        for (k, v) in opts
            .headers
            .into_iter()
            .map(|s| {
                let header = s.splitn(2, ':').collect::<Vec<_>>();
                anyhow::ensure!(header.len() == 2, anyhow::anyhow!("Parse header"));
                let name = HeaderName::from_str(header[0])?;
                let value = HeaderValue::from_str(header[1].trim_start_matches(' '))?;
                Ok::<(HeaderName, HeaderValue), anyhow::Error>((name, value))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
        {
            headers.insert(k, v);
        }

        headers
    };

    let body: Option<&'static [u8]> = match (opts.body_string, opts.body_path) {
        (Some(body), _) => Some(Box::leak(body.into_boxed_str().into_boxed_bytes())),
        (_, Some(path)) => {
            let mut buf = Vec::new();
            std::fs::File::open(path)?.read_to_end(&mut buf)?;
            Some(Box::leak(buf.into_boxed_slice()))
        }
        _ => None,
    };

    let print_mode = if opts.json {
        PrintMode::Json
    } else {
        PrintMode::Text
    };

    let (result_tx, result_rx) = batch_channel::unbounded();

    let ip_strategy = match (opts.ipv4, opts.ipv6) {
        (false, false) => Default::default(),
        (true, false) => hickory_resolver::config::LookupIpStrategy::Ipv4Only,
        (false, true) => hickory_resolver::config::LookupIpStrategy::Ipv6Only,
        (true, true) => hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6,
    };
    let (config, mut resolver_opts) = system_resolv_conf()?;
    resolver_opts.ip_strategy = ip_strategy;
    let resolver = hickory_resolver::AsyncResolver::tokio(config, resolver_opts);

    let client = client::Client {
        http_version,
        url_generator,
        method: opts.method,
        headers,
        body,
        dns: client::Dns {
            resolver,
            connect_to: opts.connect_to,
        },
        timeout: opts.timeout.map(|d| d.into()),
        redirect_limit: opts.redirect,
        disable_keepalive: opts.disable_keepalive,
        insecure: opts.insecure,
        #[cfg(unix)]
        unix_socket: opts.unix_socket,
        #[cfg(feature = "vsock")]
        vsock_addr: opts.vsock_addr.map(|v| v.0),
        #[cfg(feature = "rustls")]
        // Cache rustls_native_certs::load_native_certs() because it's expensive.
        root_cert_store: {
            let mut root_cert_store = rustls::RootCertStore::empty();
            for cert in
                rustls_native_certs::load_native_certs().expect("could not load platform certs")
            {
                root_cert_store.add(cert).unwrap();
            }
            std::sync::Arc::new(root_cert_store)
        },
    };

    if !opts.no_pre_lookup {
        client.pre_lookup().await?;
    }

    let start = std::time::Instant::now();

    let no_tui = opts.no_tui || !std::io::stdout().is_tty() || opts.debug;
    let data_collector = if no_tui {
        // When `--no-tui` is enabled, just collect all data.
        tokio::spawn(async move {
            let mut all = Vec::new();
            tokio::select! {
                _ = async {
                    loop {
                        let data = result_rx.recv_batch(usize::MAX).await;
                        if data.is_empty() {
                            break;
                        }

                        all.extend(data);
                    }
                } => {}
                _ = tokio::signal::ctrl_c() => {
                    // User pressed ctrl-c.
                    /*
                    let _ = printer::print_result(&mut std::io::stdout(), print_mode, start, &all, start.elapsed(), opts.disable_color, opts.stats_success_breakdown);
                    std::process::exit(libc::EXIT_SUCCESS)
                    */
                }
            };
            Ok::<_, Infallible>(all)
        })
    } else {
        todo!()
        /*
        // Spawn monitor future which draws realtime tui
        tokio::spawn(
            monitor::Monitor {
                print_mode,
                end_line: opts
                    .duration
                    .map(|d| monitor::EndLine::Duration(d.into()))
                    .unwrap_or(monitor::EndLine::NumQuery(opts.n_requests)),
                report_receiver: result_rx,
                start,
                fps: opts.fps,
                disable_color: opts.disable_color,
                stats_success_breakdown: opts.stats_success_breakdown,
            }
            .monitor(),
        )
        */
    };
    // When panics, reset terminal mode and exit immediately.
    std::panic::set_hook(Box::new(move |info| {
        if !no_tui {
            use crossterm::ExecutableCommand;
            let _ = std::io::stdout().execute(crossterm::terminal::LeaveAlternateScreen);
            let _ = crossterm::terminal::disable_raw_mode();
            let _ = std::io::stdout().execute(crossterm::cursor::Show);
        }
        eprintln!("{info}");
        std::process::exit(libc::EXIT_FAILURE);
    }));

    if opts.debug {
        if let Err(e) = client::work_debug(client, result_tx).await {
            eprintln!("{e}");
        }
        std::process::exit(libc::EXIT_SUCCESS);
    } else if let Some(duration) = opts.duration.take() {
        match opts.query_per_second {
            Some(0) | None => match opts.burst_duration {
                None => {
                    client::work_until(
                        client,
                        result_tx,
                        start + duration.into(),
                        opts.n_connections,
                        opts.n_http2_parallel,
                        opts.wait_ongoing_requests_after_deadline,
                    )
                    .await
                }
                Some(burst_duration) => {
                    if opts.latency_correction {
                        client::work_until_with_qps_latency_correction(
                            client,
                            result_tx,
                            client::QueryLimit::Burst(
                                burst_duration.into(),
                                opts.burst_requests.unwrap_or(1),
                            ),
                            start,
                            start + duration.into(),
                            opts.n_connections,
                            opts.n_http2_parallel,
                            opts.wait_ongoing_requests_after_deadline,
                        )
                        .await
                    } else {
                        client::work_until_with_qps(
                            client,
                            result_tx,
                            client::QueryLimit::Burst(
                                burst_duration.into(),
                                opts.burst_requests.unwrap_or(1),
                            ),
                            start,
                            start + duration.into(),
                            opts.n_connections,
                            opts.n_http2_parallel,
                            opts.wait_ongoing_requests_after_deadline,
                        )
                        .await
                    }
                }
            },
            Some(qps) => {
                if opts.latency_correction {
                    client::work_until_with_qps_latency_correction(
                        client,
                        result_tx,
                        client::QueryLimit::Qps(qps),
                        start,
                        start + duration.into(),
                        opts.n_connections,
                        opts.n_http2_parallel,
                        opts.wait_ongoing_requests_after_deadline,
                    )
                    .await
                } else {
                    client::work_until_with_qps(
                        client,
                        result_tx,
                        client::QueryLimit::Qps(qps),
                        start,
                        start + duration.into(),
                        opts.n_connections,
                        opts.n_http2_parallel,
                        opts.wait_ongoing_requests_after_deadline,
                    )
                    .await
                }
            }
        }
    } else {
        match opts.query_per_second {
            Some(0) | None => match opts.burst_duration {
                None => {
                    client::work(
                        client,
                        result_tx,
                        opts.n_requests,
                        opts.n_connections,
                        opts.n_http2_parallel,
                    )
                    .await
                }
                Some(burst_duration) => {
                    if opts.latency_correction {
                        client::work_with_qps_latency_correction(
                            client,
                            result_tx,
                            client::QueryLimit::Burst(
                                burst_duration.into(),
                                opts.burst_requests.unwrap_or(1),
                            ),
                            opts.n_requests,
                            opts.n_connections,
                            opts.n_http2_parallel,
                        )
                        .await
                    } else {
                        client::work_with_qps(
                            client,
                            result_tx,
                            client::QueryLimit::Burst(
                                burst_duration.into(),
                                opts.burst_requests.unwrap_or(1),
                            ),
                            opts.n_requests,
                            opts.n_connections,
                            opts.n_http2_parallel,
                        )
                        .await
                    }
                }
            },
            Some(qps) => {
                if opts.latency_correction {
                    client::work_with_qps_latency_correction(
                        client,
                        result_tx,
                        client::QueryLimit::Qps(qps),
                        opts.n_requests,
                        opts.n_connections,
                        opts.n_http2_parallel,
                    )
                    .await
                } else {
                    client::work_with_qps(
                        client,
                        result_tx,
                        client::QueryLimit::Qps(qps),
                        opts.n_requests,
                        opts.n_connections,
                        opts.n_http2_parallel,
                    )
                    .await
                }
            }
        }
    }

    let duration = start.elapsed();

    let res = {
        let all = data_collector.await??;
        let mut res = ResultData::default();
        for data in all {
            res.push(data);
        }
        res
    };

    printer::print_result(
        &mut std::io::stdout(),
        print_mode,
        start,
        &res,
        duration,
        opts.disable_color,
        opts.stats_success_breakdown,
    )?;

    if let Some(db_url) = opts.db_url {
        eprintln!("Storing results to {db_url}");
        let _ = db::store(&db_url, start, res.success());
    }

    Ok(())
}

fn system_resolv_conf() -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
    // check if we are running in termux https://github.com/termux/termux-app
    #[cfg(unix)]
    if env::var("TERMUX_VERSION").is_ok() {
        let prefix = env::var("PREFIX")?;
        let path = format!("{prefix}/etc/resolv.conf");
        let conf_data = std::fs::read(&path).context(format!("DNS: failed to load {path}"))?;
        return hickory_resolver::system_conf::parse_resolv_conf(conf_data)
            .context(format!("DNS: failed to parse {path}"));
    }

    hickory_resolver::system_conf::read_system_conf()
        .context("DNS: failed to load /etc/resolv.conf")
}
