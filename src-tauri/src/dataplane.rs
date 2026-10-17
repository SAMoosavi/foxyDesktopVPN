// Data plane, ported from the reference client `Vauth/FoxyVPN`:
//
// * `GET https://vpn.mozilla.org/api/v1/fpn/token` mints the short-lived
//   **proxy pass** (GuardianClient.fetchProxyPass).
// * A local **SOCKS5** proxy (`127.0.0.1:1080`) and a local **HTTP** proxy
//   (`127.0.0.1:8080`) accept app traffic (LocalSocks5Server /
//   LocalHttpProxyServer).
// * Every target becomes an HTTP/2 `CONNECT <host>:<port>` stream on a TLS
//   connection to the Remote Settings edge (default `port` 2499), carrying
//   `proxy-authorization: Bearer <proxy pass>` — H2UpstreamSession.
// * The exit IP/country is read through the tunnel from Cloudflare's trace
//   endpoint (ExitCheck), and the proxy pass is renewed at half-life
//   (startProxyPassRenewal).
//
// No TUN/route changes are made: this is the reference app's *proxy-only*
// mode, so nothing blackholes traffic if the tunnel dies.
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsConnector;

pub const BIND_ADDRESS: &str = "127.0.0.1";
/// Reference defaults (`SettingsStore.DEFAULT_*`).
pub const SOCKS_PORT: u16 = 1080;
pub const HTTP_PORT: u16 = 8080;

pub const GUARDIAN_FPN_TOKEN_URL: &str = "https://vpn.mozilla.org/api/v1/fpn/token";
const EXIT_CHECK_HOST: &str = "www.cloudflare.com";
const MAX_HEAD_BYTES: usize = 64 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

// ---- Guardian proxy pass (fpn/token) ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPass {
    pub token: String,
    /// Epoch seconds when the pass dies; None when neither the response nor
    /// the JWT states one (renewal then falls back to a fixed interval).
    pub expires_at: Option<i64>,
}

/// Mint a proxy pass with the stored FxA access token, mirroring the
/// reference client's status handling (401/403 = token rejected, 429 = quota).
pub fn fetch_proxy_pass(access_token: &str) -> Result<ProxyPass, String> {
    let response = reqwest::blocking::Client::new()
        .get(GUARDIAN_FPN_TOKEN_URL)
        .header("User-Agent", crate::MOZILLA_VPN_USER_AGENT)
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {access_token}"))
        .timeout(Duration::from_secs(30))
        .send()
        .map_err(|e| format!("Could not reach Guardian: {e}"))?;
    let status = response.status().as_u16();
    match status {
        401 | 403 => return Err(crate::EXPIRED_TOKEN_ERROR.to_owned()),
        429 => return Err("Account proxy quota exceeded — try again later.".into()),
        _ => {}
    }
    let text = response.text().unwrap_or_default();
    if status != 200 {
        return Err(format!(
            "Guardian could not issue a proxy pass (HTTP {status})."
        ));
    }
    parse_proxy_pass(&text)
}

/// Pure JSON/JWT parsing so the shape is unit-tested offline.
pub fn parse_proxy_pass(text: &str) -> Result<ProxyPass, String> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("Invalid Guardian proxy pass response: {e}"))?;
    let token = value
        .get("token")
        .and_then(|v| v.as_str())
        .filter(|token| !token.is_empty())
        .ok_or("Guardian's proxy pass response did not contain a token.")?
        .to_owned();
    let expires_at = match value
        .get("expires_at")
        .and_then(|v| v.as_i64())
        .filter(|seconds| *seconds > 0)
    {
        Some(seconds) => Some(seconds),
        None => jwt_expiry(&token),
    };
    Ok(ProxyPass { token, expires_at })
}

/// `exp` from the proxy-pass JWT payload (base64url), as the reference
/// client's `jwtExpiryEpochSeconds` does.
fn jwt_expiry(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let trimmed = payload.trim_end_matches('=');
    let padded = format!("{trimmed}{}", "=".repeat((4 - trimmed.len() % 4) % 4));
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE
        .decode(padded)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = value.get("exp").and_then(|v| v.as_i64())?;
    (exp > 0).then_some(exp)
}

// ---- TLS ----

fn tls_config(alpn: &[u8]) -> Arc<rustls::ClientConfig> {
    static H2: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static HTTP1: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let slot = if alpn == b"h2" { &H2 } else { &HTTP1 };
    slot.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_owned()];
        Arc::new(config)
    })
    .clone()
}

// ---- Edge session: TLS + HTTP/2 CONNECT ----

struct Edge {
    sender: tokio::sync::Mutex<h2::client::SendRequest<Bytes>>,
    bearer: tokio::sync::RwLock<String>,
}

impl Edge {
    async fn dial(host: &str, port: u16, bearer: String) -> Result<Arc<Edge>, String> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
            .await
            .map_err(|_| format!("Timed out reaching the VPN edge {host}:{port}."))?
            .map_err(|e| format!("Could not reach the VPN edge {host}:{port}: {e}"))?;
        let _ = stream.set_nodelay(true);
        let connector = TlsConnector::from(tls_config(b"h2"));
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|e| format!("Invalid edge hostname {host}: {e}"))?;
        let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, stream))
            .await
            .map_err(|_| {
                format!("Timed out on the TLS handshake with the VPN edge {host}:{port}.")
            })?
            .map_err(|e| format!("TLS handshake with the VPN edge failed: {e}"))?;
        match tls.get_ref().1.alpn_protocol() {
            Some(b"h2") => {}
            other => {
                return Err(format!(
                    "The VPN edge did not negotiate HTTP/2 (ALPN {})",
                    other
                        .map(|p| String::from_utf8_lossy(p).into_owned())
                        .unwrap_or_default()
                ));
            }
        }
        let (sender, connection) = h2::client::handshake(tls)
            .await
            .map_err(|e| format!("HTTP/2 handshake with the VPN edge failed: {e}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Arc::new(Edge {
            sender: tokio::sync::Mutex::new(sender),
            bearer: tokio::sync::RwLock::new(bearer),
        }))
    }

    /// One `CONNECT <authority>` stream, authorized with the current proxy
    /// pass — the reference client's `H2UpstreamSession.openStream`.
    async fn open_stream(&self, authority: &str) -> Result<H2Tunnel, String> {
        let sender = self.sender.lock().await.clone();
        let mut sender = tokio::time::timeout(CONNECT_TIMEOUT, sender.ready())
            .await
            .map_err(|_| "Timed out waiting for the VPN edge connection.".to_owned())?
            .map_err(|e| format!("The VPN edge connection is not ready: {e}"))?;
        let bearer = self.bearer.read().await.clone();
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(authority)
            .header("proxy-authorization", format!("Bearer {bearer}"))
            .body(())
            .expect("a CONNECT request with a static body always builds");
        let (response, send) = sender
            .send_request(request, false)
            .map_err(|e| format!("Could not open a tunnel stream to {authority}: {e}"))?;
        let response = tokio::time::timeout(OPEN_TIMEOUT, response)
            .await
            .map_err(|_| format!("Timed out waiting for the edge to accept {authority}."))?
            .map_err(|e| format!("Edge stream error for {authority}: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("Edge rejected CONNECT {authority}: HTTP {status}"));
        }
        Ok(H2Tunnel {
            send,
            recv: response.into_body(),
            pending: None,
        })
    }
}

/// An accepted H2 stream presented as an ordinary bidirectional byte stream,
/// so the local proxies can relay with `copy_bidirectional`.
pub struct H2Tunnel {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    pending: Option<Bytes>,
}

impl AsyncRead for H2Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if let Some(mut pending) = self.pending.take() {
            let n = buf.remaining().min(pending.len());
            buf.put_slice(&pending[..n]);
            if n < pending.len() {
                self.pending = Some(pending.split_off(n));
            }
            let _ = self.recv.flow_control().release_capacity(n);
            return std::task::Poll::Ready(Ok(()));
        }
        loop {
            match Pin::new(&mut self.recv).poll_data(cx) {
                std::task::Poll::Ready(Some(Ok(mut data))) => {
                    if data.is_empty() {
                        continue;
                    }
                    let n = buf.remaining().min(data.len());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        self.pending = Some(data.split_off(n));
                    }
                    let _ = self.recv.flow_control().release_capacity(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Err(io::Error::other(e)));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.send.reserve_capacity(buf.len());
        loop {
            match self.send.poll_capacity(cx) {
                std::task::Poll::Ready(Some(Ok(capacity))) => {
                    if capacity == 0 {
                        self.send.reserve_capacity(buf.len());
                        continue;
                    }
                    let n = capacity.min(buf.len());
                    if let Err(e) = self
                        .send
                        .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    {
                        return std::task::Poll::Ready(Err(io::Error::other(e)));
                    }
                    return std::task::Poll::Ready(Ok(n));
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Err(io::Error::other(e)));
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(Err(io::Error::other("tunnel stream closed")));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let _ = self.send.send_data(Bytes::new(), true);
        std::task::Poll::Ready(Ok(()))
    }
}

// ---- Upstream seam (real edge in production, scripted in tests) ----

pub trait TunnelStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> TunnelStream for T {}

pub type OpenFuture = Pin<Box<dyn Future<Output = Result<Box<dyn TunnelStream>, String>> + Send>>;

pub trait Upstream: Send + Sync + 'static {
    /// Open a tunneled byte stream to `authority` (`host:port`).
    fn open(&self, authority: &str) -> OpenFuture;
}

struct EdgeUpstream {
    edge: Arc<Edge>,
}

impl Upstream for EdgeUpstream {
    fn open(&self, authority: &str) -> OpenFuture {
        let edge = self.edge.clone();
        let authority = authority.to_owned();
        Box::pin(async move {
            edge.open_stream(&authority)
                .await
                .map(|tunnel| Box::new(tunnel) as Box<dyn TunnelStream>)
        })
    }
}

// ---- Local target guard (the reference proxies never carry local traffic) ----

pub fn is_local_target(host: &str) -> bool {
    let host = host.trim().trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        return true;
    }
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_private() || v4.is_loopback() || v4.is_link_local())
        }
    }
}

fn authority_of(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ---- Local HTTP proxy ----

async fn read_head<S>(stream: &mut S, buf: &mut Vec<u8>) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    loop {
        if buf.len() > MAX_HEAD_BYTES {
            return Err(io::Error::other("proxy request head too large"));
        }
        let read = tokio::time::timeout(HEAD_TIMEOUT, stream.read(&mut byte))
            .await
            .map_err(|_| io::Error::other("timed out reading the proxy request"))??;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(());
        }
    }
}

/// Absolute-URI (or origin-form + Host) target → (host, port, path).
pub fn parse_forward_target(
    target: &str,
    host_header: Option<&str>,
) -> Option<(String, u16, String)> {
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let (host, port) = split_authority(authority, 80);
        return Some((host, port, path.to_owned()));
    }
    if let Some(rest) = target.strip_prefix("https://") {
        // Absolute https URI without CONNECT: forward to port 443.
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let (host, port) = split_authority(authority, 443);
        return Some((host, port, path.to_owned()));
    }
    let host_header = host_header?;
    let (host, port) = split_authority(host_header, 80);
    if host.is_empty() {
        return None;
    }
    Some((host, port, target.to_owned()))
}

fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = authority.strip_prefix('[') {
        // [v6]:port
        if let Some((host, rest)) = rest.split_once(']') {
            let port = rest
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (host.to_owned(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
            (host.to_owned(), port.parse::<u16>().unwrap_or(default_port))
        }
        _ => (authority.to_owned(), default_port),
    }
}

async fn handle_http<S>(mut client: S, upstream: Arc<dyn Upstream>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut head = Vec::new();
    read_head(&mut client, &mut head).await.ok();
    if head.is_empty() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or("HTTP/1.1").to_owned();
    if method.is_empty() || target.is_empty() {
        let _ = client
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nProxy-Agent: FoxyVPN\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        return Ok(());
    }
    let mut headers = Vec::new();
    let mut host_header: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            host_header = Some(value.trim().to_owned());
        }
        if !line.to_ascii_lowercase().starts_with("proxy-connection:") {
            headers.push(line.to_owned());
        }
    }

    let (authority, request_prefix) = if method == "CONNECT" {
        (target.clone(), String::new())
    } else {
        let Some((host, port, path)) = parse_forward_target(&target, host_header.as_deref()) else {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nProxy-Agent: FoxyVPN\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        };
        let host_in_headers = host_header
            .clone()
            .unwrap_or_else(|| authority_of(&host, port));
        let mut request = format!("{method} {path} {version}\r\nHost: {host_in_headers}\r\n");
        for header in &headers {
            if header.to_ascii_lowercase().starts_with("host:") {
                continue;
            }
            request.push_str(header);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        (authority_of(&host, port), request)
    };

    let target_host = authority
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or(&authority)
        .to_owned();
    if is_local_target(&target_host) {
        let _ = client
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\nProxy-Agent: FoxyVPN\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        return Ok(());
    }

    let mut tunneled = match upstream.open(&authority).await {
        Ok(tunneled) => tunneled,
        Err(error) => {
            let mut response = format!(
                "HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: FoxyVPN\r\nContent-Length: {}\r\n\r\n",
                error.len()
            );
            response.push_str(&error);
            let _ = client.write_all(response.as_bytes()).await;
            return Ok(());
        }
    };

    if method == "CONNECT" {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: FoxyVPN\r\n\r\n")
            .await?;
    } else {
        tunneled.write_all(request_prefix.as_bytes()).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut tunneled).await?;
    Ok(())
}

pub async fn serve_http(
    listener: TcpListener,
    upstream: Arc<dyn Upstream>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    let _ = handle_http(stream, upstream).await;
                });
            }
        }
    }
}

// ---- Local SOCKS5 proxy ----

fn socks_reply(code: u8) -> [u8; 10] {
    [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

async fn read_exact_for<S>(stream: &mut S, buf: &mut [u8]) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| io::Error::other("timed out in the SOCKS5 handshake"))??;
    Ok(())
}

async fn handle_socks<S>(mut client: S, upstream: Arc<dyn Upstream>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut greeting = [0u8; 2];
    read_exact_for(&mut client, &mut greeting).await?;
    if greeting[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    if !methods.is_empty() {
        read_exact_for(&mut client, &mut methods).await?;
    }
    if !methods.contains(&0u8) {
        client.write_all(&[5, 0xFF]).await?;
        return Ok(());
    }
    client.write_all(&[5, 0]).await?;

    let mut header = [0u8; 4];
    read_exact_for(&mut client, &mut header).await?;
    if header[0] != 5 {
        client.write_all(&socks_reply(0x07)).await?;
        return Ok(());
    }
    if header[1] != 0x01 {
        // BIND (0x02) and UDP ASSOCIATE (0x03) are not carried by the edge.
        client.write_all(&socks_reply(0x07)).await?;
        return Ok(());
    }
    let (host, literal) = match header[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            read_exact_for(&mut client, &mut ip).await?;
            (std::net::Ipv4Addr::from(ip).to_string(), true)
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_for(&mut client, &mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            if !name.is_empty() {
                read_exact_for(&mut client, &mut name).await?;
            }
            (String::from_utf8_lossy(&name).into_owned(), false)
        }
        0x04 => {
            let mut ip = [0u8; 16];
            read_exact_for(&mut client, &mut ip).await?;
            (std::net::Ipv6Addr::from(ip).to_string(), true)
        }
        _ => {
            client.write_all(&socks_reply(0x08)).await?;
            return Ok(());
        }
    };
    let mut port_bytes = [0u8; 2];
    read_exact_for(&mut client, &mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    if is_local_target(&host) {
        // Same policy as the reference proxies: local traffic is never tunneled.
        client
            .write_all(&socks_reply(if literal { 0x02 } else { 0x04 }))
            .await?;
        return Ok(());
    }

    let authority = authority_of(&host, port);
    let mut tunneled = match upstream.open(&authority).await {
        Ok(tunneled) => tunneled,
        Err(error) => {
            let code = if error.contains("refused") {
                0x05
            } else if error.contains("unreachable")
                || error.contains("Timed out")
                || error.contains("timed out")
            {
                0x04
            } else {
                0x01
            };
            client.write_all(&socks_reply(code)).await?;
            return Ok(());
        }
    };
    client.write_all(&socks_reply(0x00)).await?;
    tokio::io::copy_bidirectional(&mut client, &mut tunneled).await?;
    Ok(())
}

pub async fn serve_socks(
    listener: TcpListener,
    upstream: Arc<dyn Upstream>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    let _ = handle_socks(stream, upstream).await;
                });
            }
        }
    }
}

// ---- Exit check through the tunnel ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub ip: String,
    pub country: String,
}

/// `ip=` / `loc=` from Cloudflare's trace page (ExitCheck's parser).
pub fn parse_trace(body: &str) -> Result<ExitInfo, String> {
    fn field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
        body.lines()
            .find_map(|line| line.strip_prefix(key))
            .filter(|value| !value.is_empty())
    }
    let ip = field(body, "ip=")
        .ok_or("Exit check returned no IP.")?
        .to_owned();
    let country = field(body, "loc=").unwrap_or_default().to_owned();
    Ok(ExitInfo { ip, country })
}

async fn exit_check(edge: &Arc<Edge>) -> Result<ExitInfo, String> {
    let tunnel = edge
        .open_stream(&authority_of(EXIT_CHECK_HOST, 443))
        .await
        .map_err(|e| format!("Could not open the exit check through the tunnel: {e}"))?;
    let connector = TlsConnector::from(tls_config(b"http/1.1"));
    let server_name =
        tokio_rustls::rustls::pki_types::ServerName::try_from(EXIT_CHECK_HOST.to_owned())
            .map_err(|e| format!("Invalid exit-check hostname: {e}"))?;
    let mut tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tunnel))
        .await
        .map_err(|_| "Timed out on the exit check TLS handshake.".to_owned())?
        .map_err(|e| format!("Exit check TLS handshake failed: {e}"))?;
    let request = format!(
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {EXIT_CHECK_HOST}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
        crate::MOZILLA_VPN_USER_AGENT
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("Could not write the exit check request: {e}"))?;
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), tls.read_to_end(&mut body))
        .await
        .map_err(|_| "Timed out reading the exit check response.".to_owned())?
        .map_err(|e| format!("Could not read the exit check response: {e}"))?;
    parse_trace(&String::from_utf8_lossy(&body))
}

// ---- Proxy-pass renewal at half-life (startProxyPassRenewal) ----

async fn renew_proxy_pass(edge: Arc<Edge>, mut expires_at: Option<i64>) {
    loop {
        let delay = match expires_at {
            Some(expiry) => {
                let remaining = (expiry - crate::now_secs()).max(0);
                Duration::from_secs(((remaining / 2).clamp(30, 600)) as u64)
            }
            None => Duration::from_secs(300),
        };
        tokio::time::sleep(delay).await;
        let minted = tokio::task::spawn_blocking(|| -> Result<ProxyPass, String> {
            let session =
                crate::load_session().ok_or_else(|| crate::SIGNED_OUT_ERROR.to_owned())?;
            let access_token = if session.needs_refresh(crate::now_secs()) {
                let refresh = session
                    .refresh_token
                    .clone()
                    .ok_or_else(|| crate::EXPIRED_TOKEN_ERROR.to_owned())?;
                crate::refresh_session(&refresh, crate::now_secs())?.access_token
            } else {
                session.access_token
            };
            fetch_proxy_pass(&access_token)
        })
        .await;
        match minted {
            Ok(Ok(pass)) => {
                *edge.bearer.write().await = pass.token;
                expires_at = pass.expires_at;
            }
            _ => {
                // Transient failure: the live pass keeps working until its own
                // expiry; retry on the fallback interval.
                expires_at = None;
            }
        }
    }
}

// ---- Start / stop ----

#[derive(Debug, Clone, serde::Serialize)]
pub struct Info {
    pub socks_port: u16,
    pub http_port: u16,
    pub exit_ip: String,
    pub exit_country: String,
    /// True when the desktop's system proxy was pointed at the local proxy.
    pub system_proxy: bool,
}

impl Info {
    /// Human line for the status UI, e.g.
    /// `SOCKS5 127.0.0.1:1080 · HTTP 127.0.0.1:8080`.
    pub fn proxy_label(&self) -> String {
        format!(
            "SOCKS5 {BIND_ADDRESS}:{} · HTTP {BIND_ADDRESS}:{}",
            self.socks_port, self.http_port
        )
    }
}

struct Running {
    stop: watch::Sender<bool>,
    join: Option<std::thread::JoinHandle<()>>,
}

fn running() -> &'static StdMutex<Option<Running>> {
    static RUNNING: OnceLock<StdMutex<Option<Running>>> = OnceLock::new();
    RUNNING.get_or_init(|| StdMutex::new(None))
}

async fn setup(
    host: &str,
    port: u16,
    bearer: String,
    expires_at: Option<i64>,
    stop: watch::Receiver<bool>,
) -> Result<Info, String> {
    let socks = TcpListener::bind((BIND_ADDRESS, SOCKS_PORT))
        .await
        .map_err(|e| {
            format!("Could not start the local SOCKS5 proxy on {BIND_ADDRESS}:{SOCKS_PORT}: {e}")
        })?;
    let http = TcpListener::bind((BIND_ADDRESS, HTTP_PORT))
        .await
        .map_err(|e| {
            format!("Could not start the local HTTP proxy on {BIND_ADDRESS}:{HTTP_PORT}: {e}")
        })?;
    let edge = Edge::dial(host, port, bearer).await?;
    let exit = exit_check(&edge).await?;

    let upstream: Arc<dyn Upstream> = Arc::new(EdgeUpstream { edge: edge.clone() });
    tokio::spawn(serve_socks(socks, upstream.clone(), stop.clone()));
    tokio::spawn(serve_http(http, upstream, stop.clone()));
    tokio::spawn(renew_proxy_pass(edge, expires_at));

    let system_proxy = apply_system_proxy().is_ok();
    Ok(Info {
        socks_port: SOCKS_PORT,
        http_port: HTTP_PORT,
        exit_ip: exit.ip,
        exit_country: exit.country,
        system_proxy,
    })
}

/// Bring up the whole data plane for one edge. Stops any previous instance
/// first, and cleans up completely on failure (listeners, runtime, system
/// proxy), so a failed connect never leaves half a proxy behind.
pub fn start(
    host: &str,
    port: u16,
    bearer: String,
    expires_at: Option<i64>,
) -> Result<Info, String> {
    stop();
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let host = host.to_owned();
    let join = std::thread::Builder::new()
        .name("foxy-dataplane".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("Could not start the VPN data plane: {e}")));
                    return;
                }
            };
            let result = runtime.block_on(setup(&host, port, bearer, expires_at, stop_rx.clone()));
            match result {
                Err(error) => {
                    // Dropping the runtime closes both listeners and tasks.
                    let _ = ready_tx.send(Err(error));
                }
                Ok(info) => {
                    let _ = ready_tx.send(Ok(info));
                    runtime.block_on(async move {
                        let _ = stop_rx.changed().await;
                    });
                }
            }
        })
        .map_err(|e| format!("Could not spawn the VPN data plane: {e}"))?;

    let info = ready_rx
        .recv()
        .map_err(|_| "The VPN data plane stopped before it was ready.".to_owned())??;
    // Take ownership of the (just-applied) system proxy only after the data
    // plane is ready; from here on `stop()` is what restores it.
    *running().lock().unwrap() = Some(Running {
        stop: stop_tx,
        join: Some(join),
    });
    Ok(info)
}

/// Tear the data plane down and restore whatever system proxy we replaced.
///
/// The system proxy is only restored when *this process* started a data plane
/// (owns the `Running` slot): `stop()` is also called from unit tests and from
/// `close_tunnel()` in paths that never applied anything, and those must never
/// rewrite — or delete the snapshot of — a proxy set by a live app instance.
pub fn stop() {
    let Some(mut running) = running().lock().unwrap().take() else {
        return;
    };
    let _ = running.stop.send(true);
    if let Some(join) = running.join.take() {
        // The accept loops wake on the watch message; the runtime drop
        // then aborts idle relay tasks, so this returns promptly.
        let _ = join.join();
    }
    restore_system_proxy();
}

// ---- System proxy (GNOME/gsettings), restored on disconnect ----

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ProxySnapshot {
    mode: String,
    http_host: String,
    http_port: String,
    https_host: String,
    https_port: String,
    socks_host: String,
    socks_port: String,
}

fn snapshot_path() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
        })
        .unwrap_or_else(std::env::temp_dir);
    base.join("foxy-desktop-vpn").join("system-proxy.json")
}

fn gsettings_get(schema: &str, key: &str) -> Option<String> {
    let output = std::process::Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn gsettings_set(schema: &str, key: &str, value: &str) -> bool {
    std::process::Command::new("gsettings")
        .args(["set", schema, key, value])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Point the desktop's proxy settings at the local proxies (best effort):
/// returns Ok(false) when gsettings isn't available, in which case apps must
/// be pointed at the proxy themselves — the label says where.
fn apply_system_proxy() -> Result<bool, ()> {
    let Some(mode) = gsettings_get("org.gnome.system.proxy", "mode") else {
        return Err(());
    };
    let snapshot = ProxySnapshot {
        mode,
        http_host: gsettings_get("org.gnome.system.proxy.http", "host").unwrap_or_default(),
        http_port: gsettings_get("org.gnome.system.proxy.http", "port").unwrap_or_default(),
        https_host: gsettings_get("org.gnome.system.proxy.https", "host").unwrap_or_default(),
        https_port: gsettings_get("org.gnome.system.proxy.https", "port").unwrap_or_default(),
        socks_host: gsettings_get("org.gnome.system.proxy.socks", "host").unwrap_or_default(),
        socks_port: gsettings_get("org.gnome.system.proxy.socks", "port").unwrap_or_default(),
    };
    let applied = gsettings_set("org.gnome.system.proxy", "mode", "'manual'")
        && gsettings_set(
            "org.gnome.system.proxy.http",
            "host",
            &format!("'{BIND_ADDRESS}'"),
        )
        && gsettings_set(
            "org.gnome.system.proxy.http",
            "port",
            &HTTP_PORT.to_string(),
        )
        && gsettings_set(
            "org.gnome.system.proxy.https",
            "host",
            &format!("'{BIND_ADDRESS}'"),
        )
        && gsettings_set(
            "org.gnome.system.proxy.https",
            "port",
            &HTTP_PORT.to_string(),
        )
        && gsettings_set(
            "org.gnome.system.proxy.socks",
            "host",
            &format!("'{BIND_ADDRESS}'"),
        )
        && gsettings_set(
            "org.gnome.system.proxy.socks",
            "port",
            &SOCKS_PORT.to_string(),
        );
    if !applied {
        return Err(());
    }
    // Persist the snapshot so a crash can still be undone (see run()).
    if let Some(dir) = snapshot_path().parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(json) = serde_json::to_string(&snapshot) {
        let _ = std::fs::write(snapshot_path(), json);
    }
    Ok(true)
}

/// Undo a previous run's (or a crash's) proxy change. Called on disconnect and
/// at app start, so a killed session never leaves a dead proxy configured.
pub fn restore_system_proxy() {
    let Ok(json) = std::fs::read_to_string(snapshot_path()) else {
        return;
    };
    let Ok(snapshot) = serde_json::from_str::<ProxySnapshot>(&json) else {
        return;
    };
    gsettings_set("org.gnome.system.proxy.http", "host", &snapshot.http_host);
    gsettings_set("org.gnome.system.proxy.http", "port", &snapshot.http_port);
    gsettings_set("org.gnome.system.proxy.https", "host", &snapshot.https_host);
    gsettings_set("org.gnome.system.proxy.https", "port", &snapshot.https_port);
    gsettings_set("org.gnome.system.proxy.socks", "host", &snapshot.socks_host);
    gsettings_set("org.gnome.system.proxy.socks", "port", &snapshot.socks_port);
    gsettings_set("org.gnome.system.proxy", "mode", &snapshot.mode);
    let _ = std::fs::remove_file(snapshot_path());
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Far side of the tunnel: echoes bytes back, recording authorities.
    #[derive(Default)]
    struct EchoUpstream {
        authorities: StdMutex<Vec<String>>,
    }

    impl Upstream for EchoUpstream {
        fn open(&self, authority: &str) -> OpenFuture {
            self.authorities.lock().unwrap().push(authority.to_owned());
            Box::pin(async {
                let (mut far, near) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match far.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if far.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                Ok(Box::new(near) as Box<dyn TunnelStream>)
            })
        }
    }

    /// Reads whatever the proxy produced so far (bounded, never hangs).
    async fn read_available<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
                Ok(Err(_)) => break,
            }
            if out.len() >= 4096 {
                break;
            }
        }
        out
    }

    fn upstream() -> Arc<EchoUpstream> {
        Arc::new(EchoUpstream::default())
    }

    #[tokio::test]
    async fn http_connect_establishes_and_relays() {
        let upstream = upstream();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let hooks = upstream.clone();
        tokio::spawn(async move {
            let _ = handle_http(server, hooks).await;
        });
        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        let head = read_available(&mut client).await;
        let head = String::from_utf8_lossy(&head);
        assert!(
            head.starts_with("HTTP/1.1 200 Connection Established"),
            "CONNECT must be acknowledged, got: {head:?}"
        );
        assert_eq!(
            upstream.authorities.lock().unwrap().as_slice(),
            ["example.com:443"]
        );

        client.write_all(b"ping").await.unwrap();
        let echo = read_available(&mut client).await;
        assert_eq!(echo, b"ping");
    }

    #[tokio::test]
    async fn http_forward_rewrites_request_line_and_keeps_host() {
        let upstream = upstream();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let hooks = upstream.clone();
        tokio::spawn(async move {
            let _ = handle_http(server, hooks).await;
        });
        client
            .write_all(
                b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n",
            )
            .await
            .unwrap();
        let echoed = read_available(&mut client).await;
        let echoed = String::from_utf8_lossy(&echoed);
        assert_eq!(
            upstream.authorities.lock().unwrap().as_slice(),
            ["example.com:80"]
        );
        assert!(
            echoed.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
            "absolute URI must be rewritten to origin form, got: {echoed:?}"
        );
        assert!(
            echoed.contains("Host: example.com\r\n"),
            "Host kept: {echoed:?}"
        );
        assert!(
            !echoed.to_lowercase().contains("proxy-connection:"),
            "hop-by-hop header dropped: {echoed:?}"
        );
    }

    #[tokio::test]
    async fn http_refuses_local_targets() {
        let upstream = upstream();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let hooks = upstream.clone();
        tokio::spawn(async move {
            let _ = handle_http(server, hooks).await;
        });
        client
            .write_all(b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
            .await
            .unwrap();
        let head = read_available(&mut client).await;
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 403 Forbidden"),
            "local targets must never be tunneled"
        );
        assert!(upstream.authorities.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn socks5_connect_handshake_and_relay() {
        let upstream = upstream();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let hooks = upstream.clone();
        tokio::spawn(async move {
            let _ = handle_socks(server, hooks).await;
        });

        // Greeting: version 5, no-auth.
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, [5, 0]);

        // CONNECT example.com:443 by domain name.
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply[0], 5);
        assert_eq!(reply[1], 0, "SOCKS CONNECT must succeed, got {reply:?}");
        assert_eq!(
            upstream.authorities.lock().unwrap().as_slice(),
            ["example.com:443"]
        );

        client.write_all(b"ping").await.unwrap();
        let echo = read_available(&mut client).await;
        assert_eq!(echo, b"ping");
    }

    #[tokio::test]
    async fn socks5_refuses_local_targets() {
        let upstream = upstream();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let hooks = upstream.clone();
        tokio::spawn(async move {
            let _ = handle_socks(server, hooks).await;
        });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut buf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, [5, 0]);

        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&8080u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reply[1], 0x02,
            "local target must be refused, got {reply:?}"
        );
        assert!(upstream.authorities.lock().unwrap().is_empty());
    }

    #[test]
    fn local_target_policy_matches_the_reference_proxies() {
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.7",
            "172.16.4.5",
            "::1",
            "fd00::1",
            "fe80::1",
            "localhost",
            "0.0.0.0",
            "169.254.1.1",
        ] {
            assert!(is_local_target(local), "{local} must be treated as local");
        }
        for remote in [
            "1.1.1.1",
            "example.com",
            "faor73.m1.fastly-masque.net",
            "2606:4700::1111",
        ] {
            assert!(!is_local_target(remote), "{remote} must stay tunneled");
        }
    }

    #[test]
    fn proxy_pass_parses_token_and_jwt_expiry() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"1;FXA","exp":1792245802}"#);
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload}.signature");
        let pass = parse_proxy_pass(&format!(r#"{{"token":"{token}"}}"#)).expect("pass parses");
        assert_eq!(pass.token, token);
        assert_eq!(pass.expires_at, Some(1_792_245_802));

        let explicit = parse_proxy_pass(r#"{"token":"t","expires_at":42}"#).expect("pass parses");
        assert_eq!(explicit.expires_at, Some(42));

        assert!(
            parse_proxy_pass(r#"{}"#).is_err(),
            "missing token is an error"
        );
        assert!(
            parse_proxy_pass("not json").is_err(),
            "bad JSON is an error"
        );
    }

    #[test]
    fn exit_trace_parses_ip_and_country() {
        let body = "fl=123f\nh=www.cloudflare.com\nip=203.0.113.9\nts=1792245000\nloc=DE\n";
        let info = parse_trace(body).expect("trace parses");
        assert_eq!(info.ip, "203.0.113.9");
        assert_eq!(info.country, "DE");
        assert!(parse_trace("no ip here").is_err(), "missing ip is an error");
    }

    #[test]
    fn forward_target_parsing_handles_ports_and_paths() {
        assert_eq!(
            parse_forward_target("http://example.com:8080/a/b", None),
            Some(("example.com".to_owned(), 8080, "/a/b".to_owned()))
        );
        assert_eq!(
            parse_forward_target("/origin/path", Some("example.com:443")),
            Some(("example.com".to_owned(), 443, "/origin/path".to_owned()))
        );
        assert_eq!(parse_forward_target("/no-host", None), None);
    }
}
