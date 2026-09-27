#![forbid(unsafe_code)]
//! fake-transport — a stand-in route, used before a real one exists.
//!
//! A SOCKS5 or HTTP proxy that logs every request. It exists so that
//! isolation, fail-closed behaviour and leak testing can be finished before a
//! real transport is wired in. "Build the isolation" and "integrate a
//! transport" are different problems; combined, neither failure can be
//! diagnosed.
//!
//! Its log is also the data source for showing which route a request took.
//!
//! Protocols:
//!   --proto socks5  SOCKS5, the way Tor offers it (the default)
//!   --proto http    an HTTP proxy, the way I2P routers offer it: CONNECT for
//!                   tunnels, and absolute URIs (`GET http://host/path`) for
//!                   plain HTTP
//!
//! Modes:
//!   --mode connect  actually connect (an ordinary proxy)
//!   --mode sink     accept and discard (connection succeeds, nothing leaves)
//!   --mode deny     refuse everything (fail-closed testing)
//!
//! Both protocols write the same log: the same events with the same fields,
//! plus `proto`. `iso`, which SOCKS5 carries in its username, is null over
//! HTTP, where there is nothing to carry it in.
//!
//! Standard library only. A test rig with no dependencies has nothing that can
//! shift underneath it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Connect,
    Sink,
    Deny,
}

#[derive(Clone, Copy, PartialEq)]
enum Proto {
    Socks5,
    Http,
}

impl Proto {
    fn name(self) -> &'static str {
        match self {
            Proto::Socks5 => "socks5",
            Proto::Http => "http",
        }
    }
}

struct Cfg {
    listen: String,
    mode: Mode,
    proto: Proto,
    log: Option<String>,
    label: String,
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn jesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// One field of a log line. `Null` is for a field the protocol in use has no
/// value for, so that an event carries the same keys whichever protocol
/// produced it.
#[derive(Clone)]
enum V {
    S(String),
    Null,
}

impl From<String> for V {
    fn from(s: String) -> V {
        V::S(s)
    }
}

impl From<&str> for V {
    fn from(s: &str) -> V {
        V::S(s.to_string())
    }
}

impl From<Option<String>> for V {
    fn from(o: Option<String>) -> V {
        o.map_or(V::Null, V::S)
    }
}

struct Journal {
    sink: Mutex<Option<std::fs::File>>,
    seq: AtomicU64,
}

impl Journal {
    fn write(&self, fields: &[(&str, V)]) {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut line = format!("{{\"seq\":{},\"t\":{}", n, now_ms());
        for (k, v) in fields {
            match v {
                V::S(s) => line.push_str(&format!(",\"{}\":\"{}\"", k, jesc(s))),
                V::Null => line.push_str(&format!(",\"{}\":null", k)),
            }
        }
        line.push_str("}\n");
        if let Ok(mut g) = self.sink.lock() {
            match g.as_mut() {
                Some(f) => {
                    let _ = f.write_all(line.as_bytes());
                    let _ = f.flush();
                }
                None => {
                    print!("{}", line);
                    let _ = std::io::stdout().flush();
                }
            }
        }
    }
}

/// `host:port`, with an IPv6 literal in brackets. Without them the port cannot
/// be told apart from the address: `2001:db8::1:443`.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Splits `host:port` or `[v6]:port` into the bare host and the port. The port
/// may be left out only where the protocol has a default for it.
fn split_host_port(s: &str, default: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (h, after) = rest.split_once(']')?;
            if after.is_empty() {
                (h, None)
            } else {
                (h, Some(after.strip_prefix(':')?))
            }
        }
        None => match s.rsplit_once(':') {
            // A second colon is an IPv6 literal without its brackets, and then
            // which part is the port cannot be known.
            Some((h, _)) if h.contains(':') => return None,
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        },
    };
    let port = match port {
        Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0)?,
        None => default?,
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// What kind of address a client named, in the words SOCKS5 uses — so that
/// `addrtype` means the same thing whichever protocol asked. Over HTTP an
/// address arrives as text, and a name that looks like one is one.
fn kind_of(host: &str) -> &'static str {
    if host.parse::<Ipv4Addr>().is_ok() {
        "ipv4"
    } else if host.parse::<Ipv6Addr>().is_ok() {
        "ipv6"
    } else {
        "domain"
    }
}

/// What the client is told for each outcome, in its own protocol.
struct Answers {
    /// Sent once upstream is connected. `None` where the origin's own response
    /// is the answer: a plain HTTP request, forwarded.
    granted: Option<Vec<u8>>,
    /// Sent in sink mode, which pretends the connection was made.
    sunk: Vec<u8>,
    refused: Vec<u8>,
    failed: Vec<u8>,
}

fn socks_answers() -> Answers {
    Answers {
        granted: Some(vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
        sunk: vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        refused: vec![5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
        failed: vec![5, 4, 0, 1, 0, 0, 0, 0, 0, 0],
    }
}

const TUNNEL: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// A complete response from the proxy itself. It closes the connection after
/// it, so that the next request arrives on a new one — and in the log.
fn http_answer(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn http_answers(tunnel: bool) -> Answers {
    Answers {
        granted: tunnel.then(|| TUNNEL.to_vec()),
        sunk: if tunnel { TUNNEL.to_vec() } else { http_answer("200 OK", "") },
        refused: http_answer("403 Forbidden", "fake-transport: refused (--mode deny).\n"),
        failed: http_answer("502 Bad Gateway", "fake-transport: could not connect to the target.\n"),
    }
}

/// A request, whichever protocol it came in.
struct Request {
    /// `host:port` for the log, an IPv6 literal in brackets.
    target: String,
    /// The host as the client named it, without brackets. Not resolved here.
    host: String,
    port: u16,
    addrtype: &'static str,
    iso: Option<String>,
    /// A plain HTTP request as it goes to the origin, head rewritten.
    head: Option<Vec<u8>>,
    /// What the client sent after the part that was read: the start of a
    /// request body, or of the tunnel.
    rest: Vec<u8>,
    answers: Answers,
}

enum Parsed {
    Asked(Request),
    /// Something this proxy does not do, and what to answer it with.
    Rejected { why: String, answer: Vec<u8> },
    /// The client left before asking for anything, the way browsers drop the
    /// connections they open speculatively. Nothing to log.
    Gone,
}

/// Read the SOCKS5 address field, returning (display string, target).
/// Domains are deliberately not resolved here: *where* resolution happens is
/// precisely what is under test.
fn read_target(s: &mut TcpStream) -> std::io::Result<(String, String, u16, &'static str)> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "socks version"));
    }
    let cmd = head[1];
    if cmd != 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "only CONNECT is supported"));
    }
    let (host, kind) = match head[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b)?;
            (format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), "ipv4")
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            let mut b = vec![0u8; l[0] as usize];
            s.read_exact(&mut b)?;
            (String::from_utf8_lossy(&b).to_string(), "domain")
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b)?;
            // The standard form (2001:db8::1), which is also what a client
            // would have typed.
            (Ipv6Addr::from(b).to_string(), "ipv6")
        }
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("address type {}", other),
            ))
        }
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p)?;
    let port = u16::from_be_bytes(p);
    Ok((host_port(&host, port), host, port, kind))
}

fn socks_request(c: &mut TcpStream) -> std::io::Result<Parsed> {
    // Greeting. Username/password auth is accepted because stream isolation
    // rides in those fields, so whatever label a client attaches shows up here.
    let mut hello = [0u8; 2];
    c.read_exact(&mut hello)?;
    let nmethods = hello[1] as usize;
    let mut methods = vec![0u8; nmethods];
    c.read_exact(&mut methods)?;
    let mut auth_user = String::new();
    if methods.contains(&2) {
        c.write_all(&[5, 2])?;
        let mut h = [0u8; 2];
        c.read_exact(&mut h)?;
        let mut u = vec![0u8; h[1] as usize];
        c.read_exact(&mut u)?;
        auth_user = String::from_utf8_lossy(&u).to_string();
        let mut pl = [0u8; 1];
        c.read_exact(&mut pl)?;
        let mut p = vec![0u8; pl[0] as usize];
        c.read_exact(&mut p)?;
        c.write_all(&[1, 0])?;
    } else {
        c.write_all(&[5, 0])?;
    }

    Ok(match read_target(c) {
        Ok((target, host, port, addrtype)) => Parsed::Asked(Request {
            target,
            host,
            port,
            addrtype,
            iso: Some(auth_user),
            head: None,
            rest: Vec::new(),
            answers: socks_answers(),
        }),
        Err(e) => Parsed::Rejected {
            why: e.to_string(),
            answer: vec![5, 7, 0, 1, 0, 0, 0, 0, 0, 0],
        },
    })
}

/// Longer than any request head a browser sends; a client past it is not
/// sending one.
const MAX_HEAD: usize = 64 * 1024;

/// Where a request head ends: after the first empty line. A bare LF is
/// accepted as a line end, as RFC 9112 allows, so that a head typed into nc
/// works too.
fn head_end(b: &[u8]) -> Option<usize> {
    let crlf = b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let lf = b.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The lines of a head, line ends removed, without the blank ones around it.
fn head_lines(head: &[u8]) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = head
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    while v.last().is_some_and(|l| l.is_empty()) {
        v.pop();
    }
    // A client may send an empty line before the request line.
    let leading = v.iter().take_while(|l| l.is_empty()).count();
    v.drain(..leading);
    v
}

fn http_request(c: &mut TcpStream) -> std::io::Result<Parsed> {
    let reject = |why: String| {
        let answer = http_answer("400 Bad Request", &format!("fake-transport: {why}.\n"));
        Ok(Parsed::Rejected { why, answer })
    };

    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(end) = head_end(&buf) {
            break end;
        }
        if buf.len() > MAX_HEAD {
            return reject(format!("request head longer than {MAX_HEAD} bytes"));
        }
        let n = c.read(&mut chunk)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(Parsed::Gone);
            }
            return reject("connection closed inside the request head".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let rest = buf.split_off(end);
    let lines = head_lines(&buf);
    let Some(first) = lines.first() else {
        return reject("empty request".into());
    };
    let first = String::from_utf8_lossy(first);
    let parts: Vec<&str> = first.split(' ').collect();
    let [method, target, version] = parts[..] else {
        return reject(format!("malformed request line: {first}"));
    };
    if !version.starts_with("HTTP/1.") {
        return reject(format!("not HTTP/1.x: {version}"));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_host_port(target, None) else {
            return reject(format!("CONNECT needs host:port, not {target}"));
        };
        return Ok(Parsed::Asked(Request {
            target: host_port(&host, port),
            addrtype: kind_of(&host),
            host,
            port,
            iso: None,
            head: None,
            rest,
            answers: http_answers(true),
        }));
    }

    // Anything else is forwarded, and only an absolute http:// URI says where
    // to. https:// is not forwarded: a client reaches it through CONNECT.
    let Some(after) = target
        .get(..7)
        .filter(|s| s.eq_ignore_ascii_case("http://"))
        .map(|_| &target[7..])
    else {
        return reject(format!("not a proxy request: {target} is not CONNECT host:port or an absolute http:// URI"));
    };
    let cut = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, path) = after.split_at(cut);
    // Credentials in a URI are never passed on.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let Some((host, port)) = split_host_port(authority, Some(80)) else {
        return reject(format!("no usable host:port in {target}"));
    };
    let path = path.split('#').next().unwrap_or("");
    let origin = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };

    // The request line in origin form, as the origin server expects it. The
    // headers go as they came, except the ones about the connection to the
    // proxy: that connection ends after one request. Browsers pool plain-HTTP
    // connections to a proxy by the proxy, not by the site, so one connection
    // can carry requests for several sites — and bytes pumped blindly after
    // the first request carried the second site's request to the first site's
    // server, unlogged (measured with curl, which pools the same way).
    // `Connection: close` makes each request arrive on a connection, and in a
    // log line, of its own.
    let mut head = format!("{method} {origin} {version}\r\n").into_bytes();
    let (mut has_host, mut dropping) = (false, false);
    for l in &lines[1..] {
        // A folded continuation belongs to the header above it.
        let folded = l.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if !folded {
            let name = l.split(|b| *b == b':').next().unwrap_or(&[]);
            let name = String::from_utf8_lossy(name).trim().to_ascii_lowercase();
            dropping = matches!(
                name.as_str(),
                "connection" | "proxy-connection" | "keep-alive" | "proxy-authorization"
            );
            has_host |= name == "host";
        }
        if !dropping {
            head.extend_from_slice(l);
            head.extend_from_slice(b"\r\n");
        }
    }
    if !has_host {
        head.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");

    Ok(Parsed::Asked(Request {
        target: host_port(&host, port),
        addrtype: kind_of(&host),
        host,
        port,
        iso: None,
        head: Some(head),
        rest,
        answers: http_answers(false),
    }))
}

fn pump(mut a: TcpStream, mut b: TcpStream) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match a.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if b.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = a.shutdown(Shutdown::Read);
    let _ = b.shutdown(Shutdown::Write);
}

fn handle(mut c: TcpStream, cfg: Arc<Cfg>, j: Arc<Journal>) -> std::io::Result<()> {
    let peer = c.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let proto = cfg.proto.name();

    let parsed = match cfg.proto {
        Proto::Socks5 => socks_request(&mut c)?,
        Proto::Http => http_request(&mut c)?,
    };
    let req = match parsed {
        Parsed::Asked(r) => r,
        Parsed::Gone => return Ok(()),
        Parsed::Rejected { why, answer } => {
            j.write(&[
                ("ev", "reject".into()),
                ("why", why.into()),
                ("peer", peer.into()),
                ("transport", cfg.label.clone().into()),
                ("proto", proto.into()),
            ]);
            let _ = c.write_all(&answer);
            return Ok(());
        }
    };

    let base: Vec<(&str, V)> = vec![
        ("peer", peer.clone().into()),
        ("target", req.target.clone().into()),
        ("addrtype", req.addrtype.into()),
        ("iso", req.iso.clone().into()),
        ("transport", cfg.label.clone().into()),
        ("proto", proto.into()),
    ];

    if cfg.mode == Mode::Deny {
        let mut f = vec![("ev", V::from("deny"))];
        f.extend(base.clone());
        j.write(&f);
        c.write_all(&req.answers.refused)?; // refused
        return Ok(());
    }

    if cfg.mode == Mode::Sink {
        let mut f = vec![("ev", V::from("sink"))];
        f.extend(base.clone());
        j.write(&f);
        c.write_all(&req.answers.sunk)?;
        let mut buf = [0u8; 8192];
        let mut total = req.rest.len();
        while let Ok(n) = c.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n;
        }
        j.write(&[
            ("ev", "sink_end".into()),
            ("target", req.target.into()),
            ("bytes_in", total.to_string().into()),
            ("proto", proto.into()),
        ]);
        return Ok(());
    }

    // Mode::Connect — resolution happens here, which means the client handed
    // over a name and this process resolved it on its behalf. Whether the
    // browser passes a name or an address is recorded verbatim in addrtype.
    let t0 = now_ms();
    // Every address a name resolves to is tried in turn, the way tor and I2P
    // routers do. Trying only the first made `localhost` fail wherever it
    // resolves to ::1 first and IPv6 is off, and that failure looked like the
    // route's.
    let up = match (req.host.as_str(), req.port).to_socket_addrs() {
        Ok(it) => {
            let addrs: Vec<_> = it.collect();
            if addrs.is_empty() {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "resolved to nothing"))
            } else {
                TcpStream::connect(&addrs[..]).map(|s| {
                    let a = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                    (s, a)
                })
            }
        }
        Err(e) => Err(e),
    };
    match up {
        Ok((mut upstream, addr)) => {
            let mut f = vec![
                ("ev", V::from("open")),
                ("resolved", addr.into()),
                ("ms", (now_ms() - t0).to_string().into()),
            ];
            f.extend(base.clone());
            j.write(&f);
            if let Some(g) = &req.answers.granted {
                c.write_all(g)?;
            }
            // A forwarded request goes first, then whatever followed it.
            if let Some(h) = &req.head {
                upstream.write_all(h)?;
            }
            upstream.write_all(&req.rest)?;
            let (c2, u2) = (c.try_clone()?, upstream.try_clone()?);
            let h = thread::spawn(move || pump(c2, u2));
            pump(upstream, c);
            let _ = h.join();
        }
        Err(e) => {
            let mut f = vec![("ev", V::from("fail")), ("why", e.to_string().into())];
            f.extend(base.clone());
            j.write(&f);
            let _ = c.write_all(&req.answers.failed);
        }
    }
    Ok(())
}

fn main() {
    let mut args: HashMap<String, String> = HashMap::new();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        if let Some(k) = raw[i].strip_prefix("--") {
            let v = raw.get(i + 1).cloned().unwrap_or_default();
            args.insert(k.to_string(), v);
            i += 2;
        } else {
            i += 1;
        }
    }
    // Refused rather than defaulted: a misspelt protocol would otherwise run
    // SOCKS5 and make every HTTP client's failure look like the proxy's.
    let proto = match args.get("proto").map(|s| s.as_str()) {
        None | Some("socks5") => Proto::Socks5,
        Some("http") => Proto::Http,
        Some(other) => {
            eprintln!("unknown --proto {}: use socks5 or http", other);
            std::process::exit(2);
        }
    };
    let cfg = Arc::new(Cfg {
        listen: args.get("listen").cloned().unwrap_or_else(|| "127.0.0.1:19999".into()),
        mode: match args.get("mode").map(|s| s.as_str()) {
            Some("sink") => Mode::Sink,
            Some("deny") => Mode::Deny,
            _ => Mode::Connect,
        },
        proto,
        log: args.get("log").cloned(),
        label: args.get("label").cloned().unwrap_or_else(|| "fake".into()),
    });

    let file = cfg.log.as_ref().and_then(|p| {
        std::fs::OpenOptions::new().create(true).append(true).open(p).ok()
    });
    let journal = Arc::new(Journal { sink: Mutex::new(file), seq: AtomicU64::new(0) });

    let l = match TcpListener::bind(&cfg.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not listen on {}: {}", cfg.listen, e);
            std::process::exit(1);
        }
    };
    journal.write(&[
        ("ev", "start".into()),
        ("listen", cfg.listen.clone().into()),
        ("mode", match cfg.mode {
            Mode::Connect => "connect".into(),
            Mode::Sink => "sink".into(),
            Mode::Deny => "deny".into(),
        }),
        ("transport", cfg.label.clone().into()),
        ("proto", cfg.proto.name().into()),
    ]);
    eprintln!("fake-transport listening on {} ({})", cfg.listen, cfg.proto.name());

    for s in l.incoming() {
        match s {
            Ok(s) => {
                let (c, j) = (cfg.clone(), journal.clone());
                thread::spawn(move || {
                    let _ = handle(s, c, j);
                });
            }
            Err(e) => eprintln!("accept failed: {}", e),
        }
    }
}
