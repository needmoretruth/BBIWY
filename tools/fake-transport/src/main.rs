#![forbid(unsafe_code)]
//! fake-transport — a stand-in route, used before a real one exists.
//!
//! A SOCKS5 proxy that logs every request. It exists so that isolation,
//! fail-closed behaviour and leak testing can be finished before a real
//! transport is wired in. "Build the isolation" and "integrate a transport"
//! are different problems; combined, neither failure can be diagnosed.
//!
//! Its log is also the data source for showing which route a request took.
//!
//! Modes:
//!   --mode connect  actually connect (an ordinary proxy)
//!   --mode sink     accept and discard (connection succeeds, nothing leaves)
//!   --mode deny     refuse everything (fail-closed testing)
//!
//! Standard library only. A test rig with no dependencies has nothing that can
//! shift underneath it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
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

struct Cfg {
    listen: String,
    mode: Mode,
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

struct Journal {
    sink: Mutex<Option<std::fs::File>>,
    seq: AtomicU64,
}

impl Journal {
    fn write(&self, fields: &[(&str, String)]) {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut line = format!("{{\"seq\":{},\"t\":{}", n, now_ms());
        for (k, v) in fields {
            line.push_str(&format!(",\"{}\":\"{}\"", k, jesc(v)));
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
            let parts: Vec<String> = b.chunks(2).map(|c| format!("{:02x}{:02x}", c[0], c[1])).collect();
            (parts.join(":"), "ipv6")
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
    Ok((format!("{}:{}", host, port), host, port, kind))
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

    let (target, host, port, kind) = match read_target(&mut c) {
        Ok(t) => t,
        Err(e) => {
            j.write(&[
                ("ev", "reject".into()),
                ("why", e.to_string()),
                ("peer", peer),
                ("transport", cfg.label.clone()),
            ]);
            let _ = c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Ok(());
        }
    };

    let base = vec![
        ("peer", peer.clone()),
        ("target", target.clone()),
        ("addrtype", kind.to_string()),
        ("iso", auth_user.clone()),
        ("transport", cfg.label.clone()),
    ];

    if cfg.mode == Mode::Deny {
        let mut f = vec![("ev", "deny".to_string())];
        f.extend(base.clone());
        j.write(&f);
        c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])?; // refused
        return Ok(());
    }

    if cfg.mode == Mode::Sink {
        let mut f = vec![("ev", "sink".to_string())];
        f.extend(base.clone());
        j.write(&f);
        c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
        let mut buf = [0u8; 8192];
        let mut total = 0usize;
        while let Ok(n) = c.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n;
        }
        j.write(&[
            ("ev", "sink_end".into()),
            ("target", target),
            ("bytes_in", total.to_string()),
        ]);
        return Ok(());
    }

    // Mode::Connect — resolution happens here, which means the client handed
    // over a name and this process resolved it on its behalf. Whether the
    // browser passes a name or an address is recorded verbatim in addrtype.
    let t0 = now_ms();
    let resolved = (host.as_str(), port).to_socket_addrs();
    let up = match resolved {
        Ok(mut it) => match it.next() {
            Some(a) => TcpStream::connect(a).map(|s| (s, a.to_string())),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "resolved to nothing")),
        },
        Err(e) => Err(e),
    };
    match up {
        Ok((upstream, addr)) => {
            let mut f = vec![("ev", "open".to_string()), ("resolved", addr), ("ms", (now_ms() - t0).to_string())];
            f.extend(base.clone());
            j.write(&f);
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
            let (c2, u2) = (c.try_clone()?, upstream.try_clone()?);
            let h = thread::spawn(move || pump(c2, u2));
            pump(upstream, c);
            let _ = h.join();
        }
        Err(e) => {
            let mut f = vec![("ev", "fail".to_string()), ("why", e.to_string())];
            f.extend(base.clone());
            j.write(&f);
            let _ = c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
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
    let cfg = Arc::new(Cfg {
        listen: args.get("listen").cloned().unwrap_or_else(|| "127.0.0.1:19999".into()),
        mode: match args.get("mode").map(|s| s.as_str()) {
            Some("sink") => Mode::Sink,
            Some("deny") => Mode::Deny,
            _ => Mode::Connect,
        },
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
        ("listen", cfg.listen.clone()),
        ("mode", match cfg.mode {
            Mode::Connect => "connect".into(),
            Mode::Sink => "sink".into(),
            Mode::Deny => "deny".into(),
        }),
        ("transport", cfg.label.clone()),
    ]);
    eprintln!("fake-transport listening on {}", cfg.listen);

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
