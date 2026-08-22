#![forbid(unsafe_code)]
//! nmp-fake-transport — 설계 문서 §4가 말하는 `fake` 경로.
//!
//! 요청을 전부 기록하는 SOCKS5 프록시다. Arti를 붙이기 전에 격리·fail-closed·
//! 누수 시험을 먼저 끝내려고 만든다. "격리 구조를 세운다"와 "Arti를 붙인다"는
//! 서로 다른 어려움이고, 섞으면 무엇이 잘못됐는지 판정할 수 없다.
//!
//! 부수적으로 이 기록이 §9의 "이 요청이 어느 경로로 나갔는가" 화면의 자료원이다.
//!
//! 모드:
//!   --mode connect  실제로 연결한다 (평범한 프록시)
//!   --mode sink     받아만 두고 버린다 (연결은 성공, 자료는 안 나감)
//!   --mode deny     전부 거절한다 (fail-closed 시험)
//!
//! 표준 라이브러리만 쓴다. 의존성이 없어야 실험대가 흔들리지 않는다.

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

/// SOCKS5 주소부를 읽어 (표시용 문자열, 해석 대상) 으로 돌려준다.
/// 도메인은 여기서 해석하지 않는다 — 해석 자체가 어디서 일어나는지가 시험 대상이다.
fn read_target(s: &mut TcpStream) -> std::io::Result<(String, String, u16, &'static str)> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "socks 버전"));
    }
    let cmd = head[1];
    if cmd != 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "CONNECT 외 미지원"));
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
                format!("주소형식 {}", other),
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

    // 인사. 아이디/비번 인증도 받아준다 — Arti의 스트림 격리가 이 자리를 쓰므로,
    // 나중에 무엇이 어떤 격리 딱지를 달고 오는지 여기서 그대로 보인다.
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
        c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])?; // 연결 거절
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

    // Mode::Connect — 도메인 해석이 여기서 일어난다. 즉 클라이언트는 이름을
    // 넘겼을 뿐이고, 이 프로세스가 대신 푼다. socks_remote_dns가 참일 때
    // 브라우저가 이름을 넘기는지 주소를 넘기는지가 addrtype에 그대로 남는다.
    let t0 = now_ms();
    let resolved = (host.as_str(), port).to_socket_addrs();
    let up = match resolved {
        Ok(mut it) => match it.next() {
            Some(a) => TcpStream::connect(a).map(|s| (s, a.to_string())),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "해석 결과 없음")),
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
            eprintln!("듣기 실패 {}: {}", cfg.listen, e);
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
    eprintln!("nmp-fake-transport 듣는 중: {}", cfg.listen);

    for s in l.incoming() {
        match s {
            Ok(s) => {
                let (c, j) = (cfg.clone(), journal.clone());
                thread::spawn(move || {
                    let _ = handle(s, c, j);
                });
            }
            Err(e) => eprintln!("수락 실패: {}", e),
        }
    }
}
