//! 프로필 정의.
//!
//! ⭐**여기가 경로 의존성이 모이는 유일한 곳이다**(오너 2026-08-22: "모든 코드에서
//! 경로 의존성을 최소화한다"). Tor 를 C tor 에서 Arti 로 갈아타거나 Session Router
//! 를 붙일 때 고치는 곳은 이 표 하나여야 하고, 나머지 코드는 `Transport` 만 본다.

/// 브라우저가 바깥으로 나가는 방법.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// 직접 나간다. 프록시 없음.
    Direct,
    /// SOCKS5 프록시. (호스트 포트)
    Socks5(u16),
    /// HTTP 프록시. (호스트 포트)
    Http(u16),
}

/// 지문 방어 등급. 오너 결정(2026-08-22): **다섯 프로필이 지문을 하나로 통일한다.**
/// 데일리와 하드닝의 차이는 「엄격함」이지 지문 정체성이 아니다. (실측 13)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Strictness {
    /// 로그인·기록이 남는다. 레터박싱은 켜져 있지만 경고 후 끌 수 있다.
    /// 지문은 다른 넷과 **똑같다** — 실측 13에서 이 완화들의 지문 차이가 0이었다.
    Daily,
    /// 나갈 때 전부 지운다. 레터박싱 강제.
    Hardened,
}

pub struct Profile {
    pub name: &'static str,
    pub label: &'static str,
    /// 화면에 띄우는 글리프. 창이 겹쳐 있을 때 1px 만 보고도 알아야 한다.
    pub glyph: &'static str,
    pub transport: Transport,
    pub strictness: Strictness,
    /// 이 경로에서만 뜻이 있는 최상위 도메인. 없으면 일반 웹.
    pub suffix: Option<&'static str>,
    /// 아직 만들지 않은 경로인가. v1 순서는 네이티브 → Tor → I2P → Session.
    pub ready: bool,
}

pub const PROFILES: &[Profile] = &[
    Profile {
        name: "daily",
        label: "일상",
        glyph: "●",
        transport: Transport::Direct,
        strictness: Strictness::Daily,
        suffix: None,
        ready: true,
    },
    Profile {
        name: "hardened",
        label: "강화",
        glyph: "○",
        transport: Transport::Direct,
        strictness: Strictness::Hardened,
        suffix: None,
        ready: true,
    },
    Profile {
        name: "tor",
        label: "Tor",
        glyph: "◎",
        // v1 은 C tor 다(오너 결정). Arti 로 갈아타도 이 한 줄만 바뀐다.
        transport: Transport::Socks5(9150),
        strictness: Strictness::Hardened,
        suffix: Some(".onion"),
        ready: false,
    },
    Profile {
        name: "i2p",
        label: "I2P",
        glyph: "◆",
        // 4447 이 아니라 4444 다. 4447 은 SOCKS 이고 I2P 프로젝트는 HTTP 를 권한다.
        transport: Transport::Http(4444),
        strictness: Strictness::Hardened,
        suffix: Some(".i2p"),
        ready: false,
    },
    Profile {
        name: "session",
        label: "Session",
        glyph: "⬡",
        // 아직 자리만 잡아 둔다. 상류에 SOCKS 가 없어서 PR #51 이 병합되면
        // 그 위에 얇은 SOCKS 껍데기를 얹는 것이 계획이다.
        transport: Transport::Socks5(1080),
        strictness: Strictness::Hardened,
        suffix: Some(".sesh"),
        ready: false,
    },
];

pub fn find(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

impl Profile {
    /// 격리망 안에서 **바깥으로 나갈 수 있는 유일한 포트**.
    /// `None` 이면 직접 연결이므로 일반 웹 포트를 연다.
    pub fn relay_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Direct => None,
            Transport::Socks5(p) | Transport::Http(p) => Some(p),
        }
    }
}

/// 한글·한자는 터미널에서 두 칸을 차지한다. `{:<20}` 은 글자 수만 세므로
/// 그대로 쓰면 표가 어긋난다. 실제 표시 폭으로 채운다.
pub fn pad(s: &str, width: usize) -> String {
    let w: usize = s.chars().map(char_width).sum();
    let mut out = s.to_string();
    for _ in w..width {
        out.push(' ');
    }
    out
}

fn char_width(c: char) -> usize {
    match c as u32 {
        // 한글 · CJK · 전각 기호
        0x1100..=0x115F
        | 0x2E80..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE6F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

pub fn list() -> Result<(), String> {
    println!("  {} {} {} {}  {}", pad("프로필", 20), pad("경로", 17), pad("전용주소", 9), pad("상태", 13), "표시");
    println!("  ──────────────────────────────────────────────────────────────────");
    for p in PROFILES {
        let route = match p.transport {
            Transport::Direct => "직접 연결".to_string(),
            Transport::Socks5(port) => format!("SOCKS5 {port}"),
            Transport::Http(port) => format!("HTTP 프록시 {port}"),
        };
        println!(
            "  {} {} {} {}  {}",
            pad(&format!("{} ({})", p.name, p.label), 20),
            pad(&route, 17),
            pad(p.suffix.unwrap_or("—"), 9),
            pad(if p.ready { "준비됨" } else { "아직 안 만듦" }, 13),
            p.glyph
        );
    }
    println!();
    println!("다섯 프로필은 지문을 하나로 통일합니다. 차이는 엄격함이지 정체성이 아닙니다.");
    Ok(())
}
