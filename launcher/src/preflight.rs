//! `bbiwy doctor` — 이 기계에서 격리가 실제로 성립하는지 검사한다.
//!
//! 왜 필요한가: 격리가 안 되는 기계에서 조용히 그냥 뜨면, 사용자는 보호받는다고
//! 믿으면서 보호받지 못한다. 그게 이 제품이 절대 하면 안 되는 일이다.

use crate::profile::pad;
use std::path::Path;
use std::process::Command;

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// 이게 실패하면 격리가 아예 성립하지 않는가.
    pub fatal: bool,
}

fn which(bin: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    path.split(':')
        .map(|d| Path::new(d).join(bin))
        .find(|p| p.is_file())
        .map(|p| p.display().to_string())
}

fn sysctl(key: &str) -> Option<String> {
    let p = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

pub fn checks() -> Vec<Check> {
    let mut out = Vec::new();

    for (bin, why) in [
        ("pasta", "격리망을 바깥에 붙인다"),
        ("nft", "화이트리스트를 건다"),
        ("setpriv", "브라우저를 띄우기 전에 권한을 떨군다"),
    ] {
        let found = which(bin);
        out.push(Check {
            name: match bin {
                "pasta" => "pasta (passt)",
                "nft" => "nftables",
                _ => "setpriv (util-linux)",
            },
            ok: found.is_some(),
            detail: match &found {
                Some(p) => format!("{p} — {why}"),
                None => format!("없음. {why} 데 필요합니다"),
            },
            fatal: true,
        });
    }

    // 비특권 사용자 네임스페이스. Ubuntu 24.04+ 는 기본으로 막혀 있고,
    // 설치 때 까는 AppArmor 프로필이 그것을 푼다. (실측 10)
    let apparmor = sysctl("kernel.apparmor_restrict_unprivileged_userns");
    let restricted = apparmor.as_deref() == Some("1");
    let profile_installed = Path::new("/etc/apparmor.d/bbiwy").exists();
    out.push(Check {
        name: "비특권 격리망",
        ok: !restricted || profile_installed,
        detail: if !restricted {
            "제한 없음".into()
        } else if profile_installed {
            "AppArmor 제한이 켜져 있지만 BBIWY 프로필이 설치돼 있습니다".into()
        } else {
            "AppArmor 가 막고 있고 BBIWY 프로필이 없습니다. \
             설치 프로그램을 다시 돌리십시오 (/etc/apparmor.d/bbiwy)"
                .into()
        },
        fatal: true,
    });

    // 표시서버. 격리망은 X11 층을 못 막는다 — 프로필끼리 서로 볼 수 있다.
    let (grade, detail) = display_grade();
    out.push(Check {
        name: "프로필 간 격리",
        ok: grade != Grade::None,
        detail,
        fatal: false,
    });

    out
}

#[derive(PartialEq, Eq)]
pub enum Grade {
    /// 컴포지터가 클라이언트끼리 막아 준다.
    Full,
    /// 막긴 하는데 구멍이 있다 (KDE 는 차단 목록이 여섯 개뿐이다).
    Partial,
    /// 못 막는다. X11 이거나, security-context 를 구현하지 않은 컴포지터.
    None,
}

fn display_grade() -> (Grade, String) {
    let wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let d = desktop.to_ascii_lowercase();

    if !wayland {
        return (
            Grade::None,
            "X11 — 프로필끼리 서로의 키 입력과 화면을 볼 수 있습니다. \
             네트워크 격리는 그대로 작동합니다"
                .into(),
        );
    }
    // GNOME 은 wp_security_context_manager_v1 을 아직 구현하지 않는다.
    if d.contains("gnome") {
        (
            Grade::None,
            "Wayland(GNOME) — GNOME 은 클라이언트 간 격리 규약을 아직 구현하지 \
             않습니다. 프로필끼리 서로 볼 수 있습니다"
                .into(),
        )
    } else if d.contains("kde") || d.contains("plasma") {
        (
            Grade::Partial,
            "Wayland(KDE) — 대부분 막히지만 클립보드는 공유됩니다".into(),
        )
    } else {
        (
            Grade::Full,
            format!("Wayland({}) — 프로필끼리 서로 보지 못합니다", if desktop.is_empty() { "wlroots 계열" } else { &desktop }),
        )
    }
}

pub fn doctor() -> Result<(), String> {
    println!("BBIWY 검사\n");
    let cs = checks();
    let mut fatal_failed = false;
    for c in &cs {
        let mark = if c.ok { "✓" } else if c.fatal { "✗" } else { "!" };
        println!("  {mark} {} {}", pad(c.name, 20), c.detail);
        if !c.ok && c.fatal {
            fatal_failed = true;
        }
    }
    println!();
    if fatal_failed {
        println!("격리가 성립하지 않습니다. 위의 ✗ 를 먼저 해결해야 합니다.");
        return Err("검사 실패".into());
    }
    println!("네트워크 격리가 성립합니다.");
    // 시험용 pasta 실행으로 실제 동작까지 확인한다. 있다고 되는 것이 아니다.
    match Command::new("pasta")
        .args(["--config-net", "--tcp-ports", "none", "--udp-ports", "none", "--", "/bin/true"])
        .output()
    {
        Ok(o) if o.status.success() => println!("실제로 격리망을 만들어 보았고 성공했습니다."),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let line = err.lines().find(|l| !l.contains("IPv6")).unwrap_or("").trim();
            println!("⚠ 격리망을 실제로 만들지 못했습니다: {line}");
            return Err("격리망 생성 실패".into());
        }
        Err(e) => return Err(format!("pasta 를 실행하지 못했습니다: {e}")),
    }
    Ok(())
}
