//! 실제로 띄우는 부분.
//!
//! 두 단계로 나뉜다. `run` 은 바깥에서, `inner` 는 격리망 안에서 돈다.
//! 사이를 잇는 것은 `pasta` 이고, 우리는 우리 자신을 `__inner` 로 다시 부른다.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::nft;
use crate::profile::{self, Profile, Strictness};

/// 프로필이 사는 곳.
fn home() -> PathBuf {
    if let Ok(p) = std::env::var("BBIWY_HOME") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())).join(".local/share")
        });
    base.join("bbiwy")
}

/// 브라우저 실행파일. 아직 우리 빌드가 없으므로 당분간 환경변수로 받는다.
fn browser() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BBIWY_BROWSER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!("BBIWY_BROWSER 가 가리키는 파일이 없습니다: {}", p.display()));
    }
    for cand in ["/opt/bbiwy/browser/bbiwy", "/usr/lib/bbiwy/bbiwy"] {
        if Path::new(cand).is_file() {
            return Ok(PathBuf::from(cand));
        }
    }
    Err("브라우저를 찾지 못했습니다. BBIWY_BROWSER 로 경로를 알려 주십시오.".into())
}

/// 바깥. 격리망을 만들고 그 안에서 우리 자신을 다시 부른다.
pub fn run(name: &str) -> Result<(), String> {
    let p = profile::find(name)
        .ok_or_else(|| format!("모르는 프로필입니다: {name}. `bbiwy list` 를 보십시오."))?;
    if !p.ready {
        return Err(format!(
            "{} 경로는 아직 만들지 않았습니다. 지금 쓸 수 있는 것은 daily 와 hardened 입니다.",
            p.label
        ));
    }
    browser()?; // 격리망을 만들기 전에 먼저 확인한다. 만들고 나서 실패하면 정리가 지저분해진다.

    let me = std::env::current_exe().map_err(|e| format!("자기 경로를 못 찾습니다: {e}"))?;

    // ⛔ 여기가 설계에서 가장 조심할 자리다.
    // pasta 의 --tcp-ports/--udp-ports 기본값은 `auto` 이고 그것은 **fail-open** 이다.
    // 명시하지 않으면 열려는 적 없는 포트가 열린다.
    let forward = match p.relay_port() {
        Some(port) => port.to_string(),
        None => "none".to_string(),
    };

    let mut cmd = Command::new("pasta");
    cmd.arg("--config-net")
        .args(["--tcp-ports", &forward])
        .args(["--udp-ports", "none"])
        .arg("--")
        .arg(&me)
        .arg("__inner")
        .arg(p.name);

    let status = cmd
        .status()
        .map_err(|e| format!("pasta 를 실행하지 못했습니다: {e}. `bbiwy doctor` 를 돌려 보십시오."))?;
    if !status.success() {
        return Err("격리망 안에서 브라우저가 정상 종료하지 않았습니다.".into());
    }
    Ok(())
}

/// 안쪽. 여기서부터 바깥 네트워크가 안 보인다.
pub fn inner(name: &str) -> Result<(), String> {
    let p = profile::find(name).ok_or_else(|| format!("모르는 프로필입니다: {name}"))?;

    load_ruleset(p)?;

    let dir = home().join(p.name);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("프로필 폴더를 만들지 못했습니다 {}: {e}", dir.display()))?;

    let browser = browser()?;

    // 권한을 전부 떨구고 브라우저를 띄운다.
    // 이 뒤로는 화이트리스트를 지울 수도, 인터페이스를 만들 수도, root 를 매핑한
    // 격리망으로 빠져나갈 수도 없다. 그런데 파이어폭스 자체 샌드박스는 살아남는다
    // — 그건 자기 uid 만 매핑하므로 권한이 필요 없기 때문이다. (실측 15)
    let mut cmd = Command::new("setpriv");
    cmd.args(["--bounding-set=-all", "--inh-caps=-all", "--no-new-privs", "--"])
        .arg(&browser)
        .args(["--profile", &dir.to_string_lossy()])
        .arg("--no-remote")
        // autoconfig 가 프로필 경로로 부류를 가른다. 환경변수는 사용자가 위조할 수
        // 있어서 잠금의 뜻이 사라지므로 참고용으로만 넣는다. (실측 11)
        .env("BBIWY_PROFILE", p.name)
        .env("BBIWY_STRICTNESS", match p.strictness {
            Strictness::Daily => "daily",
            Strictness::Hardened => "hardened",
        });

    // exec 로 갈아탄다. 우리가 중간에 남아 있을 이유가 없다.
    use std::os::unix::process::CommandExt;
    let e = cmd.exec();
    Err(format!("브라우저를 띄우지 못했습니다: {e}"))
}

fn load_ruleset(p: &Profile) -> Result<(), String> {
    let rules = nft::ruleset(p);
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft 를 실행하지 못했습니다: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("nft 에 입력을 넘기지 못했습니다")?
        .write_all(rules.as_bytes())
        .map_err(|e| format!("규칙을 넘기지 못했습니다: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft 를 기다리지 못했습니다: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "화이트리스트를 걸지 못했습니다. 격리가 성립하지 않으므로 띄우지 않습니다.\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
