//! BBIWY 런처.
//!
//! 하는 일은 하나다. **프로필마다 격리망을 만들고, 그 경로만 남기고 전부 막고,
//! 권한을 전부 떨군 뒤 브라우저를 띄운다.**
//!
//! 설계에서 중요한 것 두 가지.
//!
//! 1. **실행에 권한을 하나도 쓰지 않는다.** setuid 도우미도, 파일 capability 도,
//!    polkit 도, systemd 서비스도 없다. 이 계열 도구가 가장 자주 뚫린 지점을
//!    아예 만들지 않는다. (실측 10)
//! 2. **직접 시스템콜을 부르지 않는다.** `pasta`·`nft`·`setpriv` 는 이미 있고 이미
//!    감사받은 도구다. 그것을 정해진 순서로 부르기만 하므로 이 프로그램에는
//!    `unsafe` 가 한 줄도 없고, 무엇을 하는지가 명령 한 줄씩으로 다 드러난다.
//!
//! 흐름:
//!
//! ```text
//!   bbiwy run tor
//!     └ pasta --config-net --tcp-ports <허용포트> --udp-ports none
//!         └ bbiwy __inner <설정>          ← 격리망 안. 여기부터 바깥이 안 보인다
//!             ├ nft -f -                  ← 화이트리스트 적재 (계수기 포함)
//!             └ setpriv --bounding-set=-all --inh-caps=-all --no-new-privs
//!                 └ 브라우저 --profile <경로>
//!```
#![forbid(unsafe_code)]

mod exec;
mod nft;
mod preflight;
mod profile;

use std::process::ExitCode;

const USAGE: &str = "\
BBIWY — 경로마다 격리된 브라우저

사용법:
  bbiwy doctor              이 기계에서 격리가 성립하는지 검사한다
  bbiwy list                프로필 목록을 보여 준다
  bbiwy run <프로필>        프로필을 격리망 안에서 띄운다

프로필: daily · hardened · tor · i2p · session

환경변수:
  BBIWY_BROWSER   브라우저 실행파일 경로 (기본: 설치 경로에서 찾는다)
  BBIWY_HOME      프로필을 두는 곳 (기본: ~/.local/share/bbiwy)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    let r = match cmd {
        "doctor" => preflight::doctor(),
        "list" => profile::list(),
        "run" => match args.get(2) {
            Some(name) => exec::run(name),
            None => Err("프로필 이름이 필요합니다. `bbiwy list` 로 목록을 보십시오.".into()),
        },
        // 격리망 안에서 우리 자신이 다시 불리는 자리. 사용자가 직접 부를 일은 없다.
        "__inner" => match args.get(2) {
            Some(name) => exec::inner(name),
            None => Err("__inner 에 프로필 이름이 없습니다".into()),
        },
        "-h" | "--help" | "help" | "" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => Err(format!("모르는 명령입니다: {other}\n\n{USAGE}")),
    };

    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("오류: {e}");
            ExitCode::FAILURE
        }
    }
}
