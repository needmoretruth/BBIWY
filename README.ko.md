# BBIWY

**Big Brother Is Watching You** — 네트워크 경로마다 프로필을 따로 두는 프라이버시 브라우저.

> **상태: 알파 (0.1.0-alpha.1).** `daily`·`hardened`·`tor`·`i2p` 는 설치하고 쓸 수 있습니다.
> `session` 은 위쪽에 SOCKS 리스너가 생기기를 기다립니다. 리눅스 x86_64 전용.
> 무엇을 어디서 확인했는지는 [측정 결과](docs/MEASUREMENTS.md)를 보십시오.

---

## 무엇인가

브라우저 하나에 바깥으로 나가는 길이 여럿입니다 — 직접·Tor·I2P·Session.
그리고 **각 길이 물리적으로 분리된 프로필에 잠겨 있어서** 상태도 트래픽도 섞이지 않습니다.

| 프로필 | 경로 | 성격 |
|---|---|---|
| `daily` | 직접 연결 | 로그인이 남고, 사이트가 안 깨집니다 |
| `hardened` | 직접 연결 | 아무것도 남지 않습니다 |
| `tor` | SOCKS5 → 로컬 tor | `.onion` |
| `i2p` | HTTP 프록시 → 로컬 I2P 라우터 | `.i2p` |
| `session` | Session Router | `.sesh` 내부 서비스 전용 |

**다섯 프로필은 지문을 하나로 통일합니다.** `daily`와 `hardened`의 차이는 **엄격함**이지
정체성이 아닙니다 — 로그인이 남는가, 얼마나 깨지는 것을 견디는가의 차이입니다.

실제로 재 보니 **로그인·기록·자동완성을 전부 켜도 지문 차이가 0**이었습니다.
그러니 익명 집합을 쪼갤 이유가 없습니다.

## 격리가 어떻게 작동하는가

두 층이고, 두 번째 층은 첫 번째 층을 믿지 않습니다.

**브라우저 층** — 브라우저 옆에 까는 잠금 파일 하나(`bbiwy.cfg`)가 **프로필 디렉터리
이름**으로 프로필마다 잠금을 고릅니다. 환경변수로는 절대 고르지 않습니다. 프록시·원격
이름해석·주소로 붙는 DNS-over-HTTPS·HTTP/3 끔·미리 연결 끔. 잠금이 다 들어가지 않은 창은
빨간 **UNLOCKED** 로 표시되고, 어떤 경로도 주장하지 않습니다.

**운영체제 층** — 프로필마다 리눅스 네트워크 네임스페이스를 따로 만들고 nftables 허용 목록을
겁니다. **그 프로필이 써야 할 포트 하나만** 닿습니다. 나머지는 전부 떨어뜨리고 **셉니다.**
경로 데몬이 죽어도 조용히 일반 인터넷으로 새지 않습니다 — 아예 아무 데도 못 갑니다.

런처는 **실행할 때 권한을 하나도 쓰지 않습니다.** setuid 도우미도, 파일 capability도,
polkit도, 시스템 서비스도 없습니다. 이미 검증된 도구 셋(`pasta`·`nft`·`setpriv`)을 정해진
순서로 부르고, 브라우저를 띄우기 직전에 허용 목록을 되돌릴 수 있는 권한 둘을 떨구고, 정말 떨어졌는지 확인합니다.

그 뒤로 브라우저는 허용 목록을 지울 수도, 인터페이스를 만들 수도, root를 매핑한
네임스페이스로 빠져나갈 수도 없습니다. **그런데 파이어폭스 자체 콘텐츠 샌드박스는
그대로 살아 있습니다.**

root는 **설치할 때 딱 한 번** 필요합니다 — AppArmor 프로필을 놓기 위해서입니다.
우분투에서 파이어폭스·크롬·브레이브가 전부 같은 것을 깔고 있습니다.

## 설치와 사용

`pasta`(패키지 `passt`)·`nftables`·`util-linux` 가 필요하고, 설치할 때만
`curl gpg tar xz zip unzip` 이 필요합니다. 데비안/우분투:
`sudo apt install passt nftables curl gpg xz-utils zip unzip`.

리눅스 x86_64 용 정적 바이너리가 [릴리스](https://github.com/needmoretruth/BBIWY/releases)마다
붙어 있습니다 — 그 태그에서 `.github/workflows/release.yml` 이 지은 것입니다. 직접 지어도 됩니다:

```sh
cd launcher && cargo build --release
./target/release/bbiwy install      # 최신 Mullvad Browser, 서명 확인, 잠금
sudo ~/.local/bin/bbiwy apparmor    # 우분투 23.10+ 에서만, 한 번 — 필요하면 install 이 알려 줍니다
bbiwy doctor                        # 이 기계에서 격리가 실제로 성립하는가
bbiwy run daily                     # 또는 hardened · tor · i2p, 메뉴에서도
```

| 명령 | |
|---|---|
| `bbiwy install [--tor-port 9050] [--i2p-port N]` | 내려받고, 고정해 둔 Tor Browser Developers 키로 서명 확인, 잠금·테마·메뉴 항목. 내려받는 대신 `--from <tar.xz>` 또는 `--browser <dir>` |
| `bbiwy run <프로필> [url…]` | 네임스페이스에 봉인해서 띄웁니다. 경로 데몬이 없거나 권한 떨굼이 안 먹었으면 거부합니다 |
| `bbiwy status` | 실행 중인 프로필과, 허용 목록이 통과시킨 것·떨어뜨린 것의 수 |
| `bbiwy explain <프로필>` | 그 프로필이 받는 pasta 명령·nft 규칙·잠금을 그대로 보여 줍니다 |
| `bbiwy list` · `bbiwy doctor` · `bbiwy uninstall [--purge]` | |

tor 경로는 `127.0.0.1:9150` 의 SOCKS 포트를 씁니다(시스템 tor 는 9050:
`bbiwy install --tor-port 9050`). i2p 경로는 i2pd 나 Java I2P 의 HTTP 프록시
`127.0.0.1:4444` 를 씁니다. 브라우저가 스스로 업데이트하면 테마가 지워지는데,
`bbiwy run` 이 다음 창을 띄우기 전에 되돌려 놓습니다.

## 구조

```
launcher/          런처 (Rust · #![forbid(unsafe_code)] · 의존성 없음)
tools/
  isolation-lab/   격리망을 만들고, 빠져나가려는 것을 세고, 판정을 낸다
  fake-transport/  기록하는 SOCKS5·HTTP 프록시 — 브라우저가 주소가 아니라 이름을
                   넘기는지, 프록시를 우회하는 것이 없는지 증명한다
  leakcheck/       진짜 브라우저를 몰아서 설정 잠금 상태를 읽고 지문을 뽑는다
  probe/           일부러 누수를 낸다. 계측이 눈뜬장님이 아님을 증명하려고
  profiles/        프로필 생성과 지문 비교
docs/
```

`doctor`는 격리가 성립하지 않으면 통과시키지 않습니다. **일부러 그렇게 했습니다** —
보호받지 못하는 채로 조용히 도는 프라이버시 도구는 아예 안 뜨는 것보다 나쁩니다.

## 베이스

[Mullvad Browser](https://mullvad.net/en/browser) 위에 짓습니다. 그것은 Tor Browser
위에, 그것은 Firefox ESR 위에 있습니다. **여기서 Tor는 네 경로 중 하나**이므로 중립적인
베이스가 맞습니다.

BBIWY는 Mullvad·Tor Project·Mozilla와 아무 관계가 없습니다.

## 라이선스

[MPL-2.0](LICENSE).
