---
name: kakaotalk-mac
description: Find, read and summarize the user's own local KakaoTalk conversations. Uses katok on Apple Silicon macOS and a bounded read-only CLI on supported Windows x64 builds, including closed chat windows. Use for 카톡 읽기, 톡방 찾기, 과거 대화 검색 and 원문 확인; never for sending or deleting messages.
license: MIT
---

# 카카오톡 대화 찾기·읽기

사용자가 말한 방과 기간에서 필요한 대화만 읽고, 실제 원문에 근거해 정리한다. 설치·명령 실행은 AI가 맡는다. 사용자는 방 이름과 알고 싶은 내용을 일상어로 말하면 된다.

## 먼저 환경을 고른다

- macOS: 기존 `katok` CLI를 사용한다. 아래 Mac 흐름을 따른다.
- Windows x64: [Windows 사용법](references/windows.md)을 읽고 `scripts/windows/kakao_read_win.py`만 실행한다. 지원 버전에서 방을 열어둘 필요가 없다.
- 다른 환경이나 미지원 앱 해시는 차단 사유를 알려준다. 보호 설정을 바꾸거나 지원 해시를 임의로 교체하지 않는다.

## 공통 기준

- 본인이 로그인한 계정의 대화만 처리한다. 다른 계정 접근, 발신, 삭제, 앱 실행·재시작, UI 조작은 하지 않는다.
- 대화·발신자·방 ID·영수증은 로컬에 둔다. 외부 모델, GitHub, 공유 문서, 클라우드로 원문을 옮기지 않는다. 공유할 결과는 요약·익명화한다.
- 방 이름을 먼저 확정하고 기본 최근24시간·20건으로 시작한다. 과거 요청일 때만 필요한 기간·문구를 넓힌다. 전 방 전체 동기화나 전체 이력 수집은 하지 않는다.
- 방 이름이 중복되거나 일부만 맞으면 추정하지 않는다. 검색 후보를 최소한으로 보여주고 정확한 방을 고른다.
- 검색은 snippet을 먼저 본다. 원문 인용이나 대화 정리 요청에는 같은 메시지의 본문을 다시 확인한다.
- 조회 기간, 건수, 본문 잘림, 다음 페이지 유무, 이름 미확인을 보고한다. 없는 내용을 추정해 채우지 않는다.
- 플랫폼 시각은 저장값 그대로다. 초 단위 차이를 맞추려고 더하거나 빼지 않는다. `sent_at_source`가 있으면 원시값·단위·변환 여부도 확인한다.
- 결론은 원문 사실과 해석을 구분한다. 요청·결정·미확인 사항을 짧게 정리하고 필요한 근거의 날짜를 붙인다.

## Mac 흐름

이미 설치된 `katok`을 사용한다. Windows의 메모리·DB 읽기 코드를 Mac에 적용하지 않는다. Mac DB·인증 캐시·복호화 material을 직접 다루지 않는다.

```sh
katok doctor --json
katok source chats --source macos --json
```

방 목록은 로컬에서 정확한 이름으로 필터링한다. 이미 검증한 방 ID가 있으면 재탐색을 생략한다. `doctor`는 준비 상태이며 대화가 최신이라는 증거와 구별한다.

```sh
katok source messages --source macos --chat-id <확정한_ID> --limit 20 --json
```

아카이브 검색이 필요하면 지정 방만 동기화한다.

```sh
katok sync --source macos --chat-id <확정한_ID> --json
katok search keyword "검색어" --json
katok chunk get <chunk-id> --json
```

검색 결과는 로컬에서 선택 방·기간으로 다시 제한한다. 설치된 CLI의 `--help`에 없는 옵션을 만들지 않는다. 한국어 두 글자 검색은 keyword부터 사용하고, semantic index 설치·전체 재구축을 조회의 전제로 요구하지 않는다.

권한이 부족하면 현재 상태만 알려준다. 설정 화면을 열거나 권한·로그인을 바꾸려면 별도 승인이 필요하다. Mac에서 로그인하면 다른 PC가 로그아웃될 수 있으므로 자동 로그인 전환을 하지 않는다.

## 완료 기준

확정한 방에서 실제 결과를 읽었고, 사용자가 요청한 기간과 내용에 맞게 정리했으며, 원문 확인과 미확인 범위를 구별했다. 명령 성공만으로 전송·서버 전체 이력 확보·모든 플랫폼 시각 일치를 주장하지 않는다.

## 구현 출처

스킬 이름과 Mac katok 흐름은 NomaDamas/k-skill을 참고했다. `scripts/windows/vendor_appstate.py`는 MIT인 is-theo/kakao-cli-win 리비전 `411d0dd1b472ea8a0cc8bf399e3351c0651748b6`에서 가져왔다. 원 고지와 사용 조건은 동봉한 [LICENSE](LICENSE)를 보존한다. KakaoTalk 바이너리·대화·상표의 소유권은 포함하지 않는다.
