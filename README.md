# 카카오톡 자동화: 읽기 스킬과 실험 도구

![Python](https://img.shields.io/badge/Python-3.11%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Windows](https://img.shields.io/badge/Windows-x64-blue)

본인이 로그인한 카카오톡의 대화를 읽고, Windows에서 지정한 방을 찾아 여는 오픈소스 도구입니다. 기본 설치는 **읽기 전용 `kakaotalk-mac` 스킬**입니다. **방 자동 열기는 별도 실험 CLI**로 제공하며, 검색 결과를 확인한 뒤 방을 열고 배경에서 창 상태를 점검합니다. 일반 방에 메시지·파일을 보내는 기능은 제공하지 않습니다.

> “가상 프로젝트 논의방에서 지난주에 정한 내용이랑 아직 답 안 나온 것 정리해줘. 원문 근거도 확인하고.”

Windows 읽기는 **채팅창을 열어둘 필요가 없습니다.** 카카오톡은 로그인된 상태로 실행 중이어야 합니다. 다른 앱의 화면·키보드·마우스·클립보드를 조작하지 않습니다. 기본 읽기 스킬에는 메시지·파일 발송을 포함하지 않습니다.

방 열기 실험은 검색·열기 순간에 카카오톡을 잠시 전면으로 가져옵니다. 화면 조작 없는 읽기와 구분해 사용하세요. [방 열기 사용법](experimental/room-open/README.md)과 [검증 범위](docs/room-opening-QA.md)에 실제로 확인한 동작과 남은 한계를 적었습니다.

## 설치하고 사용하기

공개 저장소를 내려받고, 스킬을 사용할 기존 프로젝트 경로를 지정합니다. 아래 `PROJECT_PATH`를 실제 프로젝트의 절대경로로 바꿉니다.

```sh
git clone https://github.com/aixlife/kakaotalk-automation.git
cd kakaotalk-automation
python tools/install.py --agent codex --project "PROJECT_PATH" --dry-run
python tools/install.py --agent codex --project "PROJECT_PATH" --install
```

Claude Code는 `--agent claude`를 사용합니다. 기본 동작은 변경 없는 dry-run이며, `--check`로 설치 상태를 읽기 전용 확인할 수 있습니다. 설치기는 스킬 폴더만 복사하며 패키지 설치·전역 설정·앱 실행·로그인·화면 조작을 하지 않습니다. [설치 위치, 충돌 처리와 준비 확인](docs/installation.md)을 참고하세요.

설치한 프로젝트를 Claude Code나 Codex에서 열고 아래처럼 말하면 됩니다.

> “kakaotalk-mac 스킬로 내 환경을 확인하고, 가상 프로젝트 논의방의 최근 대화부터20건 읽어줘. 화면이나 보안·로그인 설정은 바꾸지 마.”

Codex 설치 위치는 프로젝트의 `.agents/skills/kakaotalk-mac`, Claude Code는 `.claude/skills/kakaotalk-mac`입니다. 같은 내용이 이미 있으면 변경하지 않으며, 다른 내용이 있으면 덮어쓰거나 자동 백업하지 않고 중단합니다.

- Mac: 이미 설치한 `katok`을 사용합니다. [스킬 본문](skills/kakaotalk-mac/SKILL.md)의 Mac 흐름을 따릅니다. Mac용 katok 바이너리는 이 저장소에 포함하지 않습니다.
- Windows: Python3.11 이상 x64가 필요하며 실제 검증은3.14에서 했습니다. [Windows 사용법](skills/kakaotalk-mac/references/windows.md)의 준비 확인·조회 예제를 따릅니다. 런타임에 REA·Ghidra·WSL·SSH·화면 제어 도구는 필요하지 않습니다.

## Windows에서 방 찾아 열기

저장소 폴더에서 실행합니다. 로그인된 Windows 데스크톱과 **KakaoTalk 26.8.2.5324 x64**가 필요합니다. 대화방은 닫혀 있어도 되지만 카카오톡 메인 창은 표시된 상태여야 합니다. 다른 설치본은 차단하며, 호환성 검사를 해제하지 않습니다. 처음 사용하는 경우 다음 명령으로 가상환경과 의존성을 준비합니다.

```powershell
python -m venv .venv
$python = (Resolve-Path '.venv\Scripts\python.exe').Path
& $python -m pip install -r requirements-windows.txt
& $python experimental/room-open/room_open.py inspect
& $python experimental/room-open/room_open.py search --name "가상 프로젝트 논의방" --allow-ui
```

`search` 결과의 로컬 캡처에서 정확한 방 이름을 확인한 뒤, 저장된 검색 영수증과 해당 행의 **화면 좌표**를 `open`에 전달합니다. 300초 안에 확인하며, 첫 검색 결과를 무조건 선택하지 않습니다. 기존 검색어를 바꾸려면 `search`에 `--replace-search`를 추가합니다.

```powershell
& $python experimental/room-open/room_open.py open --search-receipt "SEARCH_RECEIPT_PATH" --point X Y --confirm-row --allow-ui
& $python experimental/room-open/room_open.py check --name "가상 프로젝트 논의방"
```

`SEARCH_RECEIPT_PATH`, `X`, `Y`는 방금 받은 결과와 실제 행 위치로 바꿉니다. 상세한 [좌표 확인·오류 처리·개인정보 보관 안내](experimental/room-open/README.md)를 먼저 확인하세요. 방을 연 뒤에도 `send_ready=false`이며, 실제 발신은 하지 않습니다. 이 CLI는 기본 스킬 설치기에 복사되지 않으므로 내려받은 저장소 폴더를 유지합니다.

## 지원 범위

| 기능 | Mac | Windows |
|---|---|---|
| 방 찾기·대화 읽기 | 기존 katok | 이 저장소의 읽기 CLI |
| 닫힌 채팅창 조회 | 기존 로컬 소스 | 지원 설치본에서 실물 검증 |
| 과거 날짜·문구·페이지 조회 | 설치된 katok 기능 범위 | 로컬 캐시의 선택 방·기간 |
| 이름 표시·재시작 후 재탐색 | 기존 katok | authorId 기반 이름/본인 역할, 요청마다 새 PID 확인 |
| 방 검색·자동 열기 | 제공하지 않음 | 별도 실험 CLI, 검색 행 확인과 일시적인 화면 조작 필요 |
| 열린 방 배경 점검 | 제공하지 않음 | 별도 실험 CLI, 창 구조·빈 입력칸 상태 확인 |
| 서버에서 누락된 이력 복구 | 제공하지 않음 | 제공하지 않음 |
| 문자·파일 보내기 | 이 스킬 범위 밖 | 이 스킬 범위 밖 |

안정 배포 범위는 읽기 스킬입니다. [방 열기 실험](experimental/room-open/README.md)은 방을 미리 열어둘 필요 없이 검색·열기·배경 점검을 수행합니다. [방 사전검사 실험](experimental/room-preflight/README.md)은 정확한 방 ID와 기존 창 후보만 진단하며 창 열기·입력·발신 코드가 없습니다. [자기방 첨부 실험](experimental/self-attachments/README.md)은 고정 QA 파일만 다룹니다. 세 실험 도구 모두 기본 설치 대상이 아닙니다.

[공개 패키지 검증 범위](docs/release-QA-20261027.md)에 합성 회귀와 Windows 설치 검사를 기록했습니다. [방 열기 QA](docs/room-opening-QA.md)는 기존 원본의 두 방 실물 성공과 배포용 이식본의 검증을 구분합니다.

자기방 준비 검사는 `python experimental/self-attachments/self_qa.py plan`입니다. 이 명령에는 창 열기·입력·파일 드롭이 없으며, 실제 발신은 상세 문서의 별도 명시 승인 명령으로 분리합니다. 기존 실험 소스의 실제 TXT·PNG 송수신 성공과 이번 배포용 이식본을 구분합니다. **배포용 이식본의 실제 송수신은 아직 NOT_RUN입니다.**

방 사전검사는 `python experimental/room-preflight/preflight.py --name "정확한 방 이름"`으로 실행합니다. 창이 없으면 `TARGET_WINDOW_NOT_FOUND`로 종료하며, 창 후보가 있어도 일반 방 ID와 HWND의 연결을 검증한 전송 준비 상태로 판정하지 않습니다.

Windows 검증 설치본은 **26.8.2.5324 x64**입니다. 다른 빌드는 차단합니다. 고정된 실행 파일 해시만 바꾸는 방식으로 지원 범위를 넓히지 않습니다. [실제 QA와 남은 한계](docs/QA.md)를 확인하세요.

**2026-10-27 별도 Windows 자기방 실물 검증을 완료했습니다.** TXT70B·PNG사진5,931B를 각1회 보내 새 자기방 수신 행과 서버 다운로드·회수본의 SHA-256 일치를 확인했습니다. 전송부터 해시 확인까지 관측한 두 구간에서 새로 표시된 카카오톡 최상위 창0개·전면 전환0회였고 전후 전면 창·커서는 같았습니다. 앱26.8.2.5324의 로그인된 Session1, 이미 열린 비최소화 자기방, 빈 입력칸, 다른 앱 전면, 실제 적용된 파일 확인 옵션 OFF 조건의 결과입니다. 동작 소스는 바꾸지 않았습니다. [첨부 QA 결과와 사용 조건](docs/attachments-QA.md)을 참고하세요.

별도 발신 실험기는 고정 자기방 QA용입니다. 일반 방 ID·파일/접근권·완료 응답을 연결하는 외부 전송 계약, 임의 파일·다른 방 발신, 잠금/로그아웃·GUI 없는 서버 실행은 미검증입니다. 방 자동 열기 성공을 실제 전달 성공으로 해석하지 않습니다. Mac 파일·사진 발신은 사용 가능한 외부 호출 경로를 확보하지 못했습니다. 로그인·보안·확인 옵션을 자동 변경하지 않습니다.

## 데이터와 자원

대화는 로컬에서 처리합니다. 읽기 영수증은 `%LOCALAPPDATA%\KakaoReader\receipts`, 방 열기 영수증·검색 캡처는 `%LOCALAPPDATA%\KakaoReader\room-open`에 남습니다. 방 이름과 대화 미리보기가 포함될 수 있으므로 공유하거나 Git에 추가하지 않습니다. 키·프로세스 덤프·평문 DB는 저장하지 않습니다. 코드·합성 테스트·익명화한 QA만 GitHub에 올립니다.

기본 최근24시간·20건, 페이지 최대100건입니다. 읽기 트리256MiB/50초, DB/WAL 각각24MiB 등의 상한이 있습니다. 한도·권한·버전 확인 실패는 `BLOCKED`로 반환합니다. 앱 자체의 RAM 상한이나 보안 설정을 바꾸지는 않습니다.

## 검사와 기여

Windows 런타임 의존성을 설치한 Python으로 합성 검사를 실행합니다. 실제 대화나 인증 파일은 테스트 자료로 쓰지 않습니다.

```sh
python tools/check.py
```

[기여 방법](CONTRIBUTING.md), [보안·권리자 신고](SECURITY.md)를 참고하세요. 다른 앱 빌드 지원은 설치본 식별·읽기 권한·원문 대조·자원 상한·화면 불변 증거를 함께 검토합니다.

## 출처와 저작권

자체 코드와 문서는 [MIT](LICENSE)입니다. 기존 Mac 흐름은 [NomaDamas/k-skill](https://github.com/NomaDamas/k-skill)의 `kakaotalk-mac`과 katok 사용 방식을 참고했습니다. Windows CBOR 파서는 [is-theo/kakao-cli-win](https://github.com/is-theo/kakao-cli-win)의 고정 리비전을 사용하며, 원 저작권·MIT 고지는 [THIRD_PARTY.md](THIRD_PARTY.md)에 보존했습니다. KakaoTalk 실행 파일·대화·화면·상표의 소유권은 해당 권리자에게 있습니다.

Kakao의 공식·제휴 도구가 아닙니다. 각자 본인 계정과 허용된 환경에서 사용하고, 상대방 대화의 취급과 서비스 이용 조건을 확인하세요. 지원 빌드의 로컬 검증은 모든 버전·계정·조직 환경에서의 동작 보장이 아닙니다.
