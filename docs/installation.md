# 프로젝트에 읽기 스킬 설치하기

기본 설치 대상은 `skills/kakaotalk-mac` 읽기 스킬입니다. Codex와 Claude Code에서 같은 스킬 이름을 사용합니다. `experimental/`의 첨부·방 사전검사 도구는 복사하지 않으며, 읽기 스킬 설치만으로 발신 기능이 추가되지 않습니다.

## 내려받기와 설치 계획 확인

Git과 Python 3.11 이상이 필요합니다. 저장소를 내려받고 `PROJECT_PATH`를 스킬을 사용할 기존 프로젝트의 절대경로로 바꿉니다. Windows 경로 예시는 `C:\work\my-project`, macOS 예시는 `/path/to/my-project`입니다.

```sh
git clone https://github.com/aixlife/kakaotalk-automation.git
cd kakaotalk-automation
python tools/install.py --agent codex --project "PROJECT_PATH" --dry-run
```

모드 옵션을 생략해도 기본값은 dry-run입니다. 이 단계는 설치 계획과 경로를 확인하며 파일을 복사하지 않습니다. Claude Code에 설치하려면 `--agent codex`를 `--agent claude`로 바꿉니다.

| 에이전트 | 프로젝트 안 설치 위치 |
|---|---|
| Codex | `.agents/skills/kakaotalk-mac` |
| Claude Code | `.claude/skills/kakaotalk-mac` |

## 설치와 상태 확인

계획에 표시된 프로젝트와 대상 경로를 확인한 뒤 명시적으로 설치합니다.

```sh
python tools/install.py --agent codex --project "PROJECT_PATH" --install
python tools/install.py --agent codex --project "PROJECT_PATH" --check
```

`--check`는 읽기 전용 확인입니다. `--check`, `--dry-run`, `--install` 중 하나의 모드를 선택합니다. 설치기는 현재 소스의 파일별 SHA-256 목록을 생성하고 복사본과 정확히 비교하며, 그 목록의 SHA-256을 결과에 출력합니다. 이는 복사 무결성 검사이며 배포자의 전자서명 검증은 아닙니다. 소스·대상 경로의 심볼릭 링크·Windows reparse point·상위 경로 이동(`..`)을 거절합니다. 홈 폴더나 파일시스템 루트에는 설치하지 않습니다.

대상에 같은 내용이 있으면 변경하지 않습니다. 내용이 다른 기존 스킬은 덮어쓰거나 자동 백업하지 않고 중단합니다. 기존 개인 규칙과 새 스킬의 차이를 먼저 검토한 뒤 사용자가 보존·병합 방법을 정해야 합니다. 경로 가드를 우회하거나 기존 스킬을 삭제해 설치를 강행하지 마세요.

설치기는 프로젝트의 스킬 폴더만 복사합니다. 전역 에이전트 설정, 패키지 설치, 카카오톡 앱 실행, 로그인, 보안 옵션, 화면은 변경하지 않습니다.

복사나 검증이 실패하면 해당 시도에서 만든 변경 없는 파일과 빈 폴더만 되돌립니다. 다른 내용으로 바뀐 파일이나 외부에서 추가된 파일은 보존합니다. 설치가 진행되는 동안 소스·설치 경로를 다른 작업에서 변경하지 마세요.

## 런타임 준비와 첫 읽기

Windows에서는 Python x64와 지원 KakaoTalk 설치본이 필요합니다. [Windows 사용법](../skills/kakaotalk-mac/references/windows.md)의 가상환경·고정 의존성 설치와 `doctor` 절차를 따릅니다. 설치기는 `pip`를 자동 실행하지 않습니다. 실제 검증 설치본은 KakaoTalk 26.8.2.5324 x64이며, 다른 빌드의 가드를 임의로 해제하지 않습니다.

macOS에서는 이미 설치한 `katok`이 필요합니다. 이 저장소에 Mac용 바이너리나 자동 설치기는 포함하지 않습니다. [스킬 본문](../skills/kakaotalk-mac/SKILL.md)의 준비 확인을 따릅니다.

설치한 프로젝트를 에이전트에서 열고 다음처럼 요청합니다.

> “kakaotalk-mac 스킬로 내 환경을 확인하고, 가상 프로젝트 논의방의 최근 대화20건을 읽어줘. 화면이나 보안·로그인 설정은 바꾸지 마.”

`doctor` 통과는 준비 확인이며 실제 대화 읽기 성공과 구분합니다. `BLOCKED`가 나오면 사유를 확인하고, 권한·로그인·앱 버전 가드를 바꾸어 우회하지 않습니다. 조회 결과에 원문이 포함될 수 있으므로 영수증을 Git·공유 문서·공개 Issue에 올리지 않습니다.

## 읽기와 실험 도구의 범위

안정 배포 범위는 방 찾기·대화 읽기·과거 검색입니다. [검증 기록](QA.md)에 실물 읽기 범위와 남은 한계를 구분했습니다.

[자기방 첨부 실험](../experimental/self-attachments/README.md)은 고정 TXT70B·PNG5,931B만 처리합니다. `python experimental/self-attachments/self_qa.py plan`은 발신 없는 준비 검사이며, 실제 발신은 별도 명시 승인 명령입니다. 기존 실험 소스에서는 실제 송수신을 확인했지만 배포용 이식본의 실제 송수신은 아직 NOT_RUN입니다.

[방 사전검사 실험](../experimental/room-preflight/README.md)은 `python experimental/room-preflight/preflight.py --name "정확한 방 이름"`으로 정확한 방과 기존 창 후보를 진단합니다. 창 열기·입력·발신 코드가 없고 `send_ready`는 항상 false입니다. 두 도구 모두 기본 설치에서 제외됩니다. 임의 파일·다른 방 발신, 닫힌 방 자동 열기, 로그인된 데스크톱 없이 동작하는 발신을 보장하지 않습니다. [첨부 QA 기록](attachments-QA.md)은 실물 성공, 차단 이력, 미검증 범위를 별도로 설명합니다.
