# 검증된 읽기 도구 업데이트 자동 적용

프로젝트별로 한 번 동의하면, **관리 실행기를 통한 다음 읽기 전에** 검증된 정식 도구 업데이트를 확인합니다. 카카오톡 자체를 업데이트하거나 미지원 버전을 자동으로 분석하는 기능은 아닙니다. 현재 앱에 맞는 검증본이 없으면 읽기를 멈춥니다.

## 한 번 켜기

공개 저장소를 내려받은 폴더에서 실행합니다. `PROJECT_PATH`는 사용할 기존 프로젝트의 절대경로입니다. 먼저 [Windows 사용법](../skills/kakaotalk-mac/references/windows.md)에 따라 `.venv`에 고정 의존성을 설치합니다. 다른 가상환경을 쓴다면 아래 `$python` 경로를 그 Python x64로 바꿉니다. Claude Code는 `codex`를 `claude`로 바꿉니다.

```powershell
$python = (Resolve-Path '.venv\Scripts\python.exe').Path
& $python tools/reader_manager.py enable --project "PROJECT_PATH" --agent codex
$manager = Join-Path 'PROJECT_PATH' '.kakaotalk-reader\reader_manager.py'
& $python $manager status --agent codex
```

`enable`은 프로젝트 안에 고정 관리 실행기와 동의 설정을 만듭니다. 다운로드, 스킬 덮어쓰기, 예약 작업, 전역 설정 변경은 없습니다. 이미 설치한 읽기 스킬이 필수는 아니지만 AI가 다음 명령으로 읽도록 안내해야 합니다. `status`의 `ENABLED`는 설정 상태이며 실제 읽기 성공이 아닙니다.

## 평소 읽기

```powershell
& $python $manager read --agent codex -- messages --name "정확한 방 이름" --limit 3
```

관리 옵션과 실제 읽기 명령 사이에 `--`를 넣습니다. `rooms`, `messages`, `search`, `self`, `doctor`, `accounts`, `schema`, `resume`과 허용된 읽기 옵션을 전달할 수 있습니다. 계정이 여러 개면 `--account-token`도 실제 읽기 명령 뒤에 붙입니다. 후보 시험 옵션, 발신, 화면·첨부 실험, 임의 명령은 허용하지 않습니다.

정식 릴리스를 성공적으로 확인하면 최대1시간 그 결과를 재사용합니다. 앱의 해시·아키텍처가 바뀌면 즉시 새 검증본을 확인합니다. 확인 실패는 이전 성공 캐시를 무효화합니다. 직접 `kakao_read_win.py`를 실행하면 이 자동 확인은 없습니다.

명시적으로 지금 확인하거나 끄려면 다음 명령을 사용합니다.

```powershell
& $python $manager check --agent codex --force
& $python $manager disable --agent codex
```

`check`는 업데이트를 받을 수 있지만 대화를 읽지 않습니다. `disable`은 관리형 실행을 끄고 설치된 payload·이전 버전·영수증을 보존합니다. 예약 작업은 처음부터 만들지 않습니다. 관리형 실행이 꺼진 뒤의 수동 읽기는 사용자가 별도로 선택합니다.

## 무엇을 검증하는가

자동으로 적용하려면 아래 조건이 모두 맞아야 합니다.

1. 고정 저장소 `aixlife/kakaotalk-automation`의 **정식 stable 릴리스**여야 합니다. prerelease와 시험 후보는 제외합니다.
2. `verified-reader-update.json`의 태그와 정확한 Git 커밋이 맞아야 합니다.
3. 전체 읽기 payload의 파일 목록·SHA-256·크기·경로가 맞아야 합니다. 링크, 경로 탈출, 대소문자 충돌, 압축 해제 크기 초과는 차단합니다. 다운로드한 설치기를 실행하지 않습니다.
4. 현재 앱의 **정확한 해시와 아키텍처**에 실제 읽기 QA가 연결되어야 합니다. 같은 버전 이름, 서명자, 합성 CI 성공만으로 승인하지 않습니다.
5. QA는 소스 해시, 정상 종료, 시간 제한, 실제 결과·대조, 페이지 인증과 무입력 조건을 충족해야 합니다. 빈 결과나 timeout을 성공으로 계산하지 않습니다.
6. sequence가 역행하거나 재사용되지 않아야 하며, 로컬 payload가 수정되지 않아야 합니다.

이 구조는 **고정 GitHub HTTPS 출처·커밋·파일 해시를 신뢰**합니다. 별도의 독립적인 전자서명 검증은 아닙니다. 읽기 승인으로 화면 조작·첨부·발신을 허용하지 않습니다. 32비트 소유자 시험 결과도 자동으로 stable 승인에 등록되지 않습니다.

## 저장과 중단 복구

프로젝트 안 `.kakaotalk-reader`에 고정 관리 실행기, 에이전트별 설정·저널, 버전별 payload가 저장됩니다. 새 버전을 별도 디렉터리에서 검증한 뒤 `active.json` 포인터만 원자적으로 교체합니다. 이미 읽기 중인 프로세스는 기존 버전의 파일을 계속 사용합니다.

이전 payload와 `active.previous.json`을 보존합니다. 교체 도중 프로세스가 종료되면 다음 `check/read`에서 저널과 파일 해시를 확인해 교체 전·후 상태를 판정합니다. 다른 변경이 끼어 있으면 덮어복구하지 않고 `RECOVERY_CONFLICT`로 중단합니다. 잠금 파일의 나이를 보고 지우지 않으며 실제 잠금 소유권은 프로세스 종료 시 OS가 해제합니다.

관리 실행기 자체는 자동 갱신하지 않습니다. 프로토콜이나 bootstrap 변경이 필요하면 정식 안내에 따른 명시적 업그레이드가 필요합니다. 원본 저장소 없이도 설치된 관리 실행기와 payload는 동작하지만, 수동 설치·32비트 시험 도구를 쓰려면 저장소를 보관합니다.

임의 버전으로 돌리는 rollback CLI는 없습니다. 문제 시 `disable`로 자동 적용을 끄고 현재·이전 파일을 보존한 뒤 검토합니다. 포인터·sequence를 직접 수정하거나 이전 버전을 새 버전으로 위장하지 않습니다. 검증한 수정본은 더 높은 sequence의 정식 릴리스로 배포합니다.

## 실패 시 처리

| 결과 | 처리 |
|---|---|
| `NO_VERIFIED_UPDATE` / `VERIFIED_MANIFEST_MISSING` | 현재 앱에 맞는 정식 검증본이 없습니다. 기존 파일을 보존하고 읽기를 중단합니다. |
| `CURRENT_OFFLINE` | 네트워크는 실패했지만 현재 앱과 정확히 일치하는 온전한 기존 payload로 읽습니다. 새 업데이트 적용은 아닙니다. |
| `UPDATE_NETWORK_UNAVAILABLE` / `UPDATE_NETWORK_TIMEOUT` | 사용 가능한 기존 payload가 없으면 읽기를 시작하지 않습니다. |
| `LOCAL_PAYLOAD_MODIFIED` / `RECOVERY_CONFLICT` | 개인 변경·외부 변경을 덮어쓰지 않습니다. 현재 파일과 이전 버전을 보존하고 차이를 확인합니다. |
| `DEPENDENCY_MISSING` | 요구 버전의 의존성을 프로젝트 가상환경에 명시적으로 설치합니다. 관리 실행기는 pip를 자동 실행하지 않습니다. |
| `BOOTSTRAP_MODIFIED` / `BOOTSTRAP_MANUAL_UPGRADE_REQUIRED` | 고정 관리 실행기의 변경·업그레이드가 필요합니다. 무시하거나 덮어쓰지 말고 정식 안내를 확인합니다. |
| `AUTO_UPDATES_DISABLED` | 프로젝트에서 자동 적용이 꺼져 있습니다. 다시 사용하려면 소유자의 명시 동의로 enable합니다. |

네트워크 오류 후 기존 버전 사용은 현재 앱과 실물 QA가 정확히 일치하고 파일이 온전한 경우에만 가능합니다. 변조·잘못된 manifest·미지 앱은 네트워크 장애처럼 처리해 우회하지 않습니다. 카카오톡 재설치, 로그인·보안 변경, 해시 허용 목록 수정으로 실패를 숨기지 않습니다.

새 카카오톡 버전에 코드 수정이 필요하면 유지보수자가 별도 실물 검증 후 릴리스해야 합니다. 자동 업데이트의 역할은 **그 검증된 수정본을 사용자에게 전달하는 것**입니다.
