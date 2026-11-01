# Windows에서 사용하기

이 경로는 Windows의 현재 로그인 계정에 남아 있는 로컬 대화를 읽는다. 채팅창을 닫아도 되고, 다른 앱을 사용해도 된다. KakaoTalk 자체는 로그인된 상태로 실행 중이어야 한다. 앱을 종료한 완전 오프라인 상태나 서버의 누락 이력을 가져오는 기능은 없다.

읽기 검증 설치본은 **26.8.2.5324·26.9.1.5339 / 카카오톡 x64**다. **26.9.1.5339 x86 앱은 소유자 PC에서 시험하는 후보이며 실제 읽기 검증 대기**다. Windows와 Python은 두 경우 모두 64비트여야 한다. 실행 파일 SHA-256과 PE 아키텍처를 확인하므로 버전 번호만 같아도 다른 파일은 차단한다. 여러 앱 프로세스는 차단하며, 계정 폴더가 여러 개면 아래 명시적 선택 절차를 따른다. 별도 화면·첨부 실험은 새 읽기 빌드에 허용되지 않는다.

`doctor`는 `app_version`, `app_architecture`, `installation_sha256`, `reason`, `next_action`을 반환한다. `APP_X86_UNSUPPORTED`이면 32비트 설치 문제, `INSTALLATION_NOT_REVIEWED`이면 미검증 빌드다. `READY`는 파일·런타임 준비 상태이며 `read_verification=NOT_RUN`이다. 실제 선택 방 읽기로 따로 확인한다. 새 버전이면 정식 읽기 도구 배포본을 확인하며, 임의 해시 허용이나 환경변수·로컬 승인 파일로 지원 범위를 넓히지 않는다.

26.9.1.5339 x64를 사용하는 데 26.8로 다운그레이드할 필요는 없다. x86은 기존 앱을 유지한 채 [별도 검증 도구](https://github.com/aixlife/kakaotalk-automation/blob/main/docs/windows-x86-probe.md)를 실행한다. `doctor --candidate-x86`의 `CANDIDATE_READY`는 시험 준비 상태다. 정식 읽기 지원이나 실제 성공을 뜻하지 않는다. 재설치·버전 전환·로그인·보안 변경은 검사에 포함하지 않는다.

## 준비 확인

Python3.11 이상 x64, `cryptography==47.0.0`, `apsw==3.54.1.0`을 사용한다. 기존 x64 실물 실행은 Python3.14 x64에서 검증했다. APSW는 큰 DB의 읽기전용 페이지 접근을 맡는다. 새 가상환경에 의존성을 설치해도 보안·권한·로그인 설정은 바꾸지 않는다.

현재 읽고 있는 `SKILL.md` 폴더의 실제 절대경로를 `$skill`에 넣는다. 아래 경로는 가상 예제이며 설치 위치에 맞춰 바꾼다. 작업 프로젝트에 가상환경을 만든다.

```powershell
$skill = 'C:\work\example\skills\kakaotalk-mac'
python -m venv .venv
$python = (Resolve-Path '.venv\Scripts\python.exe').Path
$cli = Join-Path $skill 'scripts\windows\kakao_read_win.py'
& $python -m pip install -r (Join-Path $skill 'scripts\windows\requirements.txt')
& $python $cli doctor
```

의존성 파일도 스킬 폴더 안에 있으므로 폴더만 복사해 설치해도 사용할 수 있다. `doctor`는 앱을 띄우거나 대화 DB를 읽지 않는다.

## 여러 계정 폴더가 남아 있을 때

```powershell
& $python $cli accounts
& $python $cli messages --name "가상 프로젝트 논의방" --limit 3 --account-token "64자리_계정_토큰"
```

`accounts`는 계정 폴더의 익명 토큰·DB 크기·수정일·백업명 힌트만 확인한다. 대화 DB 내용이나 앱 메모리를 읽지 않는다. 계정이 여러 개면 `ACCOUNT_SELECTION_REQUIRED`로 멈춘다. 소유자가 사용할 계정을 확인한 뒤 출력된 **전체 64자리 토큰**을 지정한다. 이 메타데이터만으로 로그인 계정이 증명되지는 않는다. 최근 폴더를 자동 선택하거나 백업 폴더를 지우지 않는다. 확실히 고를 수 없으면 중단하고 상황을 설명한다.

## 동의한 프로젝트에서 자동 업데이트 사용

공개 저장소 전체를 내려받은 위치에서, 사용자 동의 후 한 번 실행한다. `PROJECT_PATH`는 기존 프로젝트의 절대경로다. Claude Code는 `claude`로 바꾼다.

```powershell
& $python tools/reader_manager.py enable --project "PROJECT_PATH" --agent codex
$manager = Join-Path 'PROJECT_PATH' '.kakaotalk-reader\reader_manager.py'
& $python $manager status --agent codex
& $python $manager read --agent codex -- messages --name "가상 프로젝트 논의방" --limit 3
```

이후 읽기는 관리 실행기를 통해 실행한다. 직접 `$cli`를 실행하면 자동 업데이트 확인은 없다. `enable`은 프로젝트 안에 고정 관리 실행기를 만들며 다운로드·예약 작업·기존 스킬 교체는 하지 않는다. 읽기 요청 때 현재 앱에 맞는 정식 stable 배포본을 확인한다. 성공한 확인은 최대1시간 재사용하고, 앱 해시·아키텍처가 달라지면 다시 확인한다.

정확한 앱 해시·아키텍처·실물 QA가 정식 manifest에 있어야 자동 반영한다. `NO_VERIFIED_UPDATE`는 아직 맞는 검증본이 없다는 뜻이다. 32비트 시험 후보·발신·화면 실험은 이 경로로 실행하지 않는다. 오류가 난 관리 실행기를 직접 CLI로 자동 우회하지 않는다. 사용자가 관리형 실행을 끄고 수동 경로로 바꾸는 경우는 별도 결정으로 다룬다.

```powershell
& $python $manager check --agent codex --force
& $python $manager disable --agent codex
```

`disable`은 자동 적용을 끄고 기존 payload·이전 버전을 보존한다. 예약 작업은 처음부터 만들지 않는다. 의존성이 바뀌면 `DEPENDENCY_MISSING`으로 중단하므로 검증한 요구 버전을 가상환경에 설치한다. 관리 실행기 자체는 자동 갱신하지 않는다. [업데이트·복구 상세](https://github.com/aixlife/kakaotalk-automation/blob/main/docs/verified-updates.md)를 참고한다.

## 대화를 찾고 읽기

```powershell
& $python $cli rooms --name "가상 프로젝트"
& $python $cli messages --name "가상 프로젝트 논의방" --limit 20
& $python $cli search --name "가상 프로젝트 논의방" --since 2026-01-01 --until 2026-02-01 --query "견적" --limit 20
```

`rooms`는 부분 이름을 허용하지만 `messages/search`는 정확한 방 이름이어야 한다. 동명이면 차단한다. `self`는 이름을 추정하지 않고 자기방을 고른다.

```powershell
& $python $cli self --limit 3
```

- 기본 최근24시간·20건, 페이지 최대100건이다. `--since`는 포함, `--until`은 제외한다. 시간대 생략 시 한국 시각이다.
- `search`는 문구가 나온 부분만 반환한다. 퍼센트·밑줄·역슬래시는 일반 문자다. 인용하려면 해당 ID 범위의 `messages`를 다시 읽는다.
- `messages` 본문 최대4000자, 긴 본문은 `text_truncated=true`다. 이를 전체 원문으로 인용하지 않는다.
- `author_name_status`가 `unresolved/conflict`면 이름을 추정하지 않는다. `self`의 ‘나’는 본인 역할이며 프로필 실명이 아니다.
- `limit_reached`와 `next_cursor`를 확인한다. 과거 전체 범위가 필요하면 같은 방·필터에 `--cursor`를 전달한다. 커서는 계정·방·필터·기간·ID 상한을 유지한다.
- `--after-id`는 해당 ID 다음 메시지, `--before-id`는 그보다 이전 메시지다. 두 방향을 동시에 쓰지 않는다.

## 시각과 저장 영수증

`sent_at`은 원시 시각의 단위만 초로 변환한 값, `sent_at_kst`는 한국 시각 표시다. `sent_at_source.raw_value/sqlite_type/unit/rounding_applied`로 원래 숫자와 보정하지 않았음을 확인한다. 같은79건을 대조한 검사에서 두 앱의 정수 저장값 자체가38건은1초 달랐고, 각 CLI는 자기 저장값과79/79 같았다. 메시지 ID를 기준으로 대조하고 시각 완전 일치는 별도로 판정한다. 이 관측을 모든 메시지의 고정 보정값으로 적용하지 않는다.

결과·실행 영수증은 `%LOCALAPPDATA%\KakaoReader\receipts`에 저장된다. 원문이 들어 있으므로 동기화·공유·Git 추가를 하지 않는다. 키·중간키·프로세스 덤프·평문 DB는 저장하지 않는다. 영수증은 자동 삭제하지 않는다.

응답이 끊겼으면 새로 실행하지 말고 기존 `request_id`로 같은 저장 결과를 회수한다.

```powershell
& $python $cli resume --request-id <32자리_요청_ID>
```

## 제한과 실패 처리

- 전체 reader 트리256MiB/50초, 내부256MiB/45초, 실제 읽기40초와 프로세스 읽기384MiB, 응답2MiB 제한을 유지한다.
- 24MiB를 넘는 DB/WAL 또는 WAL 반영 후 큰 논리 DB는 페이지 단위 스트리밍으로 읽는다. 스트리밍 경로는 원본·논리 DB512MiB, WAL256MiB, 누적 파일 읽기3GiB, 공유 버퍼28MiB, APSW SQLite heap32MiB, 자체40초를 추가로 제한한다. 이 세부 집계는 작은 DB의 기존 경로를 포함하지 않지만 전체256MiB Job은 양쪽을 함께 제한한다. 모든 유효 nonzero 페이지 HMAC·DB/WAL 이중 해시·`quick_check`를 통과해야 한다. 검증한 baseline과 다른 페이지를 감지하거나 한도에 도달하면 결과를 버린다. 원본 파일을 잠그는 원자적 snapshot은 아니다.
- 앱 private 메모리469,893,120바이트 미만 및2GiB 미만 조건에서만 읽는다. 초과 시 reader가 중단하며 앱을 종료하거나 앱 메모리를 제한하지 않는다.
- `ACCOUNT_SELECTION_REQUIRED`이면 위 계정 선택 절차를 따른다. 큰 DB 한도는 `--limit 1`로 해소되지 않을 수 있다. 큰 합성 DB 28,745,728B 검증은 모든 실제 계정·512MiB DB의 시간 내 성공 보장이 아니다. 상한을 늘리지 말고 차단 사유를 보고한다.
- 매번 실행 파일 해시·프로세스 경로·PID·생성시각을 새로 확인한다. 앱 재시작 후 낡은 PID를 재사용하지 않는다. 초기화 중 실패하면 로그인 완료 후 새 요청으로 다시 읽을 수 있다.
- Windows 기본 읽기 권한으로 동작하지 않으면 `BLOCKED`다. 관리자 전환, 디버그 권한, 백신 예외, 보안 해제, 앱 주입으로 우회하지 않는다. Python `-O` 최적화 모드는 사용하지 않는다.
- 허용 표면은 이 CLI뿐이다. 에이전트가 별도 DB·키 추출 도구를 만들거나 모든 방을 순회하지 않는다.
- `input_calls=0`은 읽기 구현의 동작 범위다. 매 요청마다 별도의 사용자 화면 캡처·관찰을 수행한다는 뜻은 아니다. 실물 창 전후 검증은 [기존 검증 기록](https://github.com/aixlife/kakaotalk-automation/blob/main/docs/QA.md), 새 읽기 빌드는 [호환성 검증](https://github.com/aixlife/kakaotalk-automation/blob/main/docs/compatibility-QA-20261102.md)을 참고한다.
- 오류·잘림·과거 페이지 남음을 결과와 함께 보고한다. `BLOCKED`를 빈 대화나 완료로 표시하지 않는다.
