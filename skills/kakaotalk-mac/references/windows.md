# Windows에서 사용하기

이 경로는 Windows의 현재 로그인 계정에 남아 있는 로컬 대화를 읽는다. 채팅창을 닫아도 되고, 다른 앱을 사용해도 된다. KakaoTalk 자체는 로그인된 상태로 실행 중이어야 한다. 앱을 종료한 완전 오프라인 상태나 서버의 누락 이력을 가져오는 기능은 없다.

검증한 설치본은 **26.8.2.5324 / Windows x64**다. 실행 파일 SHA-256을 고정 확인한다. 다른 버전·변경된 파일·여러 로그인 계정·여러 앱 프로세스는 차단하며, 해시를 바꿔 검증을 건너뛰지 않는다.

## 준비 확인

Python3.11 이상 x64와 `cryptography==47.0.0`을 사용한다. 실제 실행 검증은 Python3.14 x64에서 했다. 새 가상환경에 의존성을 설치해도 보안·권한·로그인 설정은 바꾸지 않는다.

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

- 전체 reader 트리256MiB/50초, 내부256MiB/45초, 실제 읽기40초와 프로세스 읽기384MiB를 유지한다. DB/WAL 각각24MiB, 응답2MiB 제한이다.
- 앱 private 메모리469,893,120바이트 미만 및2GiB 미만 조건에서만 읽는다. 초과 시 reader가 중단하며 앱을 종료하거나 앱 메모리를 제한하지 않는다.
- 매번 실행 파일 해시·프로세스 경로·PID·생성시각을 새로 확인한다. 앱 재시작 후 낡은 PID를 재사용하지 않는다. 초기화 중 실패하면 로그인 완료 후 새 요청으로 다시 읽을 수 있다.
- Windows 기본 읽기 권한으로 동작하지 않으면 `BLOCKED`다. 관리자 전환, 디버그 권한, 백신 예외, 보안 해제, 앱 주입으로 우회하지 않는다. Python `-O` 최적화 모드는 사용하지 않는다.
- 허용 표면은 이 CLI뿐이다. 에이전트가 별도 DB·키 추출 도구를 만들거나 모든 방을 순회하지 않는다.
- `input_calls=0`은 읽기 구현의 동작 범위다. 매 요청마다 별도의 사용자 화면 캡처·관찰을 수행한다는 뜻은 아니다. 실물 창 전후 검증은 [검증 기록](https://github.com/aixlife/kakaotalk-reader-skill/blob/main/docs/QA.md)을 참고한다.
- 오류·잘림·과거 페이지 남음을 결과와 함께 보고한다. `BLOCKED`를 빈 대화나 완료로 표시하지 않는다.
