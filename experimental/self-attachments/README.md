# Windows 자기방 첨부 시험 도구

이 도구는 **나와의 채팅에 준비된 무해한 TXT와 PNG를 각각 한 번 보내는 실험용 QA**입니다. 임의 파일이나 다른 방의 발신 도구는 아닙니다. 안정 배포된 대화 읽기 기능과 구분합니다.

원래 실행기에서는 Windows26.8.2.5324에서 실제 파일·사진 수신 및 다운로드 SHA256 일치를 확인했습니다. 이 폴더는 그 실행기를 개인 PC 경로 없이 옮긴 버전입니다. 이식본의 실제 송수신 검증은 아직 하지 않았으며, 합성 검사와 원본 실물 증거를 같은 것으로 표시하지 않습니다.

2026-10-27 이식본 `plan`을 실제 Windows 사용자 세션에서 실행했습니다. 당시 자기방 창 상태 검사가 `SELF_WINDOW_SIGNATURE_OR_STATE_CHANGED`로 차단되어 `PLAN_BLOCKED_NO_SEND`를 반환했습니다. 이 실행의 실제 발신은0회이며 준비 완료나 송수신 성공을 입증하지 않습니다. [패키지 검증 범위](../../docs/release-QA-20261027.md)를 참고하세요.

## 준비

Windows x64, Python3.11 이상, 지원 설치본26.8.2.5324, 본인이 로그인한 사용자 세션이 필요합니다. 카카오톡 자기방을 하나 열어 최소화하지 않고 입력칸을 비운 뒤 다른 앱으로 돌아옵니다. 일반 파일 전송 확인 옵션 OFF가 이미 적용되어 있어야 합니다. 도구가 창·로그인·옵션·보안·클립보드를 변경하지 않습니다.

저장소 최상위에서 기존 읽기 의존성을 설치합니다.

```powershell
python -m pip install -r requirements-windows.txt
python experimental/self-attachments/self_qa.py plan
```

`plan`은 방·입력칸·설정 상태를 읽기만 합니다. 창을 열거나 입력하거나 파일을 투입하지 않습니다. 성공하면 `PLAN_READY_NO_SEND`와 `plan_id`가 나옵니다. 실패하면 이유를 확인하고 멈춥니다.

## 본인이 두 테스트 메시지 발신을 승인한 경우만

다음 명령은 자기방에 TXT70B와 PNG5,931B를 각각 최대 한 번 추가합니다. 앞의 성공한 `plan_id`를 넣으며, 승인 플래그는 그 두 메시지를 실제로 보내도 된다는 본인의 명시적 의사가 있을 때만 사용합니다.

```powershell
python experimental/self-attachments/self_qa.py execute-self-qa --plan-id <plan_id> --approve-self-chat-txt-and-png
```

TXT 검증이 성공한 뒤 PNG를 진행합니다. 파일 type18·사진 type2, 본인 새 수신 행, 다운로드 원본 해시, 전송 전부터 해시 확인까지의 창/전면/커서 관측을 함께 확인합니다. `TWO_SELF_ATTACHMENTS_VERIFIED`만 두 첨부 완료입니다.

실패·타임아웃·결과 불명에서는 재발신하지 않습니다. 같은 테스트 내용은 이후 새 계획에서도 일회 claim으로 차단합니다. 상태 폴더를 지워 재시도하지 않습니다. 결과 조회는 로컬 저장본만 읽습니다.

```powershell
python experimental/self-attachments/self_qa.py show --id <plan_id>
python experimental/self-attachments/self_qa.py show --execution --id <execution_id>
```

## 보관과 제한

코드는 저장소에서 읽고, 요청·원문을 포함할 수 있는 읽기 영수증·관측·다운로드 파일은 `%LOCALAPPDATA%\KakaoReader\self-attachment-qa`에만 보관합니다. 이 폴더를 GitHub나 다른 사람에게 공유하지 않습니다. 별도 reader 영수증은 기존 `%LOCALAPPDATA%\KakaoReader\receipts` 정책을 따릅니다.

원본의 자기방·고정 fixture·일회 claim·관측기 및 Windows Job256MiB/50초 제한을 유지합니다. 기존 앱 RAM 중단선469,893,120B도 유지하므로 다른 PC에서 앱 상태에 따라 차단될 수 있습니다. 제한을 바꾸거나 해시만 교체해 지원 버전을 넓히지 않습니다. 닫힌 방, 다른 방, 임의 파일, 잠금·로그아웃·앱 없는 서버 환경은 지원하지 않습니다. 관측 구간의 새로 표시된 최상위 창0개는 숨겨진 창 전체의 부재나 미래 화면 불변을 보장하지 않습니다.

코드와 fixture는 MIT입니다. reader의 제3자 고지는 저장소 `THIRD_PARTY.md`에 있습니다. 이식 후 실제 시험을 추가하면 원본 QA와 별도의 날짜·설치본·영수증 근거로 기록해야 합니다.
