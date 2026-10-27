# 운영방 전송 준비 진단

Windows에서 지정한 방을 로컬 목록으로 식별하고 이미 있는 창 후보만 검사합니다. 전송 코드, 입력·클립보드·방 열기 기능이 없습니다. 조회 결과는 `%LOCALAPPDATA%\KakaoReader\receipts`에 저장되므로 공개하지 마세요.

```powershell
python experimental/room-preflight/preflight.py --name "정확한 방 이름"
```

`TARGET_WINDOW_NOT_FOUND`는 해당 방 제목의 창 후보가 없다는 뜻입니다. 닫힌 방의 대화 데이터가 조회되어도 전송 준비 완료가 아닙니다. 창 후보가 있어도 일반 방의 ID와 창 연결이 검증되지 않아 `send_ready=false`를 반환합니다.

이 도구는 방을 자동으로 열거나 전달하지 않습니다. 방 열기가 필요하면 별도의 [방 열기 실험 CLI](../room-open/README.md)를 사용합니다. 해당 CLI는 검색·열기 순간에 화면 조작이 필요하며 일반 방 전송 기능은 없습니다.

이 사전검사 도구는 앱 RAM 중단선469,893,120B, 작업 트리256MiB·40초, 방 조회20초를 유지합니다. 카카오톡은 로그인된 대화형 세션에서 실행 중이어야 합니다.
