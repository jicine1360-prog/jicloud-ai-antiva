# JICloud AI Antiva 사용법 (한국어)

이 문서는 JICloud AI Antiva를 실제로 돌려서 쓰는 방법을 다룹니다. 설계 근거는
[design.md](design.md), 현재 지원 범위와 미완성 항목은
[product-status.md](product-status.md)에 있습니다.

## 0. 쓰기 전에 알아둘 점

- Antiva는 **모델 아티팩트 트리아지(선별) 도구**입니다. 파일을 읽을 때 역직렬화하거나
  실행하지 않습니다. 텐서 값·가중치·연산 그래프를 해석하려 하지 않고, 헤더와 구조만 봅니다.
- 이 빌드는 **관측 전용**입니다. 네트워크나 프로세스를 실제로 차단하지 않습니다.
  `/v1/status`가 `enforcement_mode: "none"`, `enforcement_health: "unavailable"`라고
  답하는 것이 그 사실입니다. 차단처럼 보이는 동작(격리)은 파일 이동만 합니다.
- `status: clean`은 "구현된 검사에서 신호가 없었다"는 뜻이지 "안전하다"는 보장이 아닙니다.
  `clean`은 신뢰 등급이 아니라 **우선순위 낮음**으로 읽으세요.
- 스캐너는 심링크·FIFO·디렉터리를 스캔하지 않습니다. 열기는 `O_NOFOLLOW`로 한 번만 하고,
  그 기술자 때문에 심링크를 일반 파일로 바꿔치기하는 TOCTOU 공격은 막힙니다.
  Windows에는 `O_NOFOLLOW`가 없어서 정규 파일 여부만 검사합니다.

## 1. 실행 방법

### 소스에서 바로

```bash
cd ~/ai-antivirus
PYTHONPATH=src python3 -m ai_antivirus.cli model.safetensors
PYTHONPATH=src python3 -m ai_antivirus.agent_cli --port 8765
```

### 배포 산출물 (zipapp, Python 3.10+)

```bash
./scripts/build-linux.sh
./scripts/make-checksums.sh dist/linux
cd dist/linux && sha256sum -c SHA-256SUMS && cd ../..
./dist/linux/ai-model-scan --help
```

`dist/linux/`에는 `ai-model-scan`(스캐너)과 `ai-model-guard`(가드 서버)가 들어 있습니다.
Windows 산출물은 `dist/windows/`, Android APK는 선택한 파일의 SHA-256만 계산하는
프로토타입입니다. CI는 ubuntu/windows에서 테스트한 뒤 플랫폼별 `dist/`를 빌드해 올립니다.

## 2. 스캔

```bash
# 단일 파일 스캔 (사람이 읽는 리포트)
./dist/linux/ai-model-scan ~/models/4x-UltraSharp.pth

# JSON 리포트 (파이프/스크립트용)
./dist/linux/ai-model-scan model.pt --json

# 디렉터리 재귀 스캔 (JSONL 한 줄에 하나)
./dist/linux/ai-model-scan ~/ComfyUI/models --recursive --json > scan.jsonl

# 차단 목록(위협 피드)과 함께 스캔
./dist/linux/ai-model-scan model.gguf --threat-feed threats.jsonl
```

디렉터리를 스캔하려면 `--recursive`가 반드시 필요합니다.

**종료 코드** (자동화 연동용):

| 코드 | 의미 |
| --- | --- |
| 0 | 차단 신호 없음 |
| 1 | 최소한 한 개 파일이 `blocked` |
| 2 | 사용법 오류, 또는 읽기/입력 오류 발생 |

### 리포트 필드

```json
{
  "schema_version": 1,
  "path": "/home/hoony/models/model.safetensors",
  "size_bytes": 335034840,
  "sha256": "…",
  "detected_format": "safetensors",
  "status": "clean",
  "findings": [{"severity": "low", "code": "…", "message": "…"}]
}
```

`status`는 `blocked`(high findings 1개 이상) → `review`(medium/low) → `clean` 순으로 판단합니다.

### findings 코드표

| 심각도 | 코드 | 의미 / 조치 |
| --- | --- | --- |
| high | `archive_bomb` | 아카이브가 선언한 전개 크기가 허용량을 넘음. 전개 금지 |
| high | `archive_path_traversal` | 멤버가 전개 디렉터리를 벗어남(`../`) |
| high | `archive_symlink` | 아카이브에 심링크 멤버. 전개 시 경로 이탈 가능 |
| high | `archive_special_file` | 디바이스·FIFO·소켓 멤버 선언. 전개 시 막힘/파괴 |
| high | `archive_executable_payload` | 스크립트·네이티브 바이너리 포함 |
| high | `invalid_archive` | ZIP 구조 자체가 잘못됨 |
| high | `threat_intel_match` | 위협 피드의 차단 SHA-256과 일치 |
| medium | `archive_unsafe_member` | 아카이브 안에 객체 직렬화 멤버(`data.pkl` 등). 로딩 시 코드 실행 가능 |
| medium | `archive_too_many_members` | 멤버 수가 한 패스 검사량을 초과(일부만 검사됨) |
| medium | `archive_finding_limit` | 멤버 findings가 상한에서 잘림. 미신뢰로 취급 |
| medium | `pickle_framed_artifact` | 피클 스트림. 로딩 시 코드 실행 가능 |
| medium | `unsafe_serialization_format` | 역직렬화가 필요한 형식. 제한적 로더+샌드박스 필요 |
| medium | `invalid_safetensors_header` | SafeTensors 헤더 없음 |
| medium | `safetensors_invalid_tensor_range` | 텐서에 쓸 만한 `data_offsets`가 없음 |
| medium | `safetensors_offsets_out_of_range` | 텐서 데이터가 파일 끝을 넘음 |
| medium | `safetensors_overlapping_tensors` | 텐서들이 같은 바이트를 공유 |
| medium | `invalid_onnx_header` | ONNX ModelProto가 `ir_version`로 시작하지 않음 |
| medium | `invalid_gguf_header` | GGUF 매직/버전 헤더 오류 |
| medium | `invalid_tflite_header` | TFLite file identifier 오류 |
| medium | `format_extension_mismatch` | ZIP 내용이 확장자와 불일치 (`.pth`가 ZIP인 경우 등) |
| low | `safetensors_trailing_data` | 마지막 텐서 이후에 아무 텐서도 주장하지 않는 바이트 |
| low | `unknown_format` | 확장자가 초기 형식 허용 목록에 없음 |

SafeTensors는 헤더만 읽고 `data_offsets`를 검증합니다(본문 텐서는 읽지 않음).
ONNX은 protobuf를 의존하지 않고 프리앰블(`ir_version` 필드)만 확인합니다.

## 3. 가드 서버 (상시 감시)

```bash
./dist/linux/ai-model-guard \
  --port 8765 \
  --watch-path ~/ComfyUI/models \
  --watch-interval 5 \
  --quarantine-dir ~/.local/share/ai-antivirus/quarantine \
  --threat-feed threats.jsonl \
  --audit-log ~/.local/state/ai-antivirus/audit.jsonl
```

| 플래그 | 기본값 | 의미 |
| --- | --- | --- |
| `--port` | 8765 | 루프백 전용 바인딩 |
| `--audit-log` | `~/.local/state/ai-antivirus/audit.jsonl` | 감사 로그 경로 |
| `--audit-max-megabytes` | 32 | 이 크기에 도달하면 세그먼트로 회전 (0 = 회전 없음) |
| `--audit-keep-segments` | 0 | 회전 세그먼트 본문 보관 개수 (0 = 전부) |
| `--watch-path` | 없음 | 상시 감시 디렉터리 (반복 지정 가능) |
| `--watch-interval` | 5.0 | 폴링 주기(초) |
| `--quarantine-dir` | 없음 | `blocked` 아티팩트를 이동시킬 위치 |
| `--watch-runtime` | off | Linux 런타임 모니터링 (7절) |
| `--runtime-interval` | 5.0 | 런타임 폴링 주기(초) |
| `--watch-process` | 없음 | 감시할 프로세스 이름 추가 |
| `--threat-feed` | 없음 | 차단 SHA-256 목록 |
| `--allowed-host` / `--allowed-path` | 없음 | 정책 허용 목록 |
| `--flag-unknown-hosts` | off | 허용 목록 밖 목적지에 review 기록 (차단 아님) |
| `--auth-token` | 없음 | `/v1` 경로에 `Authorization: Bearer` 요구. 환경변수 `AI_ANTIVA_AUTH_TOKEN`도 인식. 16자 이상 |

서버는 **루프백만** 받습니다. `Host` 헤더가 루프백이 아니면 400 `invalid_host`,
`Origin`이 루프백이 아니면 403 `forbidden_origin`로 거부하고 감사에 남깁니다.
SIGTERM(systemd stop 등)은 질서 있는 종료로 처리해서 감사 앵커를 기록하고 나갑니다.

### 워처 동작

- 새로 보이거나 바뀐 파일은 **한 폴링 주기 동안 변화가 없어야** 스캔합니다.
  계속 변하는 파일은 최대 12회 유예한 뒤 스캔하고 `artifact_unstable`을 남깁니다.
- 읽기 실패는 시그니처당 한 번만 `scan_failed`로 기록합니다(반복 로그 방지).
- 격리는 `blocked`에만 적용됩니다. 이동 대상 디렉터리는 **감시 경로 밖**이고
  **같은 파일시스템**이어야 합니다. 격리 디렉터리는 `0700`, 격리 파일은 `0600`으로
  맞추고, 이름은 `<파일명>.<sha256 앞 12자>.<uuid>.quarantined`입니다.
  하드링크가 남아 있으면 `quarantine_hardlink_remaining` findings로 알립니다.

## 4. HTTP API

| 메서드 | 경로 | 내용 |
| --- | --- | --- |
| GET | `/health` | 서버 살아있음 확인 |
| GET | `/v1/status` | 카운터·감사 무결성·컴포넌트 상태 |
| POST | `/v1/events` | AI 호스트 이벤트 1건 평가+기록 (본문 최대 1 MiB) |

```bash
curl -s localhost:8765/health
curl -s localhost:8765/v1/status

curl -s -X POST localhost:8765/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"network_egress","host":"example.com","port":443,"bytes":52428800}'
```

POST는 `Content-Type: application/json`이 필수입니다. 토큰을 설정했다면
`-H "Authorization: Bearer <token>"`를 `/v1` 요청에 붙이세요.

### 이벤트 타입

`event_type`이 필수이고, 아래 다섯 값 외에는 `unsupported event_type`로 거부합니다.

| event_type | 필수/선택 필드 |
| --- | --- |
| `file_read` | `path` 필수, `file_count` |
| `network_egress` | `host` 필수, `port`, `bytes` |
| `tool_call` | `tool` 필수 |
| `process_start` | `process_name` 필수, `pid` |
| `model_output` | (본문 없음) |

`process_start`를 제외한 타입에는 `pid`, `process_name`(귀속용)과 `data`
(최대 256 KiB 텍스트)를 넣을 수 있습니다. `data`는 감사에 원문이 아니라
`data_sha256`과 길이만 남습니다.

리스크 점수는 80 이상 `blocked`, 40 이상 `review`입니다. 감지 항목:
민감 경로 접근, 허용 목록 밖 경로/호스트, 대량 파일 접근·대량 유출(>10 MiB),
고영향 도구 호출(shell/exec/subprocess/upload/send_email), 비밀정보 패턴
(개인키·AWS 키·Bearer 토큰·api_key/password·이메일), 프롬프트 인젝션 패턴.

### `/v1/status` 필드

`events_seen`, `events_blocked`, `rejections`, `last_decision`,
`models_scanned`, `models_quarantined`, `last_model_scan`,
`audit_integrity`, `audit_degraded`, `audit_entries`, `audit_segments`,
`audit_expired_segments`, `audit_retention_blocked`,
그리고 `enforcement_mode`, `enforcement_health`, `file_watcher`,
`runtime_monitor`, `threat_feed`, `auth`(컴포넌트별 상태 문자열).

## 5. 감사 로그: 검증·회전·리텐션

감사 로그는 JSONL 한 줄에 하나씩이며 각 항목은
`{seq, timestamp, event, decision, previous_hash, entry_hash}` 구조로
이전 항목 해시를 이어붙인 체인입니다. 체인만 있으면 **꼬리를 잘라내는 공격은
탐지하지 못하기 때문에**, 체인 끝 정보를 `<로그>.anchor` 사이드카에 따로 기록합니다.
앵커는 20건마다, 그리고 종료 시점에 한 번 씁니다(degraded 상태에서는 앵커 동결).

### 회전

`--audit-max-megabytes`(기본 32)에 도달하면 활성 로그를
`audit.000000000001-000000000007.jsonl` 같은 이름의 세그먼트로 개명하고
새 활성 로그를 시작합니다. 세그먼트마다 자기 `<segment>.jsonl.anchor`가 있고,
`seq`와 해시 체인은 새 파일로 그대로 이어집니다.

### 리텐션

`--audit-keep-segments N`은 가장 오래된 세그먼트 **본문**만 삭제하고
**앵커는 항상 보존**합니다. 앵커가 없으면 삭제를 거부하고
`audit_retention_blocked: true`로 표시합니다. 삭제 사실은
`audit_segment_expired` 항목으로 로그에 남습니다.
세그먼트 본문과 앵커를 통째로 지우면 `seq` 갭으로 탐지됩니다.

### `audit_degraded: true`를 봤을 때

그 로그의 역사는 **신뢰 불가**로 취급하세요. 권장 조치:

1. 로그를 지우거나 고치지 말고 그대로 보관(포렌식 증거).
2. 활성 로그 파일과 `.anchor` 사이드카, 세그먼트 파일 권한/소유자를 확인.
3. 새 감사 경로로 시작해서 이후 기록만 신뢰하고, 이전 구간은 미확인 처리.

검증 한계: 이미 닫힌 세그먼트는 **경계(seq·앵커)만** 검사하고 본문 전체를 다시
검증하지 않습니다.
앵커는 같은 디렉터리에 있는 평문 파일이므로, 로그를 쓰는 사용자와 같은 권한으로
쓰는 공격자를 막지 못합니다. 외부 시계·서명·WORM 보관은 미구현입니다.

## 6. 위협 피드 형식

JSONL, JSON 배열, `{"indicators": [...]}` 세 가지를 모두 받습니다.

```json
{"sha256": "3f2b…", "reason": "revoked checkpoint", "source": "internal"}
```

`sha256`은 소문자 64자 hex. 형식이 잘못된 줄은 건너뛰고 개수를 셉니다.

## 7. 런타임 모니터링 (Linux 한정)

```bash
./dist/linux/ai-model-guard --watch-runtime --runtime-interval 5 \
  --watch-process vllm --watch-process my-inference
```

`/proc`에서 기본 프로세스(`ollama`, `llama-server`, `llama.cpp`, `lmstudio`,
`text-generation-launcher`, `vllm`)와 `--watch-process`로 추가한 프로세스의
**수립된 IPv4 TCP 연결**만 관찰합니다. IPv6·UDP·DNS·한 폴링 주기 안에 끝난
연결은 보이지 않습니다. 이 기능도 관측만 하고 차단하지 않습니다.

## 8. 실전 데이터에서 자주 보이는 결과

- `.bin` / 원시 텐서 파일 다수가 `unsafe_serialization_format`로 `review`에 남습니다.
  직렬화 형식과 원시 텐서 덩어리를 안전하게 구분할 수 없어서 의도적으로 남깁니다.
- torch `.pth`는 ZIP이면 `format_extension_mismatch` + `archive_unsafe_member`,
  피클이면 `pickle_framed_artifact`로 잡힙니다.
- 대용량 파일은 SHA-256 계산에 시간이 걸립니다. 크기 상한 옵션은 아직 없습니다.

## 9. 개발·테스트

```bash
PYTHONPATH=src python3 -m pytest -q
```

문서를 고칠 때 실제 코드와 플래그 표기가 일치하는지 함께 확인하세요.
