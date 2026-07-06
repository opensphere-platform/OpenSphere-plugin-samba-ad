# 05 · 패키징 · 서명 · 배포

## 5.1 신뢰 루트 = `uipluginpackage.yaml`

```yaml
kind: UIPluginPackage            # 신뢰 루트/카탈로그 (status 없음)
metadata: { name: samba-ad, namespace: opensphere-system, labels: { opensphere.io/host-ref: foundation } }
spec:
  serviceAccountName: opensphere-plugin-samba-ad     # 전용 SA(읽기 최소권한)
  image:
    repository: ghcr.io/opensphere-platform/plugin-samba-ad
    digest: sha256:…                                 # ★ 태그 금지 — sha256 강제(S1: CRD가 ^sha256: 패턴 검증)
  manifest:
    path: /plugins/ui-shell.manifest.json
    sha256: "…"                                       # ★ 매니페스트 해시(핀)
    signaturePath: /plugins/ui-shell.manifest.json.sig
  trust: { keyId: opensphere-plugins-v2 }             # 서명 검증 공개키 ID
  permissions: [ page:register, api:proxy, manual:contribute ]
  api: { basePath: /api/plugins/samba-ad }
  cli: { namespace: ad, manifestPath: /cli/manifest } # os ad … 기여
---
kind: UIPluginRegistration       # 원하는 상태(desiredState) + status
spec:
  packageRef: { name: samba-ad }
  desiredState: Enabled          # Enabled | Disabled | Uninstalled
  installPolicy: { createWorkload: true, createProxyRoute: true, exposeInNavigation: false }  # false = host 안층 표시
```

- **UIPluginPackage**(신뢰 루트, 관리자 승인값) ↔ **UIPluginRegistration**(원하는 상태·status)의 2단 분리. `dupa-registry-controller`(opensphere-system)가 조정.
- `exposeInNavigation: false` = mainShell 1단 비노출(선언적 의도) — sub-hosted 표기.

## 5.2 3중 무결성 핀 (무엇이 무엇을 보증하나)

| 핀 | 대상 | 바뀌면 |
|---|---|---|
| `image.digest` (sha256) | 컨테이너 전체(server.js + UI 번들) | **모든** 코드 변경 |
| `manifest.sha256` | `ui-shell.manifest.json`(entrySha256 포함) | **UI(entry) 변경** 시 |
| `manifest.json.sig` (P-256, v2 키) | 매니페스트 출처·무결성 | UI 변경 시 재서명 |

## 5.3 서명 (v2 키)

```bash
node <repo>/OpenSphere-plugin-status/ui-shell/sign-and-pin.mjs \
     ui-shell \
     <…>/.plugin-signing/key.pem            # opensphere-plugins-v2 개인키
# 출력: entrySha256(→ manifest에 주입됨) / manifestSha256(→ CR spec.manifest.sha256) / spki
```

- 도구가 ① `ui-shell.plugin.js` 해시 → `manifest.entrySha256` 주입, ② 매니페스트 P-256 서명 → `.sig`, ③ `manifestSha256` 출력.
- **개인키는 레포 밖**(`.plugin-signing/key.pem`). 절대 커밋 금지. 트러스트키 변경은 에이전트 차단 대상.

## 5.4 배포 사이클 — 변경 종류에 따라 다르다

| 변경 | 재빌드 | 재서명 | 패치할 필드 |
|---|---|---|---|
| **UI**(`ui-shell.plugin.js`) | ✅ | ✅ | `image.digest` **+** `manifest.sha256` |
| **백엔드만**(`server.js`) | ✅ | ❌ | `image.digest` **만** |

> samba-ad의 entry는 실제 UI 코드라 UI 변경 = 재서명. (foundation subShell처럼 entry가 얇은 부트스트랩이면 UI 변경도 digest만 — 하지만 여기선 아님.)

### 표준 절차 (UI 변경 기준)
```bash
# 1) 재서명
node .../sign-and-pin.mjs ui-shell <key.pem>          # → 새 manifestSha256

# 2) 이미지 빌드·푸시(digest 확보)
docker build -t ghcr.io/opensphere-platform/plugin-samba-ad:vN .
docker push  ghcr.io/opensphere-platform/plugin-samba-ad:vN   # → "vN: digest: sha256:…"

# 3) uipluginpackage.yaml에 새 digest/manifest.sha256 기입 후 → 전체 선언형 apply(권장)
#    ⚠️ kubectl patch로 digest/manifest만 갱신하면 파일의 다른 필드(spec.permissions 등)가 live에 반영 안 됨(drift).
#       spec 필드를 바꿨으면 반드시 apply. (kubectl set image로 Deployment 직접수정은 금지 — controller가 되돌림.)
kubectl apply -f uipluginpackage.yaml     # digest·manifest·permissions 등 전체 상태 정합

# 4) 완료 판정은 live spec 재확인으로 닫는다(소스 diff만으로 닫지 않음)
kubectl get uipluginpackage samba-ad -n opensphere-system -o jsonpath='{.spec.permissions}{"\n"}'
```

## 5.5 롤아웃 검증

```bash
# registration이 Enabled + 새 파드 imageID가 푸시 digest와 일치할 때까지 폴링
kubectl get uipluginregistration samba-ad -n opensphere-system -o jsonpath='{.status.phase}'
kubectl get pods -n opensphere-system -l app=samba-ad \
  -o jsonpath='{range .items[*]}{.status.containerStatuses[0].imageID}{"\n"}{end}'
```

- **정상 레이스**: 패치 직후 `Failed reason=DigestMismatch`가 잠깐 뜰 수 있다 — 구 파드가 재검증 순간 구 매니페스트를 서빙하는 롤아웃 레이스. 새 파드가 뜨면 다음 재조정(≈15s)에 **자가치유(Enabled)**. 15초 더 기다린 뒤 판단.
- 브라우저 검증은 §03.6(shadow DOM deepFind) + §03.5(15분 토큰 만료 시 새로고침) 참고.

## 5.6 함정 모음 (실측)

| 함정 | 증상 | 해결 |
|---|---|---|
| 태그로 배포 | CRD가 거부 | `image.digest`는 `sha256:` 필수(S1) |
| UI 바꾸고 manifest 패치 누락 | `DigestMismatch` 지속 | UI 변경은 digest **+** manifest.sha256 둘 다 |
| `kubectl set image` 직접수정 | 5~12초 내 되돌려짐 | CR `spec.image.digest`부터 patch |
| 새 GHCR 이미지 private | control-plane `ImagePullBackOff`(operand fetch 소비자 측) | 소비 Deployment에 `imagePullSecrets: [ghcr-pull]` |
| inline `onclick` | CSP가 조용히 차단 | `addEventListener`(§03.3) |
| 15분 토큰 만료 | 쓰기 시 `401 token expired` | tokenExpired 선차단 + 새로고침 안내(§03.5) |
| velero 쓰기 403 | `schedules.velero.io is forbidden` | `foundation-velero-backup` Role(velero ns)을 admin 그룹에(§04 축7) |

## 5.7 레퍼런스 표

### 이미지 / 배포 아티팩트
| | |
|---|---|
| 이미지 | `ghcr.io/opensphere-platform/plugin-samba-ad@sha256:8b6a5ff5…` (bk2) |
| 매니페스트 | `manifest.sha256 = 0e64ca25…`, `entrySha256 = 134351c2…`, keyId `opensphere-plugins-v2` |
| kubectl apply | `rbac.yaml` · `servicemonitor.yaml` · `uipluginpackage.yaml` |
| operand | control-plane이 `GET /operand/manifests`로 fetch(별도 apply 아님) |

### 이 plugin이 다루는 k8s 리소스(요약)
| 리소스 | ns | 관계 |
|---|---|---|
| Deployment/Service `samba-ad` | opensphere-system | plugin 컨테이너(UI+백엔드) — DUPA controller가 생성 |
| Deployment/PVC/SVC/NetPol `foundation-identity-samba` | opensphere-foundation | operand — plugin 선언 + control-plane apply |
| FoundationModel `identity` | (foundation) | 선언 정본(설정·백업설정·engines 게이트) |
| ServiceMonitor `samba-ad` | opensphere-system | kps 스크레이프 등록 |
| `velero.io/Schedule·Backup·BSL` `samba-ad` | velero | 백업 등록(사용자 임퍼소네이션 write) |

### 환경변수
| var | 기본 | 용도 |
|---|---|---|
| `PORT` | 8080 | 리슨 |
| `PLUGIN_DIR` | /plugins | 서명 자산 위치 |
| `FOUNDATION_NS` | opensphere-foundation | operand/실물 ns |
| `PROMETHEUS_URL` | kps-prometheus.monitoring.svc:9090 | 차트 프록시 |
| `LOKI_URL` | loki.monitoring.svc:3100 | 로그 |
| `OSP_CONTROLLER` | dupa-registry-controller…:8080 | 이벤트 발행 |
| `SHELL_SERVICE_TOKEN` | (controller 주입) | audit bus 인증 |

---

## 다른 plugin을 이 샘플로 시작하려면

1. **레포 복제 구조**: `server.js`(의존성0) + `ui-shell/`(서명) + `uipluginpackage.yaml` + `rbac.yaml` + `Dockerfile`.
2. **표시 패턴 선택**: 최상위 메뉴면 `registerPage` 호출 + `hostRef` 제거(standalone). 도메인 종속이면 samba-ad처럼 `hostRef` + 미호출(sub-hosted).
3. **최소권한 SA**: 읽기만. 쓰기는 host 검증 write-path(임퍼소네이션) 재사용.
4. **통합축은 필요한 것만**: 관측(/metrics+SM), 로그(/api/logs), 메시지(publishNotify), CLI(spec.cli+/cli/manifest), 매뉴얼(manual.contribute), 백업(velero write-path) — §04의 배선을 그대로.
5. **디자인·CSP·세션 규율**(§03.3·3.5)은 무조건 지킬 것.
6. 배포는 §5.4 절차, 검증은 §5.5.
