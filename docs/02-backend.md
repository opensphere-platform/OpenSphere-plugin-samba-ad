# 02 · 백엔드 (`server.js`)

한 파일, **의존성 0**(node:22 내장 `http`/`fs`/`path`/`net`만). 기능 컨테이너가 **자기 UI를 서빙**하고, **읽기 집계 + 통합 표면**을 제공한다. 쓰기(도메인 자원·velero)는 하지 않는다 — 그건 host 검증 write-path 소관(§03·§04).

## 2.1 서비스 어카운트 = 읽기 전용 최소권한

`rbac.yaml`이 정의하는 전용 SA `opensphere-plugin-samba-ad`:

| 스코프 | 리소스 | verbs | 왜 |
|---|---|---|---|
| ClusterRole | `foundation.opensphere.io/foundationmodels` | `get` | 선언 정본(identity 모델) 조회 |
| ClusterRole | `storage.k8s.io/storageclasses` | `list` | 설정 폼의 StorageClass 드롭다운 |
| Role(`opensphere-foundation`) | `apps/deployments` | `get` | samba/keycloak 실물 조회 |
| Role(`opensphere-foundation`) | `pods`, `events` | `list` | 파드·이벤트 |

> **쓰기 verb가 하나도 없다.** 이게 최소권한의 핵심. SA는 apiserver를 `Bearer $(cat /var/run/secrets/…/token)`로 직접 호출(`k8sGet`)하되 **읽기만**. 도메인 자원 write는 §03의 검증 write-path로 위임한다.

## 2.2 엔드포인트 지도

| Method · Path | 용도 | 인증/권한 |
|---|---|---|
| `GET /healthz` | 헬스 | — |
| `GET /api/samba` | **집계 페이로드**(meta·model·config·backup·storageClasses·workload·keycloak·events) | plugin SA(읽기) |
| `GET /operand/manifests` | **operand 배포 선언**(`{engine, config, items[]}`) — control-plane이 fetch해 SSA | plugin SA(읽기) |
| `GET /metrics` | Prometheus exposition(실 신호) | kps 스크레이프 |
| `GET /api/metrics/range?q=&minutes=` | UI 차트용 kps range API 프록시 | plugin SA |
| `GET /api/logs?minutes=` | Loki LogQL tail(samba pod stdout) | plugin SA |
| `GET /cli/manifest` | `os ad` 명령 매니페스트(OAHAgentToolManifest 호환) | — (registry 광고) |
| `GET /cli/status` `·/describe` `·/events` | `os ad status/describe/events` 데이터 | plugin SA |
| `GET /plugins` `·/plugins/{file}` | **서명된 UI 자산 서빙**(경로 탈출 방지) | — |

바깥으로 나가는 호출(outbound):
| 대상 | 용도 |
|---|---|
| `POST {controller}/api/admin/events` (`x-shell-token`) | **메시지 통합** — 자기 이벤트를 콘솔 audit bus에 발행(§04) |
| `GET {kps}/api/v1/query_range` | 차트 데이터 |
| `GET {loki}/loki/api/v1/query_range` | 로그 |

## 2.3 집계 = "선언 정본 + 실물"을 정직하게 합친다

`sambaPayload()`는 6개를 병렬 조회해 하나로 합친다:

```
FoundationModel/identity  ─┐  (선언 정본: phase·observed·ldapURL·engines 옵션·parameters.samba)
Deployment samba          ─┤
Deployment keycloak       ─┼─▶  { meta, model, config, backup, storageClasses, workload, keycloak, events }
pods (app=samba)          ─┤
events (samba)            ─┤
StorageClass 목록         ─┘
```

- **원칙: "코드/설치 여부"와 "지금 클러스터 실재"를 분리해 정직하게 표시.** 예: `workload.found=false`이면 "미배포"로, `engineOpt=disabled`면 "engines 옵션으로 비활성"으로 구분해 안내한다(추측/위조 0).
- `config`/`backup`은 `FM.spec.parameters.samba`(+`.backup`)에서 읽어 UI 폼이 현재값을 표시하게 한다.

## 2.4 self-contained operand — plugin이 배포 선언을 소유

```js
GET /operand/manifests
  → { engine:'samba', config:<readSambaConfig()>, items:[ PVC, Service, Deployment, NetworkPolicy ] }
```

- `buildOperand(cfg)`가 Samba DC operand(6포트 SVC + privileged Deployment + NetworkPolicy + 3Gi PVC)를 **JSON 오브젝트 배열**로 생성. `cfg`는 `FM.spec.parameters.samba`(도메인/replicas/StorageClass/DNS forwarder)에서 렌더.
- **control-plane(foundation)이 이 선언을 fetch → 라벨 스탬프(owner·engine) → SSA apply**("내민 선언을 apply만"). plugin은 선언을 **소유**하고, host는 **적용**만 한다.
- **PVC는 회수 대상에서 제외**(SAM DB 보존) — Disable/재조정 시에도 데이터가 남는다.
- ⚠️ dev 예외: operand는 `privileged: true` + dev 기본 도메인 비밀번호(`SAMBA_DEFAULTS.domainPass`). 프로덕션은 Secret 주입·비-privileged로 대체할 것.

## 2.5 관측 표면 — /metrics는 위조 0

`metricsText()`는 **실측만** exposition으로 낸다:

| 메트릭 | 출처(실측) |
|---|---|
| `samba_ad_up` | Deployment `readyReplicas≥1` |
| `samba_ad_ldap_reachable` | **`net.Socket`으로 :389 TCP dial**(실제 도달성) |
| `samba_ad_replicas_ready` / `_desired` | Deployment status/spec |
| `samba_ad_restarts_total` | 컨테이너 restartCount 합 |
| `samba_ad_model_installed` | `FM.status.phase == 'Installed'` |
| `samba_ad_keycloak_federation_up` | keycloak(소비자) ready |

전부 `{plugin="samba-ad"}` 라벨. `servicemonitor.yaml`이 kps에 스크레이프 등록(§04).

## 2.6 메시지 발행 — best-effort, 전이만, 위장 불가

- `publishNotify(ev)`: `SHELL_SERVICE_TOKEN`(controller가 podEnv로 주입)으로 `POST /api/admin/events` (`x-shell-token`). **토큰 없으면 조용히 생략**, 실패해도 경고 1회 후 억제 — **본기능과 무관**.
- `healthTransitionPublish()`: DC ready / LDAP 도달성이 **바뀔 때만** 발행(첫 관측=기준선 → 재기동 스팸 방지). 60초 주기.
- source는 controller가 `ext:`로 강제 태깅 → **actor 위장 불가**.

## 2.7 왜 의존성 0인가

`Dockerfile`은 `node:22-alpine` + `server.js` + `ui-shell/` 복사뿐(`npm install` 없음). `fetch`/`http`/`net`/`fs`는 전부 node 내장. → **공급망 표면 최소, 빌드 재현성 최대, 이미지 최소.** 샘플로서 권장 기본값.

→ 다음: [03-ui-plugin.md](03-ui-plugin.md)
