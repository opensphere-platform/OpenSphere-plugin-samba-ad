# 04 · 통합축 — 어떻게 "중앙 스택에 연결"되는가

> 이 문서가 샘플의 핵심이다. plugin은 **자기 사일로를 만들지 않고**, 각 관심사를 **콘솔/플랫폼의 단일 스택에 등록**한다. 축마다 "무엇을·어떻게(엔드포인트·CR·RBAC·흐름)"를 기술한다.

## 요약

| 축 | 연결 대상 | 방향 | 실체 | 쓰기 주체 |
|---|---|---|---|---|
| 1 operand 배포 | control-plane(foundation) | pull | `GET /operand/manifests` → SSA | control-plane SA |
| 2 관측 | kube-prometheus-stack | pull | `/metrics` + `ServiceMonitor` | (스크레이프) |
| 3 로그 | Loki | push→query | promtail 수집, `/api/logs` LogQL | (수집기) |
| 4 메시지 | 콘솔 audit bus | push | `POST /api/admin/events` (`x-shell-token`) | plugin(서비스 토큰) |
| 5 CLI | `os` 바이너리 | pull | `spec.cli` 광고 → `/cli/manifest` | — |
| 6 매뉴얼 | Manual Registry | push | `ctx.extensions.manual.contribute()` | plugin(로드 시) |
| 7 백업 | Velero | write | `velero.io/Schedule·Backup·BSL` | **사용자 임퍼소네이션**(host 프록시) |
| 8 설정 | FoundationModel | write | FM `parameters.samba` merge-patch | **사용자 임퍼소네이션**(host 프록시) |

**쓰기 3원칙**: (읽기·스크레이프·수집)은 plugin SA/스택이, **도메인/velero 쓰기는 사용자 임퍼소네이션**(host 검증 write-path)이, **감사 이벤트만 plugin 서비스 토큰**이 한다. plugin SA는 어디에도 write 권한이 없다.

---

## 축 1 · operand 배포 (self-contained + 선언형 회수)

**무엇**: Samba AD DC 실물(Deployment/PVC/SVC/NetworkPolicy)을 plugin이 **선언 소유**하고, control-plane이 적용한다.

**흐름**
```
FoundationModel/identity (engines.samba=enabled) 변경
   → foundation-control-plane 재조정
   → GET http://<samba-ad svc>/operand/manifests   (plugin이 선언 제공)
   → 라벨 스탬프(owner=identity, foundation.opensphere.io/engine=samba)
   → SSA apply (opensphere-foundation ns)
```
- **게이트** = `engines.samba` 옵션. `enabled`면 fetch+apply, `disabled`면 **회수**: `foundation.opensphere.io/engine=samba` 라벨 셀렉터로 `DeleteAllOf`.
- **PVC 보존**: 회수 대상(bundleKinds)에서 PVC 제외 → Disable해도 SAM DB 유지 → 재-Enable 시 동일 PV 재마운트로 데이터 복원. (왕복 실증됨.)
- **왜 pull인가**: 선언은 plugin이 소유(도메인/replicas/StorageClass가 plugin 스키마), 적용 권한은 control-plane이 소유 → 관심사 분리.

## 축 2 · 관측 (kube-prometheus-stack)

**무엇**: 실 신호를 `/metrics`로 노출하고 kps가 긁는다. UI는 시계열을 스파크라인으로 그린다.

- **노출**: `GET /metrics` (§02.5, 위조 0 — TCP dial·readyReplicas 등 실측).
- **등록**: `servicemonitor.yaml` — `selector.matchLabels: {opensphere.io/dupa-plugin: samba-ad}`(DUPA controller가 만든 plugin Service 라벨), `targetPort 8080 path /metrics interval 30s`. kps(monitoring)는 빈 셀렉터라 전 ns SM을 스크레이프.
- **차트**: UI `_loadCharts()` → `GET /api/metrics/range?q=&minutes=30` → server가 `kps-prometheus.monitoring.svc:9090` range API 프록시 → 순수 SVG 스파크라인(라이브러리 무의존).

```
samba-ad /metrics ◀── kps(ServiceMonitor) ── 시계열 축적
UI ──▶ /api/metrics/range ──▶ kps range API ──▶ 스파크라인 4종
```

## 축 3 · 로그 (Loki)

**무엇**: samba pod stdout을 중앙 Loki에서 tail해 UI 콘솔 박스에 표시.

- **수집**: promtail(DaemonSet, monitoring ns)이 전 pod stdout을 Loki에 push. (Loki 스택은 `tools/local-dev/loki-stack.yaml`로 설치 — plugin 외부의 공유 관측 계층.)
- **쿼리**: server `GET /api/logs?minutes=` → `loki.monitoring.svc:3100` LogQL `{namespace="opensphere-foundation",app="foundation-identity-samba"}` query_range tail.
- **표시**: UI `_loadLogs()` → 셸 `vl-log` 콘솔 박스(velero 페이지와 동일 컴포넌트룩) 재사용. 타임스탬프+라인.

## 축 4 · 메시지 (콘솔 audit bus / 단일 인박스)

**무엇**: plugin이 자기 이벤트를 콘솔 단일 감사 버스에 발행 → 콘솔 알림/인박스에 통합.

- **배선**: controller가 `SHELL_SERVICE_TOKEN`(`dupa-events-token` secret)을 plugin 워크로드 env로 주입(S2). server가 `POST {controller}/api/admin/events`에 `x-shell-token`으로 발행.
- **정책**: 전이 시에만(dedup) — `started`(기동) + DC ready/LDAP 도달성 전이. 첫 관측=기준선(스팸 방지). 실패해도 best-effort.
- **위장 방지**: source는 controller가 `ext:samba-ad`로 강제 태깅.

## 축 5 · CLI (`os ad …`) — cli:contribute

**무엇**: plugin이 `os` 바이너리에 **도메인 명령 네임스페이스**를 기여한다(콘솔 재빌드 불요, headless binding).

- **광고**: `uipluginpackage.yaml`
  ```yaml
  cli: { namespace: ad, manifestPath: /cli/manifest }
  ```
  registry(`/api/v1/registry`)가 이 바인딩을 광고.
- **디스패치**: `os ad status` → `os`가 registry에서 ns `ad`를 찾아 `<console>/api/plugins/samba-ad/cli/manifest` 조회 → **`os ai`와 동일한 매니페스트 엔진**(matchTool/buildRequest)으로 실행.
- **매니페스트**: `GET /cli/manifest` = `OpenSphereCLICommandManifest`(kind/cli.commandPrefix/tools[]). 현재 명령은 전부 **읽기(risk=low)** — `ad.status`/`ad.describe`/`ad.events`.
- **경계**: 디렉터리 내용(사용자·그룹) 변경은 콘솔/CLI가 하지 않는다(ADR-FND-001) — `samba-tool`/RSAT 소관.

```
os ad status ─▶ registry(ns 'ad' 발견) ─▶ GET /cli/manifest ─▶ os ai 엔진 재사용 ─▶ GET /cli/status
```

## 축 6 · 매뉴얼 (Manual Registry)

**무엇**: 로드(적재)와 동시에 자기 운영 매뉴얼을 셸 단일 Manual Registry에 기여.

- `activate()` 안에서 `ctx.extensions.manual?.contribute?.({ sourceId:'plugin:samba-ad', documents: MANUAL_DOCS, authorityTier:3, language:'ko' })`.
- `MANUAL_DOCS`는 제어 위치·연결 좌표·day-0 구성·**백업**·경계를 담은 마크다운. 콘솔 매뉴얼 검색(`/api/manual/search`)의 canonical 히트로 확인됨.

## 축 7 · 백업 (Velero) — 공용 기본 + 전용 override

**무엇**: samba PVC(SAM DB) 백업을 **중앙 Velero에 등록**한다. 대상은 **외부 S3(사용자 구성)**.

- **공용 기본**: `BSS → Velero` 페이지에서 외부 S3(default BSL)를 구성(Velero Release CR 선언형 PATCH → provider-helm이 creds Secret + BSL + node-agent DaemonSet 적용). 여러 plugin 공유.
- **전용 override**: samba-ad "백업" 섹션에서 samba 전용 외부 S3(별도 `samba-ad` BSL + secret) 구성 가능.
- **등록 실체**: `velero.io/Schedule` `samba-ad`(ns velero) — `includedNamespaces:[opensphere-foundation]`, `labelSelector: app=foundation-identity-samba`(→ Velero가 바인딩된 PVC 자동 포함), `defaultVolumesToFsBackup: true`(node-agent 파일시스템 백업), `storageLocation: default|samba-ad`, `ttl: 720h`. "지금 백업"=일회성 `Backup` CR.
- **쓰기 경로**: UI가 **foundation 프록시 + `x-os-id-token`(사용자 임퍼소네이션)**으로 velero CR create-or-merge(POST→409면 merge-patch). **plugin SA엔 velero 권한 0.**
- **상태 읽기**: UI가 foundation 프록시(토큰 없이 → host SA)로 Schedule/Backup/BSL 조회.
- **RBAC**(foundation 레포 `rbac-velero.yaml`):
  - `foundation-velero-manage`(SA+admin): velero.io/daemonsets **읽기**(상태 조회).
  - `foundation-velero-backup`(Role, **velero ns 한정**) → `opensphere-console-admins`: schedules/backups/BSL + secrets **쓰기**(secrets 클러스터전역 부여 회피 — 최소권한).

```
UI "백업 활성화·저장" ─▶ foundation 프록시(x-os-id-token) ─▶ 임퍼소네이션 ─▶ velero.io/Schedule 생성
   (실제 백업 실행은 default BSL이 Available일 때 = 사용자가 외부 S3 자격증명 입력 시)
```

## 축 8 · 설정 (FoundationModel write-path)

**무엇**: 도메인/replicas/StorageClass/DNS forwarder + 백업 설정을 UI 폼에서 편집 → 선언 정본에 기록.

- UI 폼 → `PATCH FM/identity` `spec.parameters.samba`(+`.backup`) merge-patch, **foundation 검증 write-path**(`x-os-id-token`, §03.4).
- 저장 후 control-plane 재조정 → operand 재렌더(도메인/replicas 변경 시 pod 재기동, PVC 보존).
- StorageClass는 **클러스터 실 목록 드롭다운**(plugin SA `storageclasses list`)에서 선택.

---

## 종합 시퀀스 (한 화면에 다 모임)

```
                     ┌─────────────────────────── <osp-samba-ad> (UI) ───────────────────────────┐
읽기(host SA):        │  /api/samba(집계)   /api/metrics/range(kps)   /api/logs(Loki)             │
                     │  velero Schedule/Backup 상태(foundation 프록시, 토큰 없이)                 │
쓰기(임퍼소네이션):   │  FM parameters.samba(설정·백업설정)   velero Schedule/Backup/BSL/secret    │
                     └──────────────────────────────────────────────────────────────────────────┘
plugin SA(읽기):      FoundationModel get · Deployment get · pods/events list · storageclasses list
plugin 서비스토큰:    audit bus 이벤트 발행(전이만)
control-plane:        GET /operand/manifests → SSA(operand)     kps: /metrics 스크레이프
os 바이너리:          registry(ns ad) → /cli/manifest → os ad …
```

→ 다음: [05-packaging-signing-deploy.md](05-packaging-signing-deploy.md)
