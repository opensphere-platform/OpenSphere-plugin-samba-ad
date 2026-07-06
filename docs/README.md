# OpenSphere-plugin-samba-ad — 레퍼런스 문서

> 이 문서 세트는 `OpenSphere-plugin-samba-ad`가 **독립 plugin으로 무엇을 처리하고, 어떻게 콘솔·Foundation·클러스터에 연결되며, 어떻게 구현·서명·배포되는지**를 상세히 기술한다. 목적은 이 plugin을 **다른 plugin 개발의 표준 샘플**로 삼는 것이다.

작성: 2026-07-06 · 대상 버전 **bk2** (image `@sha256:8b6a5ff5…`, manifest `0e64ca25…`)

---

## 0. 성숙도 평가 (정직한 결론)

**결론: "sub-hosted feature plugin" 패턴의 레퍼런스 샘플로 인정할 수 있다 — 아래 두 단서를 명시하는 조건에서.**

이 plugin은 우리 설계 목표(신뢰·서명 경계 = 독립 컨테이너, self-contained, 최소권한, 단일 통합 표면)를 **실제로 배선하고 라이브 클러스터에서 검증**했다. 단순 더미가 아니라 8개 통합축이 전부 실동작한다.

### 왜 샘플감인가 (강점)

| 항목 | 근거 |
|---|---|
| **신뢰·서명 경계** | 폴더=컨테이너=독립 git 레포(`OpenSphere-plugin-*` 규약). v2 키 서명 + **sha256 digest 핀**(태그 금지) + 콘솔 Extension Host 이중검증 |
| **self-contained** | operand 배포 선언·관측(/metrics)·로그·설정 폼·백업·CLI·매뉴얼을 **전부 이 한 레포가 소유** |
| **최소권한** | 전용 SA는 **읽기만**. 도메인 자원·velero 쓰기는 host(Foundation)의 검증 write-path(사용자 임퍼소네이션)로 위임 — **plugin SA엔 write/impersonate 권한 0** |
| **단일 통합 표면** | 관측=kps, 로그=Loki, 메시지=콘솔 audit bus, CLI=`os ad`, 매뉴얼=Manual Registry, 백업=Velero — 전부 **중앙 스택에 등록**(자기 사일로 안 만듦) |
| **디자인 규율** | 셸 전역 Clarity/`os-*` 클래스만, **인라인 스타일 0**, CSP 준수(inline onclick 금지 → addEventListener) |
| **견고성** | 세션(15분 토큰) 만료 graceful 처리, 엔진 회수 시 PVC(데이터) 보존, 알림은 best-effort(실패해도 본기능 무관) |
| **공급망 최소** | 백엔드 의존성 **0**(node 내장만), UI 프레임워크 무의존(네이티브 커스텀 엘리먼트) |

### 단서 (샘플로 쓸 때 반드시 이해할 것)

1. **이건 host-mounted 변종의 샘플이다.** `registerPage`를 **의도적으로 호출하지 않고**(mainShell 1단 비노출) Foundation(host)이 안층에서 마운트한다. mainShell에 직접 나타나는 standalone plugin을 만들 거라면 마운트 계약이 다르다(§01 참조). 두 패턴의 **공통부**(신뢰체인·서명·SA·통합축)는 그대로 재사용 가능하다.
2. **operand(Samba DC)는 dev 예외를 포함한다.** `privileged: true` 컨테이너 + 코드 내 dev 기본 도메인 비밀번호(`SAMBA_DEFAULTS.domainPass`). **패턴은 프로덕션급이지만 samba operand 자체는 학습용 dev 구성**이다 — 프로덕션은 Secret 주입·비-privileged·외부화가 필요하다.

### 아직 아닌 것 (한계)

- 실제 **백업 실행**은 사용자가 외부 S3 자격증명을 입력해야 활성화된다(외부·사용자구성 설계상 정상). 관측·로그·백업 축은 클러스터에 상위 스택(kps·Loki·Velero)이 있어야 "살아있다".
- **CI 서명 파이프라인 없음** — 서명은 수동(`sign-and-pin.mjs`), 이미지 태그는 dev(`bk2`). 릴리스 버저닝·자동 서명은 후속.
- **보안 경계는 mainShell 단일**이다. plugin은 보안 중개자가 아니다("서명된 신뢰 코드 실행" 모델 — 샌드박스가 아님). 이 전제를 이해하고 신뢰 코드만 담아야 한다.

---

## 1. 읽는 순서

| # | 문서 | 무엇을 |
|---|---|---|
| — | [README.md](README.md) | (이 문서) 인덱스 + 성숙도 평가 |
| 01 | [01-architecture.md](01-architecture.md) | DUPA 내 위치, 신뢰·마운트 모델, 수명주기 2계층, 요청 흐름 |
| 02 | [02-backend.md](02-backend.md) | `server.js` — 엔드포인트, 최소권한 SA, self-contained operand, 의존성 0 |
| 03 | [03-ui-plugin.md](03-ui-plugin.md) | `ui-shell.plugin.js` — 커스텀 엘리먼트·마운트 계약, 디자인 규율, 검증 write-path, 세션 처리 |
| 04 | [04-integration-axes.md](04-integration-axes.md) | **핵심** — 8개 통합축이 각각 어떻게 연결되는가(엔드포인트·CR·RBAC·흐름) |
| 05 | [05-packaging-signing-deploy.md](05-packaging-signing-deploy.md) | UIPluginPackage·서명·배포 사이클·롤아웃 검증 + 레퍼런스 표 |

## 2. 한눈 요약 (Quick facts)

| | |
|---|---|
| **역할** | workspace/사원 디렉터리(Samba Active Directory DC) 관리 plugin |
| **레포** | `OpenSphere-plugin-samba-ad` (독립 git — 폴더=컨테이너=신뢰경계) |
| **manifest** | `kind: plugin`, `hostRef: foundation`, `entry: ui-shell.plugin.js` |
| **이미지** | `ghcr.io/opensphere-platform/plugin-samba-ad@sha256:…` (태그 금지, digest 핀) |
| **백엔드** | `server.js` — node:22-alpine, **의존성 0**, 읽기 집계 + operand/CLI/metrics/logs 표면 |
| **UI** | `<osp-samba-ad>` 네이티브 커스텀 엘리먼트(light DOM), Foundation이 안층 마운트 |
| **SA** | `opensphere-plugin-samba-ad` — **읽기 전용** 최소권한(`rbac.yaml`) |
| **수명주기(UI)** | `UIPluginRegistration.desiredState` (콘솔 Admin) |
| **수명주기(operand)** | `FoundationModel/identity.spec.parameters.engines.samba` (Foundation Plugins 관리) |
| **통합축** | operand·관측(kps)·로그(Loki)·메시지(audit bus)·CLI(`os ad`)·매뉴얼·백업(Velero)·설정 |
| **배포 아티팩트** | `rbac.yaml` · `servicemonitor.yaml` · `uipluginpackage.yaml` (+ operand는 control-plane이 fetch) |
