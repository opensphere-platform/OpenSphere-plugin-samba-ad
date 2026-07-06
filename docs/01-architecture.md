# 01 · 아키텍처 — DUPA 내 위치, 신뢰·마운트, 수명주기

## 1.1 DUPA 한 줄

**콘솔(mainShell)**이 프레임·계약·라우팅·인증·디자인·감사를 소유하고, **기능(feature)**은 각자 자기 백엔드 + UI 번들을 담은 **독립 배포 컨테이너**로 런타임에 적재된다. samba-ad는 그 "기능 컨테이너" 하나다.

- 보안 모델 = **"서명된 신뢰 코드만 실행"** (샌드박스 아님). 셸 레벨에 iframe/worker/shadow 격리가 방어선이 아니라, **CSP(`script-src 'self' blob:`) + P-256 이중 서명검증**(적재 시 + 설치 시)이 방어선이다.
- 따라서 **plugin은 보안 중개자가 아니다.** 보안 경계는 mainShell 단일. plugin이 하는 일은 "표시·기능 위임"이지 "격리"가 아니다. → **신뢰할 수 있는 코드만 담아야 한다.**

## 1.2 두 가지 plugin 표시 패턴 — samba-ad는 "sub-hosted"

| | (A) standalone plugin | (B) **sub-hosted plugin ← samba-ad** |
|---|---|---|
| manifest | `kind: plugin` | `kind: plugin`, **`hostRef: foundation`** |
| `registerPage` | 호출 → mainShell 1단 nav/라우팅 등재 | **의도적 미호출** → mainShell 1단 비노출 |
| 표시 위치 | 콘솔 최상위 메뉴 | **host(Foundation) 안층 메뉴**(Identity → Samba-AD) |
| 마운트 주체 | 셸 라우터 | **host가 `<osp-samba-ad>` 태그를 자기 화면에 삽입** |
| 적재·검증 | 콘솔 신뢰체인(이중 서명검증) | **동일** — 콘솔 신뢰체인 그대로 |

> **핵심**: (A)와 (B)의 **차이는 "표시 계약"뿐**이다. 신뢰체인·서명·SA·프록시·통합축은 **완전히 동일**하다. 그래서 이 샘플의 대부분(§02~05)은 두 패턴 공통으로 재사용된다. sub-hosted를 택한 이유는 Samba-AD가 Foundation의 Identity 도메인에 **개념적으로 종속**되기 때문이다(단독 최상위 메뉴가 아니라 Foundation 안의 한 엔진).

## 1.3 신뢰·서명 경계 = 폴더 = 컨테이너 = 레포

```
OpenSphere-plugin-samba-ad/         ← 독립 git 레포 = 신뢰·서명 경계 = 1 컨테이너
├── server.js                       ← 백엔드(읽기 집계 + operand/CLI/metrics/logs 표면)
├── ui-shell/
│   ├── ui-shell.plugin.js          ← UI entry (서명 대상, entrySha256로 핀)
│   ├── ui-shell.manifest.json      ← 매니페스트(entrySha256 포함) — sha256로 핀
│   └── ui-shell.manifest.json.sig  ← 매니페스트 P-256 서명(v2 키)
├── uipluginpackage.yaml            ← 신뢰 루트(digest·manifest.sha256·keyId — 관리자 승인값)
├── rbac.yaml                       ← 전용 SA + 최소권한
├── servicemonitor.yaml             ← kps 스크레이프 등록
├── Dockerfile                      ← node:22-alpine, 의존성 0
└── docs/                           ← (이 문서)
```

이중 핀:
- **이미지 digest**(`uipluginpackage.yaml` `spec.image.digest = sha256:…`) → 컨테이너 전체(UI 번들·server.js) 무결성. **태그 금지**(S1 — CRD가 `^sha256:` 패턴 강제).
- **manifest sha256 + entrySha256 + 서명** → UI entry(`ui-shell.plugin.js`)의 무결성·출처. 서명은 `trust.keyId: opensphere-plugins-v2` 공개키로 검증.

## 1.4 적재·마운트 흐름

```
관리자                     콘솔(mainShell)                     Foundation(host)          클러스터
  │                            │                                   │                       │
  │ apply UIPluginPackage ─────▶ dupa-registry-controller          │                       │
  │        + Registration      │  ├ 서명 검증(manifest.sig, v2키)   │                       │
  │                            │  ├ digest 검증(sha256 강제)        │                       │
  │                            │  └ createWorkload ────────────────────────────────────────▶ Deployment(samba-ad)
  │                            │                                   │                        + Service(라벨 dupa-plugin)
  │                            │                                   │                        + proxy route /api/plugins/samba-ad
  │ 콘솔 접속 ─────────────────▶ Extension Host                    │                       │
  │                            │  ├ manifest fetch + 재검증(적재시)  │                       │
  │                            │  └ import(entry) ─ activate(ctx) ─▶ customElements.define   │
  │                            │      (hostRef=foundation →         │  ('osp-samba-ad')     │
  │                            │       registerPage 미호출)         │                       │
  │ Foundation → Identity ─────▶ (host 라우팅)                     │ whenDefined 후         │
  │   → Samba-AD               │                                   │ <osp-samba-ad> 삽입 ──▶ 렌더
```

- **entry(`ui-shell.plugin.js`)는 부트스트랩이 아니라 실제 UI 코드**다(foundation subShell의 entry가 얇은 로더인 것과 다름). 그래서 UI를 바꾸면 entry 해시가 바뀌어 **재서명이 필요**하다(§05).
- host(Foundation)의 `samba.component`가 `customElements.whenDefined('osp-samba-ad')`를 기다렸다가 태그를 삽입한다(Angular `CUSTOM_ELEMENTS_SCHEMA`).

## 1.5 수명주기 2계층 — "UI 바깥"과 "operand 실물"을 분리

samba-ad는 **두 개의 독립된 수명주기**를 가진다. 이 분리가 설계의 핵심이다.

| 계층 | 무엇 | 정본(선언) | 제어 위치 | Enable/Disable 의미 |
|---|---|---|---|---|
| **① UI plugin** (바깥) | 화면·백엔드 컨테이너 | `UIPluginRegistration.spec.desiredState` | 콘솔 Admin(플러그인 관리) | plugin 컨테이너 자체의 등재/해지 |
| **② operand** (실물) | Samba AD DC(Deployment/PVC/…) | `FoundationModel/identity.spec.parameters.engines.samba` = `enabled\|disabled` | Foundation → Plugins 관리 | **Enable=SSA 배포, Disable=실회수(PVC 보존)** |

- operand는 **plugin이 소유한 선언**(`GET /operand/manifests`)을 control-plane이 fetch해 SSA apply한다(§04). "메뉴=실재의 투영" — Disable하면 실제 워크로드가 회수된다(단 PVC=SAM DB는 보존).
- **왜 분리하나**: UI를 끄는 것(plugin 미표시)과 디렉터리 실물을 내리는 것(데이터 서비스 중단)은 다른 결정이다. 샘플로서 이 분리를 반드시 이해할 것.

## 1.6 네임스페이스 지도

| 리소스 | 네임스페이스 |
|---|---|
| plugin Deployment/Service (UI+백엔드 컨테이너) | `opensphere-system` |
| UIPluginPackage / UIPluginRegistration | `opensphere-system` |
| operand(Samba DC Deployment/PVC/SVC/NetPol) | `opensphere-foundation` |
| FoundationModel/identity(선언 정본) | (cluster/foundation) |
| 관측 스택(kps·Loki) | `monitoring` |
| 백업 스택(Velero) | `velero` |

→ 다음: [02-backend.md](02-backend.md)
