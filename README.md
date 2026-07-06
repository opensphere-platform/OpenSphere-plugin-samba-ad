# OpenSphere-plugin-samba-ad

workspace/사원 디렉터리(Samba AD DC) 관리 plugin — **D1 승격**(2026-07-06)으로 Foundation subShell 내부 뷰에서
독립 레포(폴더=컨테이너=신뢰·서명 경계, `OpenSphere-plugin-*` 규약)로 분리된 첫 sub-hosted plugin.

## 구조 계약

| 축 | 내용 |
|---|---|
| 신뢰·적재 | 콘솔 DUPA 신뢰체인 그대로 — UIPluginPackage(v2 키 서명, sha256 digest) + Extension Host 이중검증. **sub는 보안 중개자가 아니다**(감사 D1 보수 해석: 보안 경계=mainShell 단일 유지) |
| 표시·마운트 | `kind=plugin, hostRef=foundation`(manifest). `registerPage` 의도적 미호출 → mainShell 1단 비노출. Foundation(host)이 안층 메뉴(Identity → Samba-AD)에서 `<osp-samba-ad>`를 꽂아 렌더 |
| 화면 | 프레임워크 무의존 커스텀 엘리먼트(light DOM, 셸 전역 Clarity 클래스만). 자기 백엔드 `/api/samba` 집계 15s 폴링 |
| 백엔드 | `server.js` — 읽기 전용 집계(FoundationModel/identity + samba/keycloak Deployment·pods·events). 전용 SA 최소권한(`rbac.yaml`) |
| 수명주기 | UI plugin(바깥) = UIPluginRegistration(콘솔 Admin). **operand(AD DC 실물) = FoundationModel/identity `engines.samba`**(Foundation Plugins 관리) — Enable=SSA 배포, Disable=실회수(PVC 보존) |
| 매뉴얼 | `manual:contribute` — 로드 시 자기 운영 매뉴얼을 단일 Manual Registry에 기여 |

## 빌드·서명·배포

```bash
# 1) 서명(v2 키) — entrySha256 주입 + manifest 분리서명 + manifestSha256 출력
node <sign-and-pin.mjs 경로> ui-shell <opensphere-plugins-v2 개인키.pem>

# 2) 이미지 (S1: 태그 금지 — push digest를 CR에 핀)
docker build -t ghcr.io/opensphere-platform/plugin-samba-ad:vN . && docker push ...

# 3) uipluginpackage.yaml에 image.digest(sha256)·manifest.sha256 기입 → RBAC → CR
kubectl apply -f rbac.yaml && kubectl apply -f uipluginpackage.yaml
```

## self-contained(2026-07-06) — 이 레포가 Samba-AD의 전 기능을 소유

사용자 결정(self-contained)에 따라 operand 배포·관측·설정까지 이 한 레포로 이전:

| 축 | 구현 | 위치 |
|---|---|---|
| **operand 배포 선언**(PVC/Deployment/도메인/replicas/NetworkPolicy) | `server.js` `buildOperand()` + `GET /operand/manifests` | 이 레포 소유. control-plane은 이 선언을 fetch해 SSA apply만 |
| **prometheus 연결** | `server.js` `/metrics`(실 신호) + `servicemonitor.yaml` | kps가 스크레이프 |
| **메트릭 차트** | `ui-shell` 스파크라인(순수 SVG) + `/api/metrics/range`(kps 프록시) | 30분 시계열 |
| **도메인·설정 편집** | `ui-shell` 설정 폼 → FM/identity `parameters.samba` merge-patch | 저장은 foundation 검증 write-path 재사용(최소권한 — plugin SA에 impersonate 미부여). 폼·스키마·operand 렌더는 plugin 소유 |
| 관리 UI / CLI(os ad) / 매뉴얼 | 앞서 구현 | 이 레포 |

**배포 아티팩트**(kubectl apply): `rbac.yaml` · `servicemonitor.yaml` · `uipluginpackage.yaml`.
operand는 control-plane이 `GET /operand/manifests`로 받아 apply(라벨 스탬프·회수 유지) — engines.samba 설치옵션이 게이트.
