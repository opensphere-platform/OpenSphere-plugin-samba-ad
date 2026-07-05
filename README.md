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

operand(Samba AD DC 자체)의 배포 선언은 Foundation control-plane identity 번들 소관
(`OpenSphere-shell-foundation/backend/control-plane/identity_bundle.yaml`) — 이 레포는 **관리 UI와 그 신뢰 경계**만 소유한다.
