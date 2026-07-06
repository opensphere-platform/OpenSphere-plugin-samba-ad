# 08 · 감사 회신·시정 (2026-07-06)

- 대상 감사: [06-technical-audit-2026-07-06.md](06-technical-audit-2026-07-06.md)
- 참조 노티: [07-crossplane-writepath-notice-2026-07-06.md](07-crossplane-writepath-notice-2026-07-06.md) (ADR-005R1 선언형 write-path · Foundation Claim/Binding 정합)
- 회신자: `OpenSphere-plugin-samba-ad` owner
- 결과 버전: **bk3** (image `@sha256:ed7a0928…`, manifest `ec418ce6…`, entry `69498862…`)

## 1. 총평

감사의 기술적 주장 5건을 **소스에 직접 대조해 전부 사실로 확인**했다(허위·과장 없음). 판정(레퍼런스 승인 + 프로덕션 전 하드닝)에 동의한다. **특히 도메인 비밀번호 문제를 자평에서 "dev 단서"로 과소평가한 것을 인정**한다 — 소스 하드코딩 + `/operand/manifests` 평문 서빙은 Critical이 맞다. 노티(07)의 Claim/Binding·선언형 write-path 정합 기준도 시정에 반영했다.

## 2. 발견별 처분

| # | 발견 | 등급 | 처분 | 근거·검증 |
|---|---|---|---|---|
| 1 | operand 비밀번호 평문 노출 | Critical | ✅ **시정 완료** | 하드코딩 제거 · `readSambaConfig`가 domainPass 미반환 · operand `DOMAINPASS`→`secretKeyRef` · Foundation 소유 Secret. 라이브: `/operand/manifests`에 `OpenSphere2026`/`domainPass`/평문 DOMAINPASS **전무**, samba Deployment DOMAINPASS=secretKeyRef, samba Running/Ready(restarts 0) |
| 2 | privileged + INSECURELDAP + NOCOMPLEXITY | High | ⚠️ **dev 예외 명시** | operand 고유 예외로 문서화(§docs/02·README). **프로덕션 프로파일**(LDAPS·비-privileged) = "다음"(§4) |
| 3 | NetworkPolicy `from` 없음(전 출처) | High | ✅ **시정 완료** | `from`=[Keycloak pod, opensphere-foundation ns]. 라이브 확인 |
| 4 | 임의 PromQL 프록시 | Medium | ✅ **시정 완료** | `samba_ad_*` 단일 메트릭+라벨매처만 허용. 라이브: 임의쿼리 400 거부·samba_ad_* 200 |
| 5 | 미사용 `page:register` | Medium | ✅ **시정 완료** | manifest·package permissions에서 제거(재서명) |
| 6 | fetch 타임아웃 없음 | Medium | ✅ **시정 완료** | `fetchT` AbortController 헬퍼 → k8s/prom/loki/controller 전부 유한 타임아웃 |
| 7 | UI가 `window.__OS_AUTH__` 전역 의존 | Low | ↪ **플랫폼 후속** | 콘솔 계약(플러그인 단독 수정 불가). 셸에 `ctx.auth` 도입은 콘솔 측 과제 |
| 8 | 테스트/CI 없음 | Weak | ✅ **시정 완료** | `verify.mjs`(의존성0): 구문·해시일치·**RBAC write verb 0**·비밀번호 하드코딩 0 검사. 11/11 pass |
| 9 | 매뉴얼 개념그래프·action binding 없음 | Gap | ↪ **후속** | Q&A엔 무방. `ManualActionBinding`은 "다음" |

## 3. 노티(07) 정합 — Claim/Binding · 선언형 write-path

노티의 "즉시" 항목 처분:

| 노티 §7 즉시 | 처분 |
|---|---|
| hardcoded `domainPass` 제거 | ✅ |
| `/operand/manifests` secret redaction | ✅ (domainPass 미반환) |
| Deployment env → `secretKeyRef` | ✅ (라이브 검증) |
| 매뉴얼에 Claim/Binding 사용권 정책 | ✅ MANUAL_DOCS에 "사용권·연결(Claim/Binding)" 절 추가 — 사용권은 Binding의 `endpointRef`/`secretRef`/`policyRef`로, 설치/변경/secret은 Foundation 선언형 write-path, OAA는 secret 미노출·apply는 사용자 승인+Foundation 권한 |

**secret 권위 정합**: 도메인 비밀번호는 이제 **Foundation 소유 Secret**(`foundation-identity-samba-creds`, ns `opensphere-foundation`, 라벨 `secret-authority=foundation`·`interim-bootstrap=true`)이 보유하고 operand는 secretKeyRef로만 참조한다. **plugin backend는 secret을 만들거나 반환하지 않는다.** 현 Secret은 **interim 부트스트랩**(운영 samba 무중단을 위해 기존 값과 동일하게 생성)이며, 최종 생성·회전 권위는 아래 "다음"의 Foundation control-plane/adapter로 수렴한다.

## 4. "다음" — 목표 모델과 계획

노티 §4~§6의 목표 모델로 수렴한다. 이 항목들은 Foundation control-plane 범위(plugin 단독 불가)라 계약·경로로 남긴다.

1. **typed Claim/Binding 계약 초안**: `IdentityDirectoryClaim`(요청: realm/domain/mode/tlsRequired) → Foundation control-plane 검증 → 선택 write-path adapter(gitops|operator|crossplane) → operand 실현 → `IdentityDirectoryBinding`(결과: `endpointRef`·`secretRef`·`policyRef`·conditions). northbound facade는 엔진 무관하게 Claim/Binding 유지.
2. **secret 권위 이관**: interim 부트스트랩 Secret → Foundation control-plane/adapter가 생성·회전(값 out-of-band, 소스/manifest 미커밋). 비밀번호 **회전**(현 값은 git 이력에 노출 이력 있음)은 samba-tool 경유 실 AD 반영과 함께.
3. **binding finalizer**: consumer 존재 동안 operand 회수 차단(`foundation.opensphere.io/consumer-protect`).
4. **production profile**: LDAPS/TLS 필수·insecure LDAP 비활성·privileged 회피 또는 정당화, admission policy로 privileged 패턴 무단 복제 차단.
5. **백업 전용대상 secret 정합**: 현재 samba-ad 백업 override의 전용 BSL 자격증명(사용자 외부 S3)도 UI가 velero ns Secret에 직접 쓴다 — 장기적으로 Claim/adapter 경유로 정렬 검토(사용자 외부 자격이라 Identity 도메인 비밀번호와는 성격이 다름).

## 5. 검증 요약 (라이브)

- `verify.mjs`: 11/11 pass (구문·해시·RBAC read-only·비밀번호 0).
- `/operand/manifests`: cleartext 0, DOMAINPASS=secretKeyRef, config.domainPass=undefined.
- samba Deployment: DOMAINPASS=secretKeyRef(`foundation-identity-samba-creds`), pod Running/Ready, DOMAINPASS Secret에서 해석(len 확인, 값 미출력).
- NetworkPolicy: `from`=[keycloak, foundation ns].
- PromQL: 임의쿼리 400 거부, samba_ad_* 200 허용.
- registration `samba-ad` Enabled, image `@sha256:ed7a0928`.

## 6. 결론

감사·노티의 **즉시 항목은 전부 시정·라이브 검증 완료**. High(privileged/LDAP)·"다음"(Claim/Binding 계약·secret 권위 이관·finalizer·production profile)은 Foundation control-plane 과제로 계약·경로를 명시했다. self-contained 구조는 유지하되 **"plugin이 모든 권한·secret을 직접 소유"가 아님**을 코드·문서·매뉴얼에 반영했다.

> 이 시정을 반영한 상태가 감사 §7의 **OpenSearch plugin 템플릿**의 기준선이 된다.
