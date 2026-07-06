# Samba-AD 담당자 노티 — Foundation Claim/Binding 및 Crossplane write-path 정합

Date: 2026-07-06
From: OpenSphere architecture review
To: `OpenSphere-plugin-samba-ad` owner
Subject: Samba-AD plugin도 ADR-005R1 선언형 write-path 및 Foundation Claim/Binding 기준을 따라야 함

## 1. 요약

`OpenSphere-plugin-samba-ad`는 현재 self-contained plugin 구조의 좋은 reference이지만, operand 설치/설정/사용권 처리 방식은 Foundation의 최상위 결정과 정합시켜야 한다.

정본 기준은 다음과 같다.

- 모든 인프라 쓰기는 ADR-005R1에 따라 선언형 write-path만 사용한다.
- write-path 엔진은 `gitops | operator | crossplane` 중 선택 가능하다.
- Crossplane은 OpenSphere 전체의 고정 중심축은 아니지만, Foundation capability의 Claim/XRD/Composition/Provider adapter로 유효하다.
- Foundation 하위 capability는 plugin API가 직접 Secret/password/권한을 발급하는 방식이 아니라, `FoundationClaim`/typed Claim 요청과 `FoundationBinding`/typed Binding 결과로 표현해야 한다.

따라서 Samba-AD도 OpenSearch와 동일하게, plugin이 직접 권한과 secret을 임의 발급하거나 `/operand/manifests`에서 민감 설정을 반환하는 형태를 유지하면 안 된다.

## 2. Samba-AD에 적용되는 해석

Samba-AD는 Foundation/Identity capability line에 속한다.

| 항목 | 결정 |
|---|---|
| 소유 도메인 | Foundation / Identity |
| plugin 위치 | Foundation subShell 하위 self-contained plugin |
| plugin 역할 | UI, 상태 투영, manual, CLI, metrics, operand declaration 표면 |
| write 권위 | Foundation control-plane / selected write-path adapter |
| 사용권/연결 권위 | Foundation Claim/Binding |
| secret 권위 | Foundation/controller가 secret-ref로 관리. plugin API는 평문 secret 반환 금지 |

## 3. 현재 Samba-AD 구현에서 조정이 필요한 부분

현재 감사에서 확인된 위험:

- `server.js`에 `SAMBA_DEFAULTS.domainPass = 'OpenSphere2026!'`가 하드코딩되어 있다.
- `/operand/manifests` 응답에 `config.domainPass`와 Deployment env `DOMAINPASS`가 평문으로 포함된다.
- operand manifest를 plugin이 직접 구성하더라도, 실제 apply/write 권위와 secret 발급 권위가 명확히 Foundation Claim/Binding으로 분리되어 있지 않다.
- NetworkPolicy, privileged mode, insecure LDAP는 production profile로 보기 어렵다.

이 중 password 평문 노출은 즉시 수정 대상이다.

## 4. 요구되는 목표 모델

Samba-AD도 다음 모델로 수렴해야 한다.

```text
소비자/운영자 요청
  -> FoundationClaim 또는 Identity typed Claim 선언
  -> Foundation control-plane 검증
  -> 선택 write-path adapter 처리
       - gitops
       - operator
       - crossplane
  -> Samba/Identity operand 실현
  -> FoundationBinding 또는 Identity Binding 발행
  -> endpointRef / secretRef / policyRef / conditions 제공
```

예시 facade:

```yaml
apiVersion: foundation.opensphere.io/v1alpha1
kind: FoundationClaim
metadata:
  name: workforce-directory
  namespace: opensphere-system
spec:
  model: identity
  capability: directory
  engine: operator
  consumer:
    id: foundation-identity
    type: subsystem
    owner: OpenSphere Foundation
  directory:
    provider: samba-ad
    realm: OPENSPHERE.LOCAL
    domain: opensphere.local
    mode: internal-directory
    tlsRequired: true
status:
  phase: Bound
  bindingRef:
    name: workforce-directory
    kind: FoundationBinding
```

예시 binding:

```yaml
apiVersion: foundation.opensphere.io/v1alpha1
kind: FoundationBinding
metadata:
  name: workforce-directory
  namespace: opensphere-system
  finalizers:
    - foundation.opensphere.io/consumer-protect
spec:
  claimRef:
    name: workforce-directory
  model: identity
  capability: directory
status:
  phase: Bound
  endpointRef:
    service: samba-ad.opensphere-system.svc.cluster.local
    ports:
      ldap: 389
      ldaps: 636
      kerberos: 88
  secretRef:
    name: samba-ad-directory-bind
    namespace: opensphere-system
  conditions:
    - type: Ready
      status: "True"
```

## 5. Plugin API 조정 요청

`OpenSphere-plugin-samba-ad`는 다음 방향으로 조정해야 한다.

1. `/operand/manifests`
   - 평문 `domainPass` 반환 금지.
   - `DOMAINPASS`는 `valueFrom.secretKeyRef`만 반환.
   - `config`에는 secret 값을 제거하고 `secretRef: REDACTED` 또는 secret metadata만 표시.

2. 설정 저장
   - plugin backend가 직접 secret/password를 만들거나 저장하지 않는다.
   - FoundationClaim/IdentityClaim 또는 FoundationModel parameters를 선언형으로 patch한다.
   - 실제 secret 생성/회전은 Foundation control-plane 또는 selected adapter가 처리한다.

3. 사용권/연결 제공
   - 다른 module이 Samba-AD를 사용해야 한다면 bind credential을 직접 공유하지 않는다.
   - Claim/Binding status로 endpointRef, secretRef, policyRef를 제공한다.
   - consumer가 존재하는 동안 binding finalizer가 operand 회수를 차단해야 한다.

4. OAA/Manual
   - manual에 "Samba-AD 사용권/연결권은 Claim/Binding으로 얻는다"를 명시한다.
   - OAA는 secret 값을 설명하거나 노출하지 않는다.
   - OAA는 Claim proposal을 작성할 수 있지만, apply는 사용자 승인과 Foundation 권한을 거쳐야 한다.

## 6. Crossplane 적용 방식

Samba-AD는 반드시 Crossplane만 써야 한다는 뜻은 아니다.

정확한 규칙은 다음이다.

- ADR-005R1: 모든 인프라 쓰기는 선언형이어야 한다.
- 엔진은 `gitops | operator | crossplane` 중 선택한다.
- Crossplane adapter를 선택하면 Claim -> XRD -> Composition -> Provider 경로를 따른다.
- Crossplane provider가 아직 준비되지 않았으면 operator/gitops adapter fallback을 둘 수 있다.
- 어떤 엔진을 선택하든 northbound facade는 Claim/Binding으로 유지한다.

즉, Samba-AD 담당자는 "Crossplane을 무조건 써라"가 아니라, "plugin 자체 명령형/평문 secret 방식 대신 Claim/Binding과 선언형 write-path로 정렬하라"로 이해하면 된다.

## 7. 우선순위

즉시:

- hardcoded `domainPass` 제거.
- `/operand/manifests` secret redaction.
- Deployment env를 `secretKeyRef`로 변경.
- manual에 Claim/Binding 기반 사용권 정책 추가.

다음:

- `FoundationClaim`/`FoundationBinding` 또는 typed `IdentityDirectoryClaim`/`IdentityDirectoryBinding` 계약 초안 작성.
- Foundation control-plane과 Samba-AD plugin 사이의 write-path adapter 결정.
- binding finalizer와 consumer protection 도입.
- production profile에서 LDAPS/TLS, network policy, privileged mode 예외 정책 정리.

## 8. 담당자에게 전달할 결론

Samba-AD plugin의 self-contained 구조는 유지한다. 다만 self-contained는 "plugin이 모든 권한과 secret을 직접 소유한다"는 뜻이 아니다.

Samba-AD plugin은 자기 UI/backend/manual/CLI/metrics/operand declaration을 소유하되, 실제 설치/변경/secret/사용권은 Foundation Claim/Binding과 ADR-005R1 선언형 write-path를 통해 처리해야 한다.

이 기준은 OpenSearch뿐 아니라 Samba-AD에도 동일하게 적용된다.

