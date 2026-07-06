# 03 · UI plugin (`ui-shell/ui-shell.plugin.js`)

프레임워크 무의존 **네이티브 커스텀 엘리먼트**(`<osp-samba-ad>`, light DOM). 셸 전역 클래스만 쓰고, 자기 백엔드(`/api/samba`)를 15초 폴링한다.

## 3.1 진입 계약 — activate / define, registerPage 미호출

```js
export function activate(ctx) {
  API_BASE = ctx.api?.baseUrl ?? '';                 // 셸 관문(프록시 base)
  if (!customElements.get(TAG)) customElements.define(TAG, SambaAdElement);
  // hostRef=foundation → registerPage 의도적 미호출(§01): mainShell 1단 비노출, host가 안층 마운트.
  ctx.extensions.manual?.contribute?.({ … });        // 매뉴얼 기여(§04)
}
export function deactivate() {}
```

- `ctx.api.baseUrl` = 이 plugin의 프록시 base(`/api/plugins/samba-ad`). **모든 fetch는 이 base 경유**(셸 관문) — plugin이 임의 오리진을 때리지 않는다(CSP·감사 정합).
- (A) standalone이면 여기서 `ctx.extensions.registerPage({...})`를 호출한다. samba-ad는 sub-hosted라 **호출하지 않음** — 이 한 줄이 두 패턴의 표시 차이 전부다.

## 3.2 렌더 사이클

```
connectedCallback → _load() ──▶ render(payload)         (카드·폼 구성)
                    └▶ _loadCharts() _loadLogs() _loadBackup()   (async, 각 영역 div 채움)
setInterval 15s ──▶ 위 반복
```

- `render()`가 정적 골격(카드·폼)을 그리고, 무거운/느린 영역(차트·로그·백업 상태)은 **별도 async 로더가 각자 `#sc-metrics`/`#sc-logs`/`#sc-backup` div를 채운다**. 15초마다 재렌더되어도 각 로더가 다시 채운다.
- 모든 동적 값은 `esc()`로 이스케이프(XSS 방지).

## 3.3 디자인 규율 (반드시 지킬 것)

이 plugin은 **자체 스타일시트를 배포하지 않는다.** 셸 전역 클래스만 쓴다.

| 규칙 | 이유 |
|---|---|
| **셸 전역 Clarity/`os-*` 클래스만** (`os-h2`·`os-sech`·`os-sub`·`os-mono`·`os-filter`·`clr-row`/`clr-col`·`card`·`label label-*`·`vl-log`) | plugin은 shadow DOM 안에 마운트되어 host의 `vl-*`/`hc-*` 컴포넌트 스타일에 접근 못 함. 셸 전역 클래스만 상속됨 |
| **인라인 스타일 0** (`style="…"` 금지) | 디자인 토큰 우회·다크모드 깨짐 방지(사용자 확정 원칙). 새 UI는 `grep 'style='`로 자가감사 |
| **`<h1>`/`<h3>` 금지** → `os-h2`(제목행), `os-sech`(섹션헤더) | Clarity 전역 CSS가 특정 헤딩을 다크배경 처리하는 트랩 회피 |
| **inline `onclick` 금지** → `addEventListener` | 콘솔 **CSP `script-src 'self'`가 inline 이벤트 핸들러를 차단**. §3.5의 새로고침 링크가 대표 사례 |

> 감사(v8)에서 인라인 style 7곳·`<h1>/<h3>` 위반을 발견해 전량 셸 클래스로 교체한 이력 있음. **새 UI는 항상 이 규율로 자가감사할 것.**

## 3.4 쓰기 = host 검증 write-path 재사용 (핵심 패턴)

plugin은 도메인 자원(FM)·velero CR을 **직접 쓰지 않는다.** host(Foundation)의 검증된 write-path를 재사용한다:

```js
function foundationApiBase() { return API_BASE.replace(/\/plugins\/samba-ad$/, '/plugins/foundation'); }
//  /api/plugins/samba-ad  →  /api/plugins/foundation   (host의 /api/k8s 프록시로 라우팅)

fetch(`${foundationApiBase()}/api/k8s/apis/.../foundationmodels/identity`, {
  method: 'PATCH',
  headers: { 'content-type': 'application/merge-patch+json', 'x-os-id-token': osIdToken() },
  body: …,
});
```

- **왜**: 최소권한. plugin SA엔 impersonate/write 권한이 없다. host의 server.js가 `x-os-id-token`을 Kanidm JWKS로 검증하고 **사용자 그룹으로 임퍼소네이션**해 apiserver에 쓴다. 권한은 사용자 RBAC(그룹)로 판정 → **plugin은 폼·스키마·검증 UX만 소유**하고 권한 부여는 안 함.
- `osIdToken()` = `window.__OS_AUTH__.token()`(콘솔 auth 브리지). **읽기(GET)엔 토큰 안 실음** → host SA로 조회. **쓰기(PATCH/POST)에만 토큰** → 임퍼소네이션.
- 이 패턴으로 쓰는 것: 설정 폼(FM `parameters.samba`), 백업 Schedule/Backup/BSL/secret(velero ns) — 전부 §04.

## 3.5 세션(15분 토큰) 만료 graceful 처리

콘솔 id_token은 **정확히 900초**, `__OS_AUTH__`는 `user`/`token`만 노출(**갱신 메서드 없음**). 복구 = **페이지 새로고침(SSO 재발급)**뿐. 저장 핸들러는 이를 우아하게 처리한다:

```js
tokenExpired()          // exp 디코드, ≤5s면 만료 → 쓰기 전 선차단(무의미한 401 왕복 방지)
isAuthFail(status,body) // 응답 401 또는 'token expired' 본문 감지
sessionExpiredMsg(el)   // "세션이 만료되었습니다… [새로고침]" + 링크(addEventListener — CSP상 inline onclick 불가)
```

- `_saveConfig`·`_saveBackup`(secret/BSL/schedule 3분기)·`_backupNow` **전부 적용**.
- 효과: 암호 같은 `HTTP 401 token expired` 대신 **명확한 재로그인 안내**. 만료 시 **요청 자체를 안 보냄**(선차단).

## 3.6 검증 노하우 (제품 아님, 개발자용)

- subShell/plugin은 콘솔 plugin-host가 **shadow DOM으로 마운트**한다. 그래서 브라우저 JS로 plugin 내부 엘리먼트를 찾으려면 `document.querySelector`로는 안 되고 **shadowRoot 재귀(deepFind)**가 필요하다(`window.frames.length === 0`).
- 세션 만료 시뮬레이트: `window.__OS_AUTH__ = { token: () => 'a.' + btoa('{"exp":1}') + '.b' }` → `tokenExpired()` true.

→ 다음: [04-integration-axes.md](04-integration-axes.md)
