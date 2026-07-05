// OpenSphere 셸 플러그인 — samba-ad (dynamic-ui §9 Runtime UI Module Contract)
// D1 승격(2026-07-06): Foundation 안층 엔진 Samba-AD의 UI를 독립 서명 번들로 분리.
//   · kind=plugin, hostRef=foundation (manifest) — 이 plugin은 mainShell 1단에 나타나지 않는다:
//     registerPage를 의도적으로 호출하지 않고(§10 라우팅 비참여), 커스텀 엘리먼트 정의까지만 수행.
//     표시·마운트는 host(Foundation subShell)가 자기 안층 메뉴에서 <osp-samba-ad>를 꽂아 수행한다.
//   · 검증·적재(신뢰체인)는 mainShell Extension Host 그대로(이중 서명검증) — sub는 보안 중개자가 아니라
//     표시 위임만 받는다(감사 D1 보수 해석: 보안 경계=main 단일 유지).
// 프레임워크 무의존(네이티브 커스텀 엘리먼트, light DOM) — 셸 전역 Clarity 클래스 + os-* 유틸만 사용.
// 모든 동적 값은 esc() 이스케이프(XSS 방지). API는 ctx.api.baseUrl(셸 관문 §11)만 사용.

const TAG = 'osp-samba-ad';
let API_BASE = '';

function esc(v) {
  return String(v ?? '—').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function pill(ok, warnWhenFalse) {
  return ok ? 'label-success' : (warnWhenFalse ? 'label-warning' : 'label-danger');
}

class SambaAdElement extends HTMLElement {
  connectedCallback() {
    this.innerHTML = '<p class="os-sub">Samba-AD 불러오는 중… <span class="spinner spinner-inline"></span></p>';
    this._load();
    this._timer = setInterval(() => this._load(), 15000);
  }
  disconnectedCallback() { if (this._timer) { clearInterval(this._timer); this._timer = null; } }

  async _load() {
    try {
      const res = await fetch(`${API_BASE}/api/samba`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`samba: HTTP ${res.status}`);
      this.render(await res.json());
    } catch (e) {
      this.innerHTML = `
        <div class="alert alert-danger"><div class="alert-items">
          <div class="alert-item static"><span class="alert-text">Samba-AD 상태 조회 실패: ${esc(e)}</span></div>
        </div></div>`;
    }
  }

  kv(pairs) { return pairs.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join(''); }
  card(title, bodyHtml) {
    return `<div class="clr-col-12 clr-col-lg-6"><div class="card">
      <div class="card-header">${title}</div>
      <div class="card-block">${bodyHtml}</div>
    </div></div>`;
  }

  render(d) {
    const w = d.workload || {};
    const m = d.model || {};
    const phase = w.found ? (w.ready ? 'Running' : '기동 중') : '미배포';
    const phasePill = w.found ? pill(w.ready, true) : 'label-warning';
    const realm = w.realmEnv || m.directoryRealm || '—';
    const baseDn = realm !== '—' ? 'DC=' + realm.split('.').join(',DC=') : '—';

    const notDeployed = !w.found ? `
      <div class="alert ${m.engineOpt === 'disabled' ? 'alert-warning' : 'alert-info'}"><div class="alert-items">
        <div class="alert-item static"><span class="alert-text">${m.engineOpt === 'disabled'
          ? 'engines 설치옵션으로 비활성(FoundationModel/identity · parameters.engines.samba=disabled) — Foundation Plugins 관리에서 Enable하면 control-plane이 선언형(SSA)으로 배포합니다.'
          : `디렉터리 워크로드가 아직 없습니다 — FoundationModel/identity 적용 시 자동 배포(모델 phase: ${esc(m.phase)}).`}</span></div>
      </div></div>` : '';

    const observedRows = (m.observed || []).map((o) => `
      <tr><td class="os-mono">${esc(o.id)}</td>
      <td><span class="label ${o.healthy ? 'label-success' : (o.value === 'n/a' ? '' : 'label-danger')}">${esc(o.value)}</span></td>
      <td>${esc(o.note || o.source)}</td></tr>`).join('');

    const eventRows = (d.events || []).map((e) => `
      <tr><td><span class="label ${e.type === 'Warning' ? 'label-warning' : ''}">${esc(e.type)}</span></td>
      <td class="os-mono">${esc(e.reason)}</td><td>${esc(e.message)}</td><td>${esc(e.time)}</td></tr>`).join('');

    this.innerHTML = `
      <h1>Samba-AD <span class="badge badge-info">plugin</span> <span class="label ${phasePill}">${esc(phase)}</span></h1>
      <p class="os-sub">workspace/사원 디렉터리 · Samba Active Directory DC · realm ${esc(realm)} · ns ${esc(d.meta?.ns)}
        · <strong>독립 서명 plugin(OpenSphere-plugin-samba-ad) — 기능 컨테이너 ${esc(d.meta?.servedBy)}가 서빙, Foundation(host)이 안층 마운트</strong></p>
      ${notDeployed}
      <div class="clr-row">
        ${this.card(`디렉터리 실물 <span class="os-mono">${esc('foundation-identity-samba')}</span>`, `
          <table class="table os-kv"><tbody>${this.kv([
            ['상태', `<span class="label ${phasePill}">${esc(phase)}</span> ${w.found ? esc(`${w.readyReplicas}/${w.replicas} ready`) : ''}`],
            ['이미지', `<span class="os-mono">${esc(w.image)}</span>`],
            ['Node / 재시작', esc(`${w.node ?? '—'} / ${w.restarts ?? '—'}`)],
            ['데이터', `<span class="os-mono">PVC foundation-identity-samba-data</span> (SAM DB — 회수 시에도 보존)`],
          ])}</tbody></table>`)}
        ${this.card('연결 — 상위 서비스 소비점', `
          <table class="table os-kv"><tbody>${this.kv([
            ['LDAP', `<span class="os-mono">${esc(m.ldapURL)}</span>`],
            ['Base DN', `<span class="os-mono">${esc(baseDn)}</span>`],
            ['LDAPS · Kerberos', '<span class="os-mono">:636 · :88</span>'],
            ['DNS · SMB', '<span class="os-mono">:53(tcp/udp) · :445</span>'],
          ])}</tbody></table>
          <p class="os-sub">소비 좌표 정본 = FoundationModel/identity <span class="os-mono">status.ldapURL</span>(control-plane 기록).</p>`)}
        ${this.card(`모델 신호 — FoundationModel/identity <span class="label ${m.phase === 'Installed' ? 'label-success' : 'label-warning'}">${esc(m.phase)}</span>`, m.found ? `
          <table class="table"><thead><tr><th>신호</th><th>값</th><th>출처</th></tr></thead>
          <tbody>${observedRows || '<tr><td colspan="3">관측 신호 없음</td></tr>'}</tbody></table>
          <p class="os-sub">관측 ${esc(m.observedAt)} · ${esc(m.controlPlane)}</p>`
          : '<p class="os-sub">FoundationModel/identity CR 없음 — deploy/foundationmodels.yaml 적용 필요.</p>')}
        ${this.card('소비자 — Keycloak federation', `
          <table class="table os-kv"><tbody>${this.kv([
            ['Keycloak', `<span class="label ${d.keycloak?.found ? pill(d.keycloak.ready, true) : ''}">${d.keycloak?.found ? (d.keycloak.ready ? 'Running' : '기동 중') : '미배포'}</span> <span class="os-mono">${esc(d.keycloak?.name)}</span>`],
            ['연동', `User Federation → 이 LDAP(<span class="os-mono">${esc(m.ldapURL)}</span>)`],
          ])}</tbody></table>
          <p class="os-sub">Keycloak(identity.iam.workspace)이 이 디렉터리를 federation해 사원 로그인을 제공.</p>`)}
      </div>
      <h3>운영 이벤트 <span class="os-sub">K8s events</span></h3>
      ${eventRows ? `<table class="table"><thead><tr><th>유형</th><th>사유</th><th>메시지</th><th>시각</th></tr></thead><tbody>${eventRows}</tbody></table>`
        : '<p class="os-sub">최근 이벤트 없음.</p>'}
      <div class="alert alert-info"><div class="alert-items">
        <div class="alert-item static"><span class="alert-text">
          수명주기(Enable/Disable)는 Foundation Plugins 관리(FoundationModel engines 설치옵션)가 정본.
          사용자·그룹 생성은 samba-tool/RSAT — 콘솔은 선언형 원칙(ADR-FND-001)상 디렉터리 내용을 명령형으로 조작하지 않는다.
        </span></div>
      </div></div>`;
  }
}

// ── 자기 매뉴얼(§매뉴얼 통합) — 설치(로드)되면서 자신의 운영 매뉴얼을 셸 Manual Registry에 기여 ──
const MANUAL_DOCS = [
  {
    id: 'operations',
    title: 'Samba-AD 디렉터리 운영 매뉴얼',
    documentType: 'reference',
    tags: ['plugin', 'foundation', 'identity', 'samba', 'directory'],
    route: '/p/foundation/samba',
    sourcePath: 'samba-ad/operations',
    content: [
      '# Samba-AD 디렉터리 운영',
      '',
      'workspace/사원 디렉터리(Active Directory DC). Keycloak이 LDAP(389)로 federation해 사원 로그인을 제공한다.',
      '',
      '## 제어 위치',
      '- 수명주기(Enable/Disable): Foundation subShell → Plugins 관리. 정본은 `FoundationModel/identity`의 `spec.parameters.engines.samba`(enabled|disabled).',
      '- Enable = 선언형 설치·배포(foundation-control-plane이 identity 번들을 SSA 적용).',
      '- Disable = 실회수(Deployment/Service/NetworkPolicy 제거) — 단 PVC(SAM DB)는 보존되어 재-Enable 시 데이터가 유지된다.',
      '- 상태 화면: Foundation → Identity → Samba-AD (독립 plugin `OpenSphere-plugin-samba-ad`가 서빙).',
      '',
      '## 연결 좌표(소비점)',
      '- LDAP: `ldap://foundation-identity-samba.opensphere-foundation.svc:389` (정본 = FoundationModel/identity `status.ldapURL`)',
      '- LDAPS :636 · Kerberos :88 · DNS :53(tcp/udp) · SMB :445',
      '- Base DN: `DC=OPENSPHERE,DC=LOCAL` (realm은 Deployment env `DOMAIN`에서 도출)',
      '',
      '## 초기(day-0) 구성',
      '- 첫 기동 시 컨테이너(nowsci/samba-domain GHCR 미러)가 도메인을 자동 프로비저닝(`DOMAIN`/`DOMAINPASS` env, dev 기본 OPENSPHERE.LOCAL).',
      '- 스토리지: PVC 3Gi — StorageClass는 `FoundationModel.spec.parameters.hostRequirements.storageClass`로 오버라이드(기본 standard).',
      '- 단일 DC(replicas 1, Recreate) — pod IP 변경 시 DNS 자기등록 특성의 dev 수용.',
      '',
      '## 경계(하지 않는 것)',
      '- 콘솔은 디렉터리 내용(사용자·그룹)을 명령형으로 조작하지 않는다(ADR-FND-001). samba-tool/RSAT 사용.',
      '- 사용자 프로비저닝 권위는 Syncope(IGA, D-7 예정) — JIT 금지(ADR-FND-002).',
    ].join('\n'),
  },
];

/** §9 계약: 셸 Extension Host가 호출하는 진입점 */
export function activate(ctx) {
  API_BASE = ctx.api?.baseUrl ?? '';
  if (!customElements.get(TAG)) customElements.define(TAG, SambaAdElement);
  // hostRef=foundation — registerPage 의도적 미호출(mainShell 1단 비노출, host가 안층 마운트).
  // 매뉴얼 기여(manual:contribute): 설치(로드)와 동시에 자기 매뉴얼을 단일 Manual Registry에 등록.
  ctx.extensions.manual?.contribute?.({
    sourceId: 'plugin:samba-ad',
    name: 'Samba-AD',
    authorityTier: 3,
    language: 'ko',
    documents: MANUAL_DOCS,
  });
}

export function deactivate() { /* 호스트 마운트 해제는 host(Foundation) 소관 */ }
