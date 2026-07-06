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
const SAMBA_LOGO_URL = 'https://cdn.statically.io/gh/openplatform-labs/images@main/logos/samba-server.svg';

// 설정 저장 = FM/identity.spec.parameters.samba(foundation 도메인 자원) → foundation host의 검증된 write-path
// (server.js가 x-os-id-token 검증+임퍼소네이션) 재사용. plugin은 폼·스키마·operand 렌더를 소유하되,
// 도메인 자원 write는 최소권한 원칙상 foundation 경로로(플러그인 SA에 impersonate 권한 미부여).
function foundationApiBase() { return API_BASE.replace(/\/plugins\/samba-ad$/, '/plugins/foundation'); }
function osIdToken() {
  try {
    const w = window.__OS_AUTH__;
    const t = typeof w?.token === 'function' ? w.token() : w?.token;
    return t || '';
  } catch { return ''; }
}

// ── 콘솔 세션(15분 id_token, 자동 갱신 수단 없음 — __OS_AUTH__는 user/token만 노출) 만료 처리 ──
// 셸이 refresh/login API를 주지 않으므로 복구 = 페이지 새로고침(SSO 재발급). 쓰기 전/후로 만료를 감지해
// 암호 같은 401 대신 명확한 재로그인 안내를 준다. [[console-15min-token-expiry]]
function tokenExpired() {
  const t = osIdToken();
  if (!t) return true;
  try { const p = JSON.parse(atob(t.split('.')[1])); return (p.exp - Math.floor(Date.now() / 1000)) <= 5; }
  catch { return false; }  // 디코드 불가면 서버 검증에 위임(선차단 안 함)
}
function isAuthFail(status, body) {
  return status === 401 || /token expired|token missing|unauthorized/i.test(String(body || ''));
}
// status 엘리먼트에 세션 만료 안내 + 새로고침 링크(inline onclick은 CSP 차단 → addEventListener). 값 esc 불요(고정 문자열).
function sessionExpiredMsg(el) {
  if (!el) return;
  el.innerHTML = '세션이 만료되었습니다 (콘솔 로그인 15분 · 자동 갱신 없음). <a href="#" data-osp-reload>새로고침</a> 후 값을 다시 입력해 저장하세요.';
  const a = el.querySelector('[data-osp-reload]');
  if (a) a.addEventListener('click', (e) => { e.preventDefault(); location.reload(); });
}

function esc(v) {
  return String(v ?? '—').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function pill(ok, warnWhenFalse) {
  return ok ? 'label-success' : (warnWhenFalse ? 'label-warning' : 'label-danger');
}

function sambaLogo(size = 34) {
  return `<img src="${SAMBA_LOGO_URL}" alt="Samba-AD" style="width:${size}px;height:${size}px;object-fit:contain;vertical-align:middle;margin-right:.5rem;">`;
}

function explainBlocker(c) {
  if (c?.id === 'identity-claim-binding') {
    return {
      title: 'Samba-AD 사용권/연결 계약이 아직 준비되지 않았습니다.',
      problem: 'Keycloak 같은 다른 모듈이 Samba-AD를 사용하려면 IdentityDirectoryClaim과 IdentityDirectoryBinding이라는 표준 계약이 먼저 있어야 합니다.',
      impact: '이 계약이 없으면 어떤 모듈에게 LDAP 주소, bind 계정 Secret, 네트워크 허용 정책을 줄지 안전하게 관리할 수 없습니다.',
      fix: 'Foundation에 IdentityDirectoryClaim/IdentityDirectoryBinding CRD와 reconciler를 설치한 뒤 다시 Preflight를 확인하세요. Crossplane 자체는 준비되어 있으므로 다음 작업은 Identity Claim/Binding 계약 등록입니다.',
    };
  }
  return {
    title: c?.label || '필수 조건 미충족',
    problem: c?.message || '설치 전 필수 조건이 충족되지 않았습니다.',
    impact: '이 상태에서는 Samba-AD operand를 안전하게 배포할 수 없습니다.',
    fix: 'BLOCK 항목을 해결한 뒤 Preflight를 다시 실행하세요.',
  };
}

// 순수 SVG 스파크라인(차트 라이브러리 무의존, light DOM). points=[[ts,"val"],…].
function sparkline(points, w = 280, h = 44, color = '#4c6fff') {
  if (!points || !points.length) return '<span class="os-sub">데이터 없음</span>';
  const vals = points.map((p) => Number(p[1]));
  const min = Math.min(...vals), max = Math.max(...vals), range = (max - min) || 1;
  const step = w / ((points.length - 1) || 1);
  const y = (v) => (h - 2 - ((v - min) / range) * (h - 4)).toFixed(1);
  const d = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${y(Number(p[1]))}`).join(' ');
  const last = vals[vals.length - 1];
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <path d="${d}" fill="none" stroke="${color}" stroke-width="1.5"/>
    <circle cx="${((points.length - 1) * step).toFixed(1)}" cy="${y(last)}" r="2.5" fill="${color}"/>
  </svg>`;
}

class SambaAdElement extends HTMLElement {
  connectedCallback() {
    this.innerHTML = '<p class="os-sub">Samba-AD 불러오는 중… <span class="spinner spinner-inline"></span></p>';
    this._load().then(() => this._afterRenderLoads());
    this._timer = setInterval(() => this._load().then(() => this._afterRenderLoads()), 15000);
  }
  disconnectedCallback() { if (this._timer) { clearInterval(this._timer); this._timer = null; } }

  _afterRenderLoads() {
    if (this.querySelector('#sc-metrics')) this._loadCharts();
    if (this.querySelector('#sc-logs')) this._loadLogs();
    if (this.querySelector('#sc-backup')) this._loadBackup();
  }

  // Loki 로그 통합 — samba pod stdout tail(자기 /api/logs 프록시 경유). 셸 vl-log 콘솔 박스 재사용(velero 동일).
  async _loadLogs() {
    const host = this.querySelector('#sc-logs');
    if (!host) return;
    try {
      const res = await fetch(`${API_BASE}/api/logs?minutes=60`, { cache: 'no-store' });
      if (!res.ok) {
        const t = await res.json().catch(() => ({}));
        host.innerHTML = `<div class="vl-log-empty">${esc(t.error || `로그 조회 실패 HTTP ${res.status}`)}</div>`;
        return;
      }
      const lines = (await res.json()).lines || [];
      host.innerHTML = lines.length
        ? lines.map((l) => `<div class="vl-log-line">${esc(new Date(l.ts).toLocaleTimeString())}  ${esc(l.line)}</div>`).join('')
        : '<div class="vl-log-empty">최근 60분 로그 없음 — promtail 수집/Loki 연결을 확인하세요.</div>';
    } catch (e) {
      host.innerHTML = `<div class="vl-log-empty">로그 조회 실패: ${esc(e)}</div>`;
    }
  }

  // kube-prometheus-stack 시계열 → 스파크라인(자기 /api/metrics/range 프록시 경유).
  async _loadCharts() {
    const host = this.querySelector('#sc-metrics');
    if (!host) return;
    const series = [
      { q: 'samba_ad_up{plugin="samba-ad"}', label: 'DC ready', kind: 'bool', good: 1 },
      { q: 'samba_ad_ldap_reachable{plugin="samba-ad"}', label: 'LDAP :389', kind: 'bool', good: 1 },
      { q: 'samba_ad_keycloak_federation_up{plugin="samba-ad"}', label: 'Keycloak federation', kind: 'bool', good: 1 },
      { q: 'samba_ad_replicas_ready{plugin="samba-ad"}', label: 'Replicas ready', kind: 'count' },
      { q: 'samba_ad_replicas_desired{plugin="samba-ad"}', label: 'Replicas desired', kind: 'count' },
      { q: 'samba_ad_restarts_total{plugin="samba-ad"}', label: 'Restart delta', kind: 'counter' },
    ];
    try {
      const results = await Promise.all(series.map((x) =>
        fetch(`${API_BASE}/api/metrics/range?q=${encodeURIComponent(x.q)}&minutes=30`, { cache: 'no-store' })
          .then((r) => r.ok ? r.json() : null).catch(() => null)));
      const aggregateSeries = (matrix, mode = 'max') => {
        const buckets = new Map();
        (matrix || []).forEach((serie) => {
          (serie.values || []).forEach(([ts, value]) => {
            const key = String(ts);
            const arr = buckets.get(key) || [];
            arr.push(Number(value));
            buckets.set(key, arr);
          });
        });
        return Array.from(buckets.entries())
          .sort((a, b) => Number(a[0]) - Number(b[0]))
          .map(([ts, values]) => [Number(ts), String(mode === 'sum'
            ? values.reduce((a, b) => a + b, 0)
            : Math.max(...values))]);
      };
      const counterDelta = (matrix) => (matrix || []).reduce((total, serie) => {
        const vals = (serie.values || []).map((x) => Number(x[1]));
        let delta = 0;
        for (let n = 1; n < vals.length; n++) delta += Math.max(0, vals[n] - vals[n - 1]);
        return total + delta;
      }, 0);
      const rows = results.map((res, i) => {
        const meta = series[i];
        const matrix = res?.data?.result || [];
        const pts = aggregateSeries(matrix, meta.kind === 'counter' ? 'sum' : 'max');
        if (!pts || !pts.length) {
          return `<tr><td>${esc(meta.label)}</td><td><span class="label">No data</span></td><td>n/a</td><td>n/a</td></tr>`;
        }
        const vals = pts.map((x) => Number(x[1]));
        const cur = vals[vals.length - 1];
        const first = vals[0];
        const availability = meta.kind === 'bool'
          ? Math.round((vals.filter((v) => v === meta.good).length / vals.length) * 100)
          : null;
        const delta = meta.kind === 'counter' ? counterDelta(matrix) : null;
        const changedAt = (() => {
          for (let n = vals.length - 1; n > 0; n--) {
            if (vals[n] !== vals[n - 1]) return new Date(Number(pts[n][0]) * 1000).toLocaleTimeString();
          }
          return 'no transition';
        })();
        const cls = meta.kind === 'bool'
          ? (cur === meta.good ? 'label-success' : 'label-danger')
          : (meta.kind === 'counter' && delta > 0 ? 'label-warning' : 'label-info');
        const now = meta.kind === 'bool' ? (cur === meta.good ? 'OK' : 'Down') : (meta.kind === 'counter' ? `+${delta}` : String(cur));
        const windowText = meta.kind === 'bool'
          ? `${availability}% available / 30m`
          : (meta.kind === 'counter' ? `current=${cur}, first=${first}` : `current=${cur}`);
        return `<tr><td>${esc(meta.label)}</td><td><span class="label ${cls}">${esc(now)}</span></td><td>${esc(windowText)}</td><td>${esc(changedAt)}</td></tr>`;
      }).join('');
      const anyData = results.some((r) => r?.data?.result?.[0]?.values?.length);
      host.innerHTML = `<div class="os-sech">Metrics <span class="os-sub">operational signals, last 30 minutes</span></div>
        ${anyData ? `<div class="card"><div class="card-block">
          <table class="table"><thead><tr><th>Signal</th><th>Now</th><th>Window</th><th>Last transition</th></tr></thead><tbody>${rows}</tbody></table>
          <p class="os-sub">Boolean health signals are shown as state and availability, not as line charts. Restart is shown as a 30m counter delta.</p>
        </div></div>` : '<p class="os-sub">No metric samples yet. Check ServiceMonitor scraping and Prometheus connectivity.</p>'}`;
    } catch (e) {
      host.innerHTML = `<div class="os-sech">Metrics</div><p class="os-sub">Metric lookup failed: ${esc(e)}</p>`;
    }
  }

  async _loadBackup() {
    const host = this.querySelector('#sc-backup');
    if (!host) return;
    const base = foundationApiBase();
    const V = `${base}/api/k8s/apis/velero.io/v1/namespaces/velero`;
    try {
      const [schRes, bkRes, bslRes] = await Promise.all([
        fetch(`${V}/schedules/samba-ad`, { cache: 'no-store' }),
        fetch(`${V}/backups?labelSelector=${encodeURIComponent('opensphere.io/plugin=samba-ad')}`, { cache: 'no-store' }),
        fetch(`${V}/backupstoragelocations`, { cache: 'no-store' }),
      ]);
      if (schRes.status === 404 && !schRes.ok && bkRes.status === 404) {
        host.innerHTML = '<p class="os-sub"><span class="label label-warning">Velero 미설치</span> BSS → Velero에서 백업 엔진과 공용 기본 대상을 먼저 구성하세요.</p>';
        return;
      }
      // Schedule
      let sch = null; if (schRes.ok) sch = await schRes.json();
      const schHtml = sch
        ? `<span class="label label-success">일정 등록됨</span> <span class="os-mono">${esc(sch.spec?.schedule)}</span> → BSL <span class="os-mono">${esc(sch.spec?.template?.storageLocation)}</span>${sch.spec?.paused ? ' <span class="label label-warning">일시중지</span>' : ''} <span class="os-sub">최근 실행 ${esc(sch.status?.lastBackup || '—')}</span>`
        : '<span class="label label-warning">일정 없음</span> <span class="os-sub">아래에서 백업을 활성화하세요.</span>';
      // 대상 BSL 가용성
      const bsls = bslRes.ok ? ((await bslRes.json()).items || []) : [];
      const bslPhase = (name) => { const b = bsls.find((x) => x.metadata?.name === name); return b ? (b.status?.phase || 'Unknown') : '없음'; };
      // Backups
      const items = bkRes.ok ? ((await bkRes.json()).items || []) : [];
      items.sort((a, b) => String(b.metadata?.creationTimestamp).localeCompare(String(a.metadata?.creationTimestamp)));
      const bkPill = (ph) => ph === 'Completed' ? 'label-success' : (ph === 'InProgress' || ph === 'New') ? 'label-warning' : (ph ? 'label-danger' : '');
      const rows = items.slice(0, 8).map((b) => {
        const ph = b.status?.phase || '—';
        const started = b.status?.startTimestamp || b.metadata?.creationTimestamp || '';
        const errs = b.status?.errors || 0;
        return `<tr><td class="os-mono">${esc(b.metadata?.name)}</td>
          <td><span class="label ${bkPill(ph)}">${esc(ph)}</span></td>
          <td>${esc(started ? new Date(started).toLocaleString() : '—')}</td>
          <td>${esc(errs ? errs + ' errors' : 'OK')}</td></tr>`;
      }).join('');
      host.innerHTML = `
        <table class="table"><tbody>
          <tr><td>일정(Schedule)</td><td>${schHtml}</td></tr>
          <tr><td>대상 저장위치(BSL)</td><td>공용 기본 <span class="label ${bslPhase('default') === 'Available' ? 'label-success' : 'label-warning'}">default: ${esc(bslPhase('default'))}</span> · 전용 <span class="label ${bslPhase('samba-ad') === 'Available' ? 'label-success' : ''}">samba-ad: ${esc(bslPhase('samba-ad'))}</span></td></tr>
        </tbody></table>
        ${rows ? `<table class="table"><thead><tr><th>백업</th><th>상태</th><th>시작</th><th>결과</th></tr></thead><tbody>${rows}</tbody></table>`
          : '<p class="os-sub">실행된 백업 없음 — 일정 등록 후 스케줄 시각에 실행되거나 "지금 백업"으로 즉시 실행.</p>'}`;
    } catch (e) {
      host.innerHTML = `<p class="os-sub">백업 상태 조회 실패: ${esc(e)}</p>`;
    }
  }

  // velero.io CR create-or-merge (foundation 프록시 + x-os-id-token). POST 생성 → 409면 merge-patch.
  async _ensureCR(base, idt, apiPath, plural, name, obj) {
    const post = await fetch(`${base}/api/k8s/${apiPath}/${plural}`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-os-id-token': idt }, body: JSON.stringify(obj),
    });
    if (post.ok) return { ok: true };
    if (post.status === 409) {
      const patch = await fetch(`${base}/api/k8s/${apiPath}/${plural}/${name}`, {
        method: 'PATCH', headers: { 'content-type': 'application/merge-patch+json', 'x-os-id-token': idt }, body: JSON.stringify(obj),
      });
      return { ok: patch.ok, status: patch.status, body: patch.ok ? '' : await patch.text().catch(() => '') };
    }
    return { ok: false, status: post.status, body: await post.text().catch(() => '') };
  }

  // 백업 활성화·저장 — (전용이면 Secret+BSL 생성) → Schedule 등록/갱신 → FM parameters.samba.backup 기록.
  async _saveBackup() {
    const status = this.querySelector('#sc-bk-status');
    if (tokenExpired()) { sessionExpiredMsg(status); return; }
    const idt = osIdToken();
    const val = (id) => (this.querySelector(id)?.value ?? '').trim();
    const mode = val('#sc-bk-mode') === 'dedicated' ? 'dedicated' : 'shared';
    const schedule = val('#sc-bk-cron') || '0 2 * * *';
    const base = foundationApiBase();
    const bslName = mode === 'dedicated' ? 'samba-ad' : 'default';
    if (status) status.textContent = '저장 중…';
    try {
      let dedicated = null;
      if (mode === 'dedicated') {
        const ep = val('#sc-bk-ep'), bucket = val('#sc-bk-bucket'), region = val('#sc-bk-region') || 'us-east-1';
        const ak = val('#sc-bk-ak'), sk = val('#sc-bk-sk');
        if (!ep || !bucket || !ak || !sk) { if (status) status.textContent = '전용 대상: 엔드포인트·버킷·Access/Secret Key는 필수입니다.'; return; }
        dedicated = { endpoint: ep, bucket, region };
        const cloud = `[default]\naws_access_key_id=${ak}\naws_secret_access_key=${sk}\n`;
        const secret = { apiVersion: 'v1', kind: 'Secret', metadata: { name: 'samba-ad-backup-creds', namespace: 'velero', labels: { 'opensphere.io/plugin': 'samba-ad' } }, type: 'Opaque', data: { cloud: btoa(cloud) } };
        const sRes = await this._ensureCR(base, idt, 'api/v1/namespaces/velero', 'secrets', 'samba-ad-backup-creds', secret);
        if (!sRes.ok) { if (isAuthFail(sRes.status, sRes.body)) { sessionExpiredMsg(status); return; } if (status) status.textContent = `전용 자격증명 저장 실패 HTTP ${sRes.status}: ${(sRes.body || '').slice(0, 120)}`; return; }
        const bsl = { apiVersion: 'velero.io/v1', kind: 'BackupStorageLocation', metadata: { name: 'samba-ad', namespace: 'velero', labels: { 'opensphere.io/plugin': 'samba-ad' } },
          spec: { provider: 'aws', objectStorage: { bucket }, credential: { name: 'samba-ad-backup-creds', key: 'cloud' }, config: { region, s3Url: ep, s3ForcePathStyle: 'true' } } };
        const bRes = await this._ensureCR(base, idt, 'apis/velero.io/v1/namespaces/velero', 'backupstoragelocations', 'samba-ad', bsl);
        if (!bRes.ok) { if (isAuthFail(bRes.status, bRes.body)) { sessionExpiredMsg(status); return; } if (status) status.textContent = `전용 저장위치(BSL) 생성 실패 HTTP ${bRes.status}: ${(bRes.body || '').slice(0, 120)}`; return; }
      }
      const sched = { apiVersion: 'velero.io/v1', kind: 'Schedule', metadata: { name: 'samba-ad', namespace: 'velero', labels: { 'opensphere.io/plugin': 'samba-ad' } },
        spec: { schedule, template: { includedNamespaces: ['opensphere-foundation'], labelSelector: { matchLabels: { app: 'foundation-identity-samba' } }, defaultVolumesToFsBackup: true, storageLocation: bslName, ttl: '720h0m0s' } } };
      const scRes = await this._ensureCR(base, idt, 'apis/velero.io/v1/namespaces/velero', 'schedules', 'samba-ad', sched);
      if (!scRes.ok) { if (isAuthFail(scRes.status, scRes.body)) { sessionExpiredMsg(status); return; } if (status) status.textContent = `일정 등록 실패 HTTP ${scRes.status}${scRes.status === 403 ? ' (권한 없음 — velero 네임스페이스 쓰기 필요)' : ''}: ${(scRes.body || '').slice(0, 120)}`; return; }
      // FM에 백업 설정 기록(표시·정본).
      const fmBody = { spec: { parameters: { samba: { backup: { enabled: true, mode, schedule, dedicated } } } } };
      await fetch(`${base}/api/k8s/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity`, {
        method: 'PATCH', headers: { 'content-type': 'application/merge-patch+json', 'x-os-id-token': idt }, body: JSON.stringify(fmBody),
      }).catch(() => {});
      if (status) status.textContent = `저장됨 — ${mode === 'dedicated' ? '전용' : '공용 기본'} 대상으로 일정 등록/갱신(${esc(schedule)}). 대상 BSL이 Available이어야 실제 백업이 저장됩니다.`;
      setTimeout(() => this._loadBackup(), 1500);
    } catch (e) { if (status) status.textContent = `저장 실패: ${esc(e)}`; }
  }

  // 지금 백업 — 일회성 Backup CR 생성(현재 모드의 BSL 사용). node-agent 파일시스템 백업으로 PVC 담김.
  async _backupNow() {
    const status = this.querySelector('#sc-bk-status');
    if (tokenExpired()) { sessionExpiredMsg(status); return; }
    const idt = osIdToken();
    const mode = (this.querySelector('#sc-bk-mode')?.value === 'dedicated') ? 'dedicated' : 'shared';
    const bslName = mode === 'dedicated' ? 'samba-ad' : 'default';
    const base = foundationApiBase();
    const name = `samba-ad-manual-${Date.now()}`;
    const bk = { apiVersion: 'velero.io/v1', kind: 'Backup', metadata: { name, namespace: 'velero', labels: { 'opensphere.io/plugin': 'samba-ad' } },
      spec: { includedNamespaces: ['opensphere-foundation'], labelSelector: { matchLabels: { app: 'foundation-identity-samba' } }, defaultVolumesToFsBackup: true, storageLocation: bslName, ttl: '720h0m0s' } };
    if (status) status.textContent = '백업 요청 중…';
    try {
      const r = await fetch(`${base}/api/k8s/apis/velero.io/v1/namespaces/velero/backups`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-os-id-token': idt }, body: JSON.stringify(bk),
      });
      if (!r.ok) { const t = await r.text().catch(() => ''); if (isAuthFail(r.status, t)) { sessionExpiredMsg(status); return; } if (status) status.textContent = `백업 요청 실패 HTTP ${r.status}: ${t.slice(0, 120)}`; return; }
      if (status) status.textContent = `백업 요청됨(${name}) — 진행 상태는 아래 표에서 갱신됩니다.`;
      setTimeout(() => this._loadBackup(), 1500);
    } catch (e) { if (status) status.textContent = `백업 요청 실패: ${esc(e)}`; }
  }

  async _load() {
    try {
      const res = await fetch(`${API_BASE}/api/samba`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`samba: HTTP ${res.status}`);
      this.render(await res.json());
      this._bindLifecycleActions();
      const btn = this.querySelector('#sc-cfg-save');
      if (btn) btn.onclick = () => this._saveConfig();
      const installSave = this.querySelector('#sc-install-save');
      if (installSave) installSave.onclick = () => this._saveInstallInputs();
      const installStart = this.querySelector('#sc-install-start');
      if (installStart) installStart.onclick = () => this._startInstall();
      const bkSave = this.querySelector('#sc-bk-save');
      if (bkSave) bkSave.onclick = () => this._saveBackup();
      const bkNow = this.querySelector('#sc-bk-now');
      if (bkNow) bkNow.onclick = () => this._backupNow();
      const bkMode = this.querySelector('#sc-bk-mode');
      if (bkMode) bkMode.onchange = () => { const d = this.querySelector('#sc-bk-dedicated'); if (d) d.hidden = bkMode.value !== 'dedicated'; };
    } catch (e) {
      this.innerHTML = `
        <div class="alert alert-danger"><div class="alert-items">
          <div class="alert-item static"><span class="alert-text">Samba-AD 상태 조회 실패: ${esc(e)}</span></div>
        </div></div>`;
    }
  }

  // 설정 저장(도메인/replicas/storageClass/dnsForwarder) → FM/identity merge-patch(foundation 검증 경로).
  async _saveInstallInputs() {
    const status = this.querySelector('#sc-install-status');
    if (tokenExpired()) { sessionExpiredMsg(status); return; }
    const idt = osIdToken();
    const val = (id) => (this.querySelector(id)?.value ?? '').trim();
    const replicas = parseInt(val('#sc-install-replicas'), 10);
    const pass = val('#sc-install-pass');
    const pass2 = val('#sc-install-pass2');
    const secretAlready = this.querySelector('#sc-install-secret-found')?.value === 'true';
    if (!secretAlready && !pass) { if (status) status.textContent = 'Bootstrap domain password is required before install apply.'; return; }
    if (pass || pass2) {
      if (pass.length < 12) { if (status) status.textContent = 'Bootstrap password must be at least 12 characters.'; return; }
      if (pass !== pass2) { if (status) status.textContent = 'Bootstrap password confirmation does not match.'; return; }
    }
    const base = foundationApiBase();
    const cfg = { spec: { parameters: { samba: {
      domain: val('#sc-install-domain') || 'OPENSPHERE.LOCAL',
      replicas: Number.isInteger(replicas) ? replicas : 1,
      storageClass: val('#sc-install-sc') || 'standard',
      dnsForwarder: val('#sc-install-dns') || '8.8.8.8',
    } } } };
    if (status) status.textContent = 'Saving install inputs...';
    try {
      const fm = await fetch(`${base}/api/k8s/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/merge-patch+json', 'x-os-id-token': idt },
        body: JSON.stringify(cfg),
      });
      if (!fm.ok) {
        const t = await fm.text().catch(() => '');
        if (isAuthFail(fm.status, t)) { sessionExpiredMsg(status); return; }
        if (status) status.textContent = `Config save failed HTTP ${fm.status}: ${t.slice(0, 120)}`;
        return;
      }
      if (pass) {
        const secret = {
          apiVersion: 'v1',
          kind: 'Secret',
          metadata: { name: 'foundation-identity-samba-creds', namespace: 'opensphere-foundation', labels: { 'opensphere.io/plugin': 'samba-ad', 'opensphere.io/managed-by': 'foundation' } },
          type: 'Opaque',
          stringData: { 'domain-password': pass },
        };
        const sr = await this._ensureCR(base, idt, 'api/v1/namespaces/opensphere-foundation', 'secrets', 'foundation-identity-samba-creds', secret);
        if (!sr.ok) {
          if (isAuthFail(sr.status, sr.body)) { sessionExpiredMsg(status); return; }
          if (status) status.textContent = `Bootstrap Secret save failed HTTP ${sr.status}: ${(sr.body || '').slice(0, 120)}`;
          return;
        }
      }
      if (status) status.textContent = 'Install inputs saved. Rechecking gate...';
      setTimeout(() => this._load(), 1200);
    } catch (e) { if (status) status.textContent = `Install input save failed: ${esc(e)}`; }
  }

  async _startInstall() {
    const status = this.querySelector('#sc-install-status');
    if (tokenExpired()) { sessionExpiredMsg(status); return; }
    const idt = osIdToken();
    const val = (id) => (this.querySelector(id)?.value ?? '').trim();
    const replicas = parseInt(val('#sc-install-replicas'), 10);
    const body = { spec: { desiredState: 'Installed', parameters: {
      engines: { samba: 'enabled' },
      samba: {
        domain: val('#sc-install-domain') || 'OPENSPHERE.LOCAL',
        replicas: Number.isInteger(replicas) ? replicas : 1,
        storageClass: val('#sc-install-sc') || 'standard',
        dnsForwarder: val('#sc-install-dns') || '8.8.8.8',
      },
    } } };
    if (status) status.textContent = 'Starting install process...';
    try {
      const res = await fetch(`${foundationApiBase()}/api/k8s/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/merge-patch+json', 'x-os-id-token': idt },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const t = await res.text().catch(() => '');
        if (isAuthFail(res.status, t)) { sessionExpiredMsg(status); return; }
        if (status) status.textContent = `Install start failed HTTP ${res.status}: ${t.slice(0, 120)}`;
        return;
      }
      if (status) status.textContent = 'Install requested. Foundation control-plane is reconciling Samba-AD.';
      setTimeout(() => this._load(), 1500);
    } catch (e) { if (status) status.textContent = `Install start failed: ${esc(e)}`; }
  }

  async _saveConfig() {
    const status = this.querySelector('#sc-cfg-status');
    if (tokenExpired()) { sessionExpiredMsg(status); return; }
    const idt = osIdToken();
    const val = (id) => (this.querySelector(id)?.value ?? '').trim();
    const replicas = parseInt(val('#sc-cfg-replicas'), 10);
    const body = { spec: { parameters: { samba: {
      domain: val('#sc-cfg-domain') || 'OPENSPHERE.LOCAL',
      replicas: Number.isInteger(replicas) ? replicas : 1,
      storageClass: val('#sc-cfg-sc') || 'standard',
      dnsForwarder: val('#sc-cfg-dns') || '8.8.8.8',
    } } } };
    if (status) status.textContent = '저장 중…';
    try {
      const res = await fetch(`${foundationApiBase()}/api/k8s/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/merge-patch+json', 'x-os-id-token': idt },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const t = await res.text().catch(() => '');
        if (isAuthFail(res.status, t)) { sessionExpiredMsg(status); return; }
        if (status) status.textContent = `저장 실패 HTTP ${res.status}${res.status === 403 ? ' (권한 없음 — foundation-models-manage)' : ''}: ${t.slice(0, 120)}`;
        return;
      }
      if (status) status.textContent = '저장됨 — control-plane이 재조정하며 operand를 재렌더합니다(도메인/replicas 변경 시 pod 재기동).';
      setTimeout(() => this._load().then(() => this._loadCharts()), 2000);
    } catch (e) { if (status) status.textContent = `저장 실패: ${esc(e)}`; }
  }

  // StorageClass 드롭다운 — 클러스터 실 목록(기본 SC 표시). 목록 조회 실패 시 현재값만 담은 select로 폴백.
  _scSelect(d) {
    const cur = (d.config || {}).storageClass || '';
    const list = (d.storageClasses || []);
    const names = list.map((s) => s.name);
    const opts = (names.length ? names : (cur ? [cur] : [])).map((n) => {
      const sc = list.find((s) => s.name === n);
      const label = n + (sc && sc.isDefault ? ' (default)' : '');
      return `<option value="${esc(n)}"${n === cur ? ' selected' : ''}>${esc(label)}</option>`;
    }).join('');
    return `<select id="sc-cfg-sc" class="os-filter">${opts || `<option value="${esc(cur)}" selected>${esc(cur || '—')}</option>`}</select>`;
  }

  stage() {
    try {
      const parts = location.pathname.split('/').filter(Boolean);
      const i = parts.indexOf('samba');
      const s = i >= 0 ? parts[i + 1] : '';
      return s === 'preflight' || s === 'install' || s === 'manage' ? s : 'auto';
    } catch { return 'auto'; }
  }

  stagePath(stage) {
    const suffix = stage === 'preflight' ? '' : `/${stage}`;
    return `/p/foundation/samba${suffix}${location.search}${location.hash}`;
  }

  manageTab() {
    try {
      const parts = location.pathname.split('/').filter(Boolean);
      const i = parts.indexOf('samba');
      const t = i >= 0 && parts[i + 1] === 'manage' ? (parts[i + 2] || '') : '';
      return ['overview', 'config', 'backup', 'metrics', 'logs', 'events'].includes(t) ? t : 'overview';
    } catch { return 'overview'; }
  }

  managePath(tab) {
    return `/p/foundation/samba/manage/${tab}${location.search}${location.hash}`;
  }

  manageNav(active) {
    const tabs = [
      ['overview', 'Overview'], ['config', 'Config'], ['backup', 'Backup'],
      ['metrics', 'Metrics'], ['logs', 'Logs'], ['events', 'Events'],
    ];
    return `<nav class="subnav" aria-label="Samba-AD manage sections">
      <ul class="nav" role="tablist">${tabs.map(([id, label]) => `
        <li class="nav-item" role="presentation"><a href="${esc(this.managePath(id))}" class="nav-link ${active === id ? 'active' : ''}" role="tab" aria-selected="${active === id ? 'true' : 'false'}" data-sc-tab="${esc(id)}">${esc(label)}</a></li>`).join('')}</ul>
    </nav>`;
  }
  lifecycleStage(pf) {
    const state = pf?.installState || 'Blocked';
    if (state === 'Installed') return 'manage';
    if (state === 'ReadyToApply' || state === 'Deploying') return 'install';
    return 'preflight';
  }

  _bindLifecycleActions() {
    this.querySelectorAll('[data-sc-action]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        const stage = el.getAttribute('data-sc-action') || 'preflight';
        history.pushState(history.state, '', this.stagePath(stage));
        this._load().then(() => this._afterRenderLoads());
      });
    });
    this.querySelectorAll('[data-sc-tab]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        history.pushState(history.state, '', this.managePath(el.getAttribute('data-sc-tab') || 'overview'));
        this._load().then(() => this._afterRenderLoads());
      });
    });
  }

  lifecycleBadge(pf) {
    const state = pf?.installState || 'Unknown';
    const cls = state === 'Installed' ? 'label-success'
      : (state === 'Blocked' ? 'label-danger' : 'label-info');
    return `<span class="label ${cls}">${esc(state)}</span>`;
  }

  foundationProcess(d) {
    const pf = d.preflight || {};
    const has = (id) => (pf.checks || []).find((c) => c.id === id);
    const pluginApi = has('plugin-api');
    const model = has('foundation-model');
    const rows = [
      ['Plugin package', pluginApi?.state || 'info', pluginApi?.message || 'UIPluginPackage signature, manifest, and backend route are verified by Foundation.'],
      ['Manual registration', 'pass', 'manual:contribute registers Samba-AD operating manual into the Manual Registry during plugin activation.'],
      ['Metrics registration', 'pass', 'ServiceMonitor and /metrics expose Samba-AD health, LDAP reachability, replicas, and restart signals.'],
      ['CLI registration', 'pass', 'cli.namespace=ad exposes os ad preflight/status/describe/events through the plugin CLI manifest.'],
      ['Log registration', 'pass', '/api/logs binds the manage Logs section to the central Loki path for Samba-AD pod stdout.'],
      ['Operand declaration', has('operand-render')?.state || 'info', has('operand-render')?.message || '/operand/manifests declares PVC, Service, Deployment, and NetworkPolicy.'],
      ['Foundation model gate', model?.state || 'info', model?.message || 'FoundationModel/identity is the lifecycle source of truth.'],
    ];
    const cls = (state) => ({ pass: 'label-success', warn: 'label-warning', fail: 'label-danger', info: 'label-info' }[state] || 'label-info');
    return `<table class="table"><thead><tr><th>Foundation process</th><th>Status</th><th>Evidence</th></tr></thead>
      <tbody>${rows.map(([name, state, detail]) => `<tr><td>${esc(name)}</td><td><span class="label ${cls(state)}">${esc(String(state).toUpperCase())}</span></td><td>${esc(detail)}</td></tr>`).join('')}</tbody></table>`;
  }

  preflight(d) {
    const pf = d.preflight || { checks: [], installState: 'Unknown', blockers: 0, warnings: 0 };
    const cls = (state) => ({
      pass: 'label-success',
      warn: 'label-warning',
      fail: 'label-danger',
      info: 'label-info',
    }[state] || '');
    const label = (state) => ({
      pass: 'PASS',
      warn: 'WARN',
      fail: 'BLOCK',
      info: 'INFO',
    }[state] || esc(state));
    const blockers = (pf.checks || []).filter((c) => c.state === 'fail');
    const blockerHtml = blockers.map((c) => {
      const ex = explainBlocker(c);
      return `
        <div style="margin-top:.5rem;">
          <span class="label label-danger">BLOCK</span>
          <strong style="margin-left:.35rem;">${esc(ex.title)}</strong>
          <div class="os-sub" style="margin-top:.35rem;"><strong>문제</strong> ${esc(ex.problem)}</div>
          <div class="os-sub"><strong>영향</strong> ${esc(ex.impact)}</div>
          <div class="os-sub"><strong>해결</strong> ${esc(ex.fix)}</div>
        </div>`;
    }).join('');
    const blockerSummary = blockers.length ? `
      <div style="margin:.5rem 0 1rem 0;padding:.65rem .75rem;border-left:3px solid #c21d00;background:#fff7f5;">
        <div style="font-weight:600;margin-bottom:.35rem;">설치를 진행할 수 없는 이유 ${esc(blockers.length)}건</div>
        ${blockerHtml}
      </div>` : '';
    const rows = (pf.checks || []).map((c) => `
      <tr>
        <td>${esc(c.label)}</td>
        <td><span class="label ${cls(c.state)}">${label(c.state)}</span></td>
        <td>${esc(c.message)}</td>
      </tr>`).join('');
    const banner = pf.installState === 'ReadyToApply'
      ? '<div class="alert alert-success"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Preflight passed. Foundation control-plane can apply /operand/manifests to deploy the Samba-AD operand.</span></div></div></div>'
      : pf.installState === 'AwaitingInstall'
        ? '<div class="alert alert-success"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Preflight passed. Continue to Install to confirm inputs and start the lifecycle transition.</span></div></div></div>'
        : pf.installState === 'AwaitingInput'
          ? '<div class="alert alert-warning"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Preflight passed, but install inputs are still required before apply.</span></div></div></div>'
      : pf.installState === 'Blocked'
        ? `<div class="alert alert-danger"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Samba-AD 설치 전 필수 조건이 충족되지 않았습니다. 아래의 문제와 해결 방법을 확인하세요.</span></div></div></div>`
        : pf.installState === 'Deploying'
          ? '<div class="alert alert-warning"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Samba-AD operand exists but is still converging. Continue watching workload, events, metrics, and logs below.</span></div></div></div>'
          : '<div class="alert alert-info"><div class="alert-items"><div class="alert-item static"><span class="alert-text">Samba-AD operand is installed. This preflight section remains as the operational baseline for drift and prerequisite checks.</span></div></div></div>';
    return `
      <div class="os-sech">Preflight <span class="os-sub">Samba-AD operand day-0 readiness</span></div>
      <div class="card"><div class="card-block">
        ${banner}
        ${blockerSummary}
        <table class="table"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="3">No preflight checks returned.</td></tr>'}</tbody></table>
        <p class="os-sub">state=${esc(pf.installState)} · blockers=${esc(pf.blockers)} · warnings=${esc(pf.warnings)} · mode=${esc(pf.mode || 'unknown')}</p>
      </div></div>`;
  }

  renderPreflight(d) {
    const pf = d.preflight || {};
    const next = pf.blockers === 0
      ? '<button class="btn btn-primary btn-sm" data-sc-action="install">Continue to Install inputs</button>'
      : '<button class="btn btn-primary btn-sm" disabled>Resolve BLOCK items first</button>';
    this.innerHTML = `
      <div class="os-title-row"><h2 class="os-h2">${sambaLogo()}Samba-AD Preflight ${this.lifecycleBadge(pf)}</h2></div>
      <p class="os-sub">Foundation validates the plugin package and the installation process before the Samba-AD operand is created.</p>
      ${this.preflight(d)}
      <div class="card"><div class="card-header">Foundation installation process</div><div class="card-block">
        ${this.foundationProcess(d)}
      </div></div>
      <div class="card"><div class="card-block">
        <h3 class="card-title">Next</h3>
        <p class="os-sub">When all blocking checks pass, the admin continues to the install wizard. Preflight is not a manage page; it exists only before the operand lifecycle advances.</p>
        <div class="os-actions">${next}</div>
      </div></div>`;
  }
  renderInstall(d) {
    const pf = d.preflight || {};
    const installed = pf.installState === 'Installed';
    const secret = d.bootstrapSecret || {};
    const canApply = !!pf.readyToApply;
    const scInstall = this._scSelect(d).replace('id="sc-cfg-sc"', 'id="sc-install-sc"');
    this.innerHTML = `
      <div class="os-title-row"><h2 class="os-h2">${sambaLogo()}Samba-AD Install <span class="label label-info">Day-1</span></h2></div>
      <p class="os-sub">Preflight 이후 Samba-AD operand 선언을 control-plane이 적용하는 설치 단계입니다.</p>
      <div class="alert ${installed ? 'alert-info' : (pf.blockers === 0 ? 'alert-success' : 'alert-danger')}"><div class="alert-items">
        <div class="alert-item static"><span class="alert-text">${installed
          ? 'Samba-AD operand는 이미 설치되어 있습니다. 설치 후 운영은 Manage 단계에서 확인하세요.'
          : (pf.blockers === 0
            ? 'Install gate is open. Confirm inputs, then start install to enable Samba-AD and let the control-plane apply /operand/manifests.'
            : 'Install gate is blocked. Return to Preflight and resolve BLOCK items first.')}</span></div>
      </div></div>
      <div class="clr-row">
        ${this.card('Install gate', `
          <table class="table"><tbody>${this.kv([
            ['Preflight blockers', `<span class="label ${pf.blockers ? 'label-danger' : 'label-success'}">${esc(pf.blockers ?? '—')}</span>`],
            ['Install input blockers', `<span class="label ${pf.inputBlockers ? 'label-warning' : 'label-success'}">${esc(pf.inputBlockers ?? 0)}</span>`],
            ['Warnings', `<span class="label ${pf.warnings ? 'label-warning' : 'label-success'}">${esc(pf.warnings ?? '—')}</span>`],
            ['Bootstrap Secret', `<span class="label ${secret.found ? 'label-success' : 'label-warning'}">${secret.found ? 'Present' : 'Missing'}</span> <span class="os-mono">${esc(secret.name || 'foundation-identity-samba-creds')}/${esc(secret.key || 'domain-password')}</span>`],
            ['Operand declaration', '<span class="os-mono">GET /operand/manifests</span>'],
            ['Apply owner', 'Foundation control-plane (SSA)'],
            ['Apply gate', `<span class="label ${canApply ? 'label-success' : 'label-warning'}">${canApply ? 'ReadyToApply' : esc(pf.installState || 'Unknown')}</span>`],
          ])}</tbody></table>`) }
        ${this.card(installed ? 'Install completed' : 'Install inputs', installed ? `
          <p class="os-sub">Samba-AD is already installed. Lifecycle cannot move backward from Manage to Install. Use Manage for drift checks and operations.</p>
          <div class="os-actions"><button class="btn btn-sm btn-primary" data-sc-action="manage">Open Manage</button></div>`
          : `
          <input id="sc-install-secret-found" type="hidden" value="${secret.found ? 'true' : 'false'}">
          <div class="clr-row">
            <div class="clr-col-12 clr-col-md-6"><label class="os-sub">Directory realm<input id="sc-install-domain" class="os-filter" value="${esc((d.config || {}).domain)}"></label></div>
            <div class="clr-col-12 clr-col-md-6"><label class="os-sub">StorageClass${scInstall}</label></div>
            <div class="clr-col-12 clr-col-md-6"><label class="os-sub">DNS forwarder<input id="sc-install-dns" class="os-filter" value="${esc((d.config || {}).dnsForwarder)}"></label></div>
            <div class="clr-col-12 clr-col-md-6"><label class="os-sub">Replicas<input id="sc-install-replicas" class="os-filter" type="number" min="1" value="${esc((d.config || {}).replicas)}"></label></div>
            <div class="clr-col-12 clr-col-md-6"><label class="os-sub">Bootstrap domain password<input id="sc-install-pass" class="os-filter" type="password" autocomplete="new-password" placeholder="${secret.found ? 'leave blank to keep existing Secret' : 'required'}"></label></div>
            <div class="clr-col-12 clr-col-md-6"><label class="os-sub">Confirm password<input id="sc-install-pass2" class="os-filter" type="password" autocomplete="new-password"></label></div>
          </div>
          <p class="os-sub">Password is written only to Kubernetes Secret stringData and is never returned by the plugin API or operand manifest.</p>
          <div class="os-actions">
            <button id="sc-install-save" class="btn btn-sm btn-outline">Save install inputs</button>
            <button id="sc-install-start" class="btn btn-sm btn-primary"${pf.blockers || pf.inputBlockers ? ' disabled' : ''}>Start install</button>
          </div>
          <p id="sc-install-status" class="os-sub"></p>`) }
      </div>`;
  }

  kv(pairs) { return pairs.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join(''); }
  card(title, bodyHtml) {
    return `<div class="clr-col-12 clr-col-lg-6"><div class="card">
      <div class="card-header">${title}</div>
      <div class="card-block">${bodyHtml}</div>
    </div></div>`;
  }

  render(d) {
    const lifecycle = this.lifecycleStage(d.preflight);
    if (lifecycle === 'preflight') {
      const requested = this.stage();
      if (requested === 'install' && (d.preflight?.blockers || 0) === 0) {
        this.renderInstall(d);
        return;
      }
      this.renderPreflight(d);
      return;
    }
    if (lifecycle === 'install') { this.renderInstall(d); return; }

    const w = d.workload || {};
    const m = d.model || {};
    const bkc = d.backup || {};
    const ded = bkc.dedicated || {};
    const activeTab = this.manageTab();
    const phase = w.found ? (w.ready ? 'Running' : 'Starting') : 'Not deployed';
    const phasePill = w.found ? pill(w.ready, true) : 'label-warning';
    const realm = w.realmEnv || m.directoryRealm || '-';
    const baseDn = realm !== '-' ? 'DC=' + realm.split('.').join(',DC=') : '-';

    const notDeployed = !w.found ? `
      <div class="alert ${m.engineOpt === 'disabled' ? 'alert-warning' : 'alert-info'}"><div class="alert-items">
        <div class="alert-item static"><span class="alert-text">${m.engineOpt === 'disabled'
          ? 'Samba-AD engine is disabled. Start install from the Install stage to enable engines.samba and let the control-plane apply the operand.'
          : `Samba-AD workload is not deployed yet. FoundationModel phase: ${esc(m.phase)}`}</span></div>
      </div></div>` : '';

    const observedRows = (m.observed || []).map((o) => `
      <tr><td class="os-mono">${esc(o.id)}</td>
      <td><span class="label ${o.healthy ? 'label-success' : (o.value === 'n/a' ? '' : 'label-danger')}">${esc(o.value)}</span></td>
      <td>${esc(o.note || o.source)}</td></tr>`).join('');

    const eventRows = (d.events || []).map((e) => `
      <tr><td><span class="label ${e.type === 'Warning' ? 'label-warning' : ''}">${esc(e.type)}</span></td>
      <td class="os-mono">${esc(e.reason)}</td><td>${esc(e.message)}</td><td>${esc(e.time)}</td></tr>`).join('');

    const relationHtml = `<div class="card"><div class="card-header">Service relationship</div><div class="card-block">
      <div class="clr-row">
        <div class="clr-col-12 clr-col-md-4">
          <h4>Foundation identity model</h4>
          <p><span class="label ${m.phase === 'Installed' ? 'label-success' : 'label-warning'}">${esc(m.phase || 'Unknown')}</span></p>
          <p class="os-sub">Owns lifecycle, install parameters, and declared endpoint status.</p>
        </div>
        <div class="clr-col-12 clr-col-md-4">
          <h4>${sambaLogo(28)}Samba-AD directory</h4>
          <p><span class="label ${phasePill}">${esc(phase)}</span> ${w.found ? esc(`${w.readyReplicas}/${w.replicas} ready`) : ''}</p>
          <p class="os-sub"><span class="os-mono">${esc(m.ldapURL || '-')}</span></p>
        </div>
        <div class="clr-col-12 clr-col-md-4">
          <h4>Connected consumers</h4>
          <p><span class="label ${d.keycloak?.found ? pill(d.keycloak.ready, true) : 'label-warning'}">Keycloak ${d.keycloak?.ready ? 'ready' : 'pending'}</span></p>
          <p class="os-sub">User Federation reads LDAP from Samba-AD. Other consumers must bind through Foundation claims.</p>
        </div>
      </div>
    </div></div>`;

    const overviewHtml = `${notDeployed}${relationHtml}<div class="clr-row">
      ${this.card(`Directory workload <span class="os-mono">${esc('foundation-identity-samba')}</span>`, `
        <table class="table"><tbody>${this.kv([
          ['Status', `<span class="label ${phasePill}">${esc(phase)}</span> ${w.found ? esc(`${w.readyReplicas}/${w.replicas} ready`) : ''}`],
          ['Image', `<span class="os-mono">${esc(w.image)}</span>`],
          ['Node / Restarts', esc(`${w.node ?? '-'} / ${w.restarts ?? '-'}`)],
          ['Persistent data', `<span class="os-mono">PVC foundation-identity-samba-data</span>`],
        ])}</tbody></table>`)}
      ${this.card('Directory endpoints', `
        <table class="table"><tbody>${this.kv([
          ['LDAP', `<span class="os-mono">${esc(m.ldapURL)}</span>`],
          ['Base DN', `<span class="os-mono">${esc(baseDn)}</span>`],
          ['LDAPS / Kerberos', '<span class="os-mono">:636 / :88</span>'],
          ['DNS / SMB', '<span class="os-mono">:53(tcp/udp) / :445</span>'],
        ])}</tbody></table>`)}
      ${this.card(`FoundationModel/identity <span class="label ${m.phase === 'Installed' ? 'label-success' : 'label-warning'}">${esc(m.phase)}</span>`, m.found ? `
        <table class="table"><thead><tr><th>Signal</th><th>Value</th><th>Source</th></tr></thead><tbody>${observedRows || '<tr><td colspan="3">No observed signals.</td></tr>'}</tbody></table>
        <p class="os-sub">Observed at ${esc(m.observedAt)} / ${esc(m.controlPlane)}</p>` : '<p class="os-sub">FoundationModel/identity is not readable.</p>')}
      ${this.card('Consumer: Keycloak federation', `
        <table class="table"><tbody>${this.kv([
          ['Keycloak', `<span class="label ${d.keycloak?.found ? pill(d.keycloak.ready, true) : ''}">${d.keycloak?.found ? (d.keycloak.ready ? 'Running' : 'Starting') : 'Not deployed'}</span> <span class="os-mono">${esc(d.keycloak?.name)}</span>`],
          ['Binding', `User Federation -> LDAP(<span class="os-mono">${esc(m.ldapURL)}</span>)`],
        ])}</tbody></table>`)}
    </div>`;

    const configHtml = `<div class="os-sech">Configuration</div>
      <div class="clr-row">
        <div class="clr-col-12 clr-col-lg-8">
          <div class="card"><div class="card-header">Directory deployment parameters</div><div class="card-block">
            <div class="clr-row">
              <div class="clr-col-12 clr-col-md-6"><label class="os-sub">Realm<input id="sc-cfg-domain" class="os-filter" value="${esc((d.config || {}).domain)}"></label></div>
              <div class="clr-col-12 clr-col-md-3"><label class="os-sub">Replicas<input id="sc-cfg-replicas" class="os-filter" type="number" min="1" value="${esc((d.config || {}).replicas)}"></label></div>
              <div class="clr-col-12 clr-col-md-3"><label class="os-sub">DNS forwarder<input id="sc-cfg-dns" class="os-filter" value="${esc((d.config || {}).dnsForwarder)}"></label></div>
              <div class="clr-col-12 clr-col-md-6"><label class="os-sub">StorageClass${this._scSelect(d)}</label></div>
              <div class="clr-col-12 clr-col-md-6" style="display:flex; align-items:flex-end; gap:.5rem;">
                <button id="sc-cfg-save" class="btn btn-primary btn-sm" style="margin:0;">Apply</button>
                <span id="sc-cfg-status" class="os-sub"></span>
              </div>
            </div>
          </div></div>
        </div>
        <div class="clr-col-12 clr-col-lg-4">
          <div class="card"><div class="card-header">Control boundary</div><div class="card-block">
            <table class="table table-compact"><tbody>${this.kv([
              ['Source', '<span class="os-mono">FoundationModel/identity</span>'],
              ['Path', '<span class="os-mono">spec.parameters.samba</span>'],
              ['Directory objects', 'Managed outside this page'],
            ])}</tbody></table>
            <p class="os-sub">Replica and network changes are reconciled by the control-plane. Users, groups, and policies belong to AD tools such as samba-tool or RSAT.</p>
          </div></div>
        </div>
      </div>`;

    const backupHtml = `<div class="os-sech">Backup <span class="os-sub">Velero schedule and restore substrate</span></div>
      <div class="card"><div class="card-block">
        <div id="sc-backup"><p class="os-sub">Loading backup status...</p></div>
        <div class="clr-row">
          <div class="clr-col-12 clr-col-md-4"><label class="os-sub">Backup target<select id="sc-bk-mode" class="os-filter">
            <option value="shared"${bkc.mode !== 'dedicated' ? ' selected' : ''}>Shared default BSL</option>
            <option value="dedicated"${bkc.mode === 'dedicated' ? ' selected' : ''}>Dedicated samba-ad BSL</option>
          </select></label></div>
          <div class="clr-col-12 clr-col-md-4"><label class="os-sub">Schedule (cron)<input id="sc-bk-cron" class="os-filter" value="${esc(bkc.schedule || '0 2 * * *')}"></label></div>
          <div class="clr-col-12 clr-col-md-4 os-actions"><button id="sc-bk-save" class="btn btn-primary btn-sm">Enable backup</button><button id="sc-bk-now" class="btn btn-outline btn-sm">Backup now</button></div>
        </div>
        <div id="sc-bk-dedicated" class="clr-row"${bkc.mode === 'dedicated' ? '' : ' hidden'}>
          <div class="clr-col-12 clr-col-md-3"><label class="os-sub">S3 URL<input id="sc-bk-ep" class="os-filter" value="${esc(ded.endpoint || '')}" placeholder="https://s3.example.com"></label></div>
          <div class="clr-col-12 clr-col-md-3"><label class="os-sub">Bucket<input id="sc-bk-bucket" class="os-filter" value="${esc(ded.bucket || '')}" placeholder="samba-ad-backup"></label></div>
          <div class="clr-col-12 clr-col-md-2"><label class="os-sub">Region<input id="sc-bk-region" class="os-filter" value="${esc(ded.region || '')}" placeholder="us-east-1"></label></div>
          <div class="clr-col-12 clr-col-md-2"><label class="os-sub">Access Key<input id="sc-bk-ak" class="os-filter" autocomplete="off"></label></div>
          <div class="clr-col-12 clr-col-md-2"><label class="os-sub">Secret Key<input id="sc-bk-sk" class="os-filter" type="password" autocomplete="off"></label></div>
        </div>
        <p id="sc-bk-status" class="os-sub"></p>
      </div></div>`;

    const metricsHtml = `<div id="sc-metrics"><div class="os-sech">Metrics</div><p class="os-sub">Loading metrics...</p></div>`;
    const logsHtml = `<div class="os-sech">Logs <span class="os-sub">Loki / samba pod stdout / last 60 minutes</span></div><div id="sc-logs" class="vl-log"><div class="vl-log-empty">Loading logs...</div></div>`;
    const eventsHtml = `<div class="os-sech">Events <span class="os-sub">Kubernetes events</span></div>${eventRows ? `<table class="table"><thead><tr><th>Type</th><th>Reason</th><th>Message</th><th>Time</th></tr></thead><tbody>${eventRows}</tbody></table>` : '<p class="os-sub">No recent events.</p>'}`;

    const content = { overview: overviewHtml, config: configHtml, backup: backupHtml, metrics: metricsHtml, logs: logsHtml, events: eventsHtml }[activeTab] || overviewHtml;

    this.innerHTML = `
      <div class="os-title-row"><h2 class="os-h2">${sambaLogo()}Samba-AD <span class="label label-info">plugin</span> <span class="label ${phasePill}">${esc(phase)}</span></h2></div>
      <p class="os-sub">Workforce directory / Samba Active Directory DC / realm ${esc(realm)} / ns ${esc(d.meta?.ns)} / served by ${esc(d.meta?.servedBy)}</p>
      ${this.manageNav(activeTab)}
      ${content}`;
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
      '- 첫 기동 시 컨테이너(nowsci/samba-domain GHCR 미러)가 도메인을 자동 프로비저닝(`DOMAIN` env, dev 기본 OPENSPHERE.LOCAL).',
      '- `DOMAINPASS`는 평문 env가 아니라 **Foundation 소유 Secret**(`foundation-identity-samba-creds`)을 `secretKeyRef`로 받는다 — 비밀번호는 소스/manifest/응답에 노출되지 않는다(secret 권위=Foundation).',
      '- 스토리지: PVC 3Gi — StorageClass는 `FoundationModel.spec.parameters.hostRequirements.storageClass`로 오버라이드(기본 standard).',
      '- 단일 DC(replicas 1, Recreate) — pod IP 변경 시 DNS 자기등록 특성의 dev 수용.',
      '',
      '## Preflight',
      '- Preflight/Install/Manage는 사용자가 임의로 오가는 탭이 아니라 Samba-AD operand lifecycle 상태다. 기본 `/p/foundation/samba` 진입은 현재 lifecycle 상태로 해석한다.',
      '- 설치 완료 후에는 Install로 역진하지 않는다. 과거 단계 URL을 열어도 상태 확인 또는 현재 Manage 단계로 유도하는 용도이며, 운영 조작은 Manage에서 수행한다.',
      '- Preflight는 plugin 이미지 배포 전 점검이 아니라, plugin 컨테이너가 뜬 뒤 Samba-AD operand 배포 전에 수행하는 day-0 점검이다.',
      '- UI 상단 Preflight 섹션과 `os ad preflight`가 같은 판정 모델을 사용한다.',
      '- BLOCK 항목이 0개이면 Install 단계로 진행하여 realm, StorageClass, DNS forwarder, replicas, Bootstrap domain password를 확정한다.',
      '- Bootstrap domain password는 `foundation-identity-samba-creds/domain-password` Secret으로만 저장하며 plugin API와 `/operand/manifests` 응답에는 절대 평문으로 반환하지 않는다.',
      '- Install 입력과 Bootstrap Secret이 준비되면 control-plane은 `/operand/manifests`를 SSA apply하여 PVC/Service/Deployment/NetworkPolicy를 배포할 수 있다.',
      '- 이미 operand가 설치된 경우 Preflight는 `Installed/manage` 모드로 남아 FoundationModel, engines.samba, StorageClass, realm, Keycloak, workload drift를 계속 확인한다.',
      '- dev/bootstrap 보안 프로필(`privileged`, `INSECURELDAP`, `NOCOMPLEXITY`)은 WARN으로 유지한다. production hardening은 별도 단계에서 제거해야 한다.',
      '',
      '## 백업(Velero 중앙 등록)',
      '- 백업 엔진은 Velero(BSS). 백업 대상은 외부 S3 호환 서비스이며 사용자가 구성한다 — 클러스터 내부 저장소에 의존하지 않는다.',
      '- 공용 기본: `BSS → Velero` 페이지에서 외부 S3(default BSL)를 구성. 여러 plugin이 공유.',
      '- 전용 override: 이 화면 "백업" 섹션에서 samba-ad 전용 외부 대상(samba-ad BSL)을 별도 구성 가능.',
      '- 등록 실체 = `velero.io/Schedule` `samba-ad`(ns velero) — samba pod(app=foundation-identity-samba) + PVC를 node-agent 파일시스템 백업으로 담는다. "지금 백업"은 일회성 `Backup` CR.',
      '- 쓰기 경로: 콘솔 사용자 임퍼소네이션(foundation 프록시) — plugin SA엔 velero 권한을 주지 않는다(최소권한).',
      '',
      '## 사용권·연결 (Claim/Binding — ADR-005R1)',
      '- Samba-AD의 **사용권/연결권은 Foundation Claim/Binding으로 얻는다** — bind credential을 직접 공유받지 않는다.',
      '- 소비 모듈은 `FoundationBinding`/typed Binding의 `endpointRef`·`secretRef`·`policyRef`로 접속 좌표와 자격을 받는다.',
      '- 모든 설치/변경/secret 발급은 **선언형 write-path(ADR-005R1: gitops|operator|crossplane 중 택1)**로 Foundation control-plane이 처리한다. plugin은 요청(Claim)·표면(UI/상태/manual/CLI/metrics/operand 선언)만 소유한다.',
      '- secret 권위 = Foundation/controller. **plugin API는 평문 secret을 반환하지 않는다**(도메인 비밀번호는 secretKeyRef로만). OAA도 secret 값을 설명·노출하지 않는다.',
      '- OAA는 Claim proposal을 작성할 수 있으나 **apply는 사용자 승인 + Foundation 권한**을 거친다.',
      '- consumer가 존재하는 동안 binding finalizer가 operand 회수를 차단한다(도입 예정).',
      '',
      '## 경계(하지 않는 것)',
      '- 콘솔은 디렉터리 내용(사용자·그룹)을 명령형으로 조작하지 않는다(ADR-FND-001). samba-tool/RSAT 사용.',
      '- plugin backend는 secret/password를 직접 만들거나 저장하지 않는다(Foundation control-plane/adapter 소관).',
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
