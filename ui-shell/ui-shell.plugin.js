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

function esc(v) {
  return String(v ?? '—').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function pill(ok, warnWhenFalse) {
  return ok ? 'label-success' : (warnWhenFalse ? 'label-warning' : 'label-danger');
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
    this._load().then(() => { this._loadCharts(); this._loadLogs(); this._loadBackup(); });
    this._timer = setInterval(() => this._load().then(() => { this._loadCharts(); this._loadLogs(); this._loadBackup(); }), 15000);
  }
  disconnectedCallback() { if (this._timer) { clearInterval(this._timer); this._timer = null; } }

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
      { q: 'samba_ad_up{plugin="samba-ad"}', label: 'DC up (1/0)', color: '#2e8b57' },
      { q: 'samba_ad_ldap_reachable{plugin="samba-ad"}', label: 'LDAP :389 reachable', color: '#4c6fff' },
      { q: 'samba_ad_replicas_ready{plugin="samba-ad"}', label: 'Replicas ready', color: '#8b5cf6' },
      { q: 'samba_ad_restarts_total{plugin="samba-ad"}', label: 'Restarts', color: '#e11d48' },
    ];
    try {
      const results = await Promise.all(series.map((s) =>
        fetch(`${API_BASE}/api/metrics/range?q=${encodeURIComponent(s.q)}&minutes=30`, { cache: 'no-store' })
          .then((r) => r.ok ? r.json() : null).catch(() => null)));
      const cards = results.map((res, i) => {
        const s = series[i];
        const pts = res?.data?.result?.[0]?.values;
        const cur = pts && pts.length ? pts[pts.length - 1][1] : '—';
        return `<div class="clr-col-12 clr-col-md-6 clr-col-lg-3"><div class="card"><div class="card-block">
          <div class="os-sub">${esc(s.label)}</div>
          <p class="p2"><strong>${esc(cur)}</strong></p>
          ${sparkline(pts, 280, 44, s.color)}
          <div class="os-sub">최근 30분</div>
        </div></div></div>`;
      }).join('');
      const anyData = results.some((r) => r?.data?.result?.[0]?.values?.length);
      host.innerHTML = `<div class="os-sech">메트릭 <span class="os-sub">kube-prometheus-stack · 30분</span></div>
        ${anyData ? `<div class="clr-row">${cards}</div>`
          : '<p class="os-sub">아직 시계열이 없습니다 — ServiceMonitor 스크레이프 누적을 기다리는 중이거나 Prometheus 연결을 확인하세요.</p>'}`;
    } catch (e) {
      host.innerHTML = `<div class="os-sech">메트릭</div><p class="os-sub">차트 조회 실패: ${esc(e)}</p>`;
    }
  }

  // 백업(Velero) 실 상태 — Schedule/Backup(velero.io, ns velero)을 foundation 프록시(사용자 임퍼소네이션)로 조회.
  // plugin SA엔 velero 권한 없음 — velero 페이지 install()과 동형 write-path(콘솔 사용자 RBAC).
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
    const idt = osIdToken();
    if (!idt) { if (status) status.textContent = '로그인 토큰 없음 — 저장 불가(콘솔 재로그인 필요).'; return; }
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
        if (!sRes.ok) { if (status) status.textContent = `전용 자격증명 저장 실패 HTTP ${sRes.status}: ${(sRes.body || '').slice(0, 120)}`; return; }
        const bsl = { apiVersion: 'velero.io/v1', kind: 'BackupStorageLocation', metadata: { name: 'samba-ad', namespace: 'velero', labels: { 'opensphere.io/plugin': 'samba-ad' } },
          spec: { provider: 'aws', objectStorage: { bucket }, credential: { name: 'samba-ad-backup-creds', key: 'cloud' }, config: { region, s3Url: ep, s3ForcePathStyle: 'true' } } };
        const bRes = await this._ensureCR(base, idt, 'apis/velero.io/v1/namespaces/velero', 'backupstoragelocations', 'samba-ad', bsl);
        if (!bRes.ok) { if (status) status.textContent = `전용 저장위치(BSL) 생성 실패 HTTP ${bRes.status}: ${(bRes.body || '').slice(0, 120)}`; return; }
      }
      const sched = { apiVersion: 'velero.io/v1', kind: 'Schedule', metadata: { name: 'samba-ad', namespace: 'velero', labels: { 'opensphere.io/plugin': 'samba-ad' } },
        spec: { schedule, template: { includedNamespaces: ['opensphere-foundation'], labelSelector: { matchLabels: { app: 'foundation-identity-samba' } }, defaultVolumesToFsBackup: true, storageLocation: bslName, ttl: '720h0m0s' } } };
      const scRes = await this._ensureCR(base, idt, 'apis/velero.io/v1/namespaces/velero', 'schedules', 'samba-ad', sched);
      if (!scRes.ok) { if (status) status.textContent = `일정 등록 실패 HTTP ${scRes.status}${scRes.status === 403 ? ' (권한 없음 — velero 네임스페이스 쓰기 필요)' : ''}: ${(scRes.body || '').slice(0, 120)}`; return; }
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
    const idt = osIdToken();
    if (!idt) { if (status) status.textContent = '로그인 토큰 없음 — 실행 불가.'; return; }
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
      if (!r.ok) { const t = await r.text().catch(() => ''); if (status) status.textContent = `백업 요청 실패 HTTP ${r.status}: ${t.slice(0, 120)}`; return; }
      if (status) status.textContent = `백업 요청됨(${name}) — 진행 상태는 아래 표에서 갱신됩니다.`;
      setTimeout(() => this._loadBackup(), 1500);
    } catch (e) { if (status) status.textContent = `백업 요청 실패: ${esc(e)}`; }
  }

  async _load() {
    try {
      const res = await fetch(`${API_BASE}/api/samba`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`samba: HTTP ${res.status}`);
      this.render(await res.json());
      const btn = this.querySelector('#sc-cfg-save');
      if (btn) btn.onclick = () => this._saveConfig();
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
  async _saveConfig() {
    const status = this.querySelector('#sc-cfg-status');
    const idt = osIdToken();
    if (!idt) { if (status) status.textContent = '로그인 토큰 없음 — 저장 불가(콘솔 재로그인 필요).'; return; }
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
    const bkc = d.backup || {};
    const ded = bkc.dedicated || {};
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
      <div class="os-title-row"><h2 class="os-h2">Samba-AD <span class="label label-info">plugin</span> <span class="label ${phasePill}">${esc(phase)}</span></h2></div>
      <p class="os-sub">workspace/사원 디렉터리 · Samba Active Directory DC · realm ${esc(realm)} · ns ${esc(d.meta?.ns)}
        · <strong>독립 서명 plugin(OpenSphere-plugin-samba-ad) — 기능 컨테이너 ${esc(d.meta?.servedBy)}가 서빙, Foundation(host)이 안층 마운트</strong></p>
      ${notDeployed}
      <div class="clr-row">
        ${this.card(`디렉터리 실물 <span class="os-mono">${esc('foundation-identity-samba')}</span>`, `
          <table class="table"><tbody>${this.kv([
            ['상태', `<span class="label ${phasePill}">${esc(phase)}</span> ${w.found ? esc(`${w.readyReplicas}/${w.replicas} ready`) : ''}`],
            ['이미지', `<span class="os-mono">${esc(w.image)}</span>`],
            ['Node / 재시작', esc(`${w.node ?? '—'} / ${w.restarts ?? '—'}`)],
            ['데이터', `<span class="os-mono">PVC foundation-identity-samba-data</span> (SAM DB — 회수 시에도 보존)`],
          ])}</tbody></table>`)}
        ${this.card('연결 — 상위 서비스 소비점', `
          <table class="table"><tbody>${this.kv([
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
          <table class="table"><tbody>${this.kv([
            ['Keycloak', `<span class="label ${d.keycloak?.found ? pill(d.keycloak.ready, true) : ''}">${d.keycloak?.found ? (d.keycloak.ready ? 'Running' : '기동 중') : '미배포'}</span> <span class="os-mono">${esc(d.keycloak?.name)}</span>`],
            ['연동', `User Federation → 이 LDAP(<span class="os-mono">${esc(m.ldapURL)}</span>)`],
          ])}</tbody></table>
          <p class="os-sub">Keycloak(identity.iam.workspace)이 이 디렉터리를 federation해 사원 로그인을 제공.</p>`)}
      </div>
      <div class="os-sech">도메인 · 설정 <span class="os-sub">FoundationModel/identity · parameters.samba (선언형 write-path)</span></div>
      <div class="card"><div class="card-block"><div class="clr-row">
        <div class="clr-col-12 clr-col-md-6 clr-col-lg-3"><label class="os-sub">도메인(realm)<input id="sc-cfg-domain" class="os-filter" value="${esc((d.config || {}).domain)}"></label></div>
        <div class="clr-col-12 clr-col-md-6 clr-col-lg-2"><label class="os-sub">replicas<input id="sc-cfg-replicas" class="os-filter" type="number" min="1" value="${esc((d.config || {}).replicas)}"></label></div>
        <div class="clr-col-12 clr-col-md-6 clr-col-lg-3"><label class="os-sub">StorageClass${this._scSelect(d)}</label></div>
        <div class="clr-col-12 clr-col-md-6 clr-col-lg-2"><label class="os-sub">DNS forwarder<input id="sc-cfg-dns" class="os-filter" value="${esc((d.config || {}).dnsForwarder)}"></label></div>
        <div class="clr-col-12 clr-col-lg-2 os-actions"><button id="sc-cfg-save" class="btn btn-primary btn-sm">적용</button></div>
      </div><p id="sc-cfg-status" class="os-sub"></p>
      <p class="os-sub">⚠️ 도메인/replicas 변경은 control-plane 재조정 시 operand 재렌더 → pod 재기동을 유발합니다(PVC=SAM DB는 보존). 사용자·그룹은 samba-tool.</p>
      </div></div>
      <div class="os-sech">백업 <span class="os-sub">Velero · 중앙 백업 등록 · 공용 기본 + 전용 override</span></div>
      <div class="card"><div class="card-block">
        <div id="sc-backup"><p class="os-sub">백업 상태 로딩…</p></div>
        <div class="clr-row">
          <div class="clr-col-12 clr-col-md-4"><label class="os-sub">백업 대상<select id="sc-bk-mode" class="os-filter">
            <option value="shared"${bkc.mode !== 'dedicated' ? ' selected' : ''}>공용 기본 (Velero default BSL)</option>
            <option value="dedicated"${bkc.mode === 'dedicated' ? ' selected' : ''}>전용 외부 대상 (samba-ad BSL)</option>
          </select></label></div>
          <div class="clr-col-12 clr-col-md-4"><label class="os-sub">일정 (cron)<input id="sc-bk-cron" class="os-filter" value="${esc(bkc.schedule || '0 2 * * *')}"></label></div>
          <div class="clr-col-12 clr-col-md-4 os-actions">
            <button id="sc-bk-save" class="btn btn-primary btn-sm">백업 활성화·저장</button>
            <button id="sc-bk-now" class="btn btn-outline btn-sm">지금 백업</button>
          </div>
        </div>
        <div id="sc-bk-dedicated" class="clr-row"${bkc.mode === 'dedicated' ? '' : ' hidden'}>
          <div class="clr-col-12 clr-col-md-3"><label class="os-sub">엔드포인트(s3Url)<input id="sc-bk-ep" class="os-filter" value="${esc(ded.endpoint || '')}" placeholder="https://s3.example.com"></label></div>
          <div class="clr-col-12 clr-col-md-3"><label class="os-sub">버킷<input id="sc-bk-bucket" class="os-filter" value="${esc(ded.bucket || '')}" placeholder="samba-ad-backup"></label></div>
          <div class="clr-col-12 clr-col-md-2"><label class="os-sub">리전<input id="sc-bk-region" class="os-filter" value="${esc(ded.region || '')}" placeholder="us-east-1"></label></div>
          <div class="clr-col-12 clr-col-md-2"><label class="os-sub">Access Key<input id="sc-bk-ak" class="os-filter" autocomplete="off"></label></div>
          <div class="clr-col-12 clr-col-md-2"><label class="os-sub">Secret Key<input id="sc-bk-sk" class="os-filter" type="password" autocomplete="off"></label></div>
        </div>
        <p id="sc-bk-status" class="os-sub"></p>
        <p class="os-sub">공용 기본은 <span class="os-mono">BSS → Velero</span>에서 구성한 외부 S3(default BSL)를 사용합니다. 전용은 이 워크로드만의 외부 대상(별도 samba-ad BSL)입니다. 백업은 node-agent 파일시스템 백업으로 PVC(SAM DB)를 담고, 자격증명은 velero 네임스페이스 Secret에만 저장됩니다.</p>
      </div></div>
      <div id="sc-metrics"><div class="os-sech">메트릭 <span class="os-sub">kube-prometheus-stack</span></div><p class="os-sub">차트 로딩…</p></div>
      <div class="os-sech">로그 <span class="os-sub">Loki · samba pod stdout · 최근 60분</span></div>
      <div id="sc-logs" class="vl-log"><div class="vl-log-empty">로그 로딩…</div></div>
      <div class="os-sech">운영 이벤트 <span class="os-sub">K8s events</span></div>
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
      '## 백업(Velero 중앙 등록)',
      '- 백업 엔진은 Velero(BSS). 백업 대상은 외부 S3 호환 서비스이며 사용자가 구성한다 — 클러스터 내부 저장소에 의존하지 않는다.',
      '- 공용 기본: `BSS → Velero` 페이지에서 외부 S3(default BSL)를 구성. 여러 plugin이 공유.',
      '- 전용 override: 이 화면 "백업" 섹션에서 samba-ad 전용 외부 대상(samba-ad BSL)을 별도 구성 가능.',
      '- 등록 실체 = `velero.io/Schedule` `samba-ad`(ns velero) — samba pod(app=foundation-identity-samba) + PVC를 node-agent 파일시스템 백업으로 담는다. "지금 백업"은 일회성 `Backup` CR.',
      '- 쓰기 경로: 콘솔 사용자 임퍼소네이션(foundation 프록시) — plugin SA엔 velero 권한을 주지 않는다(최소권한).',
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
