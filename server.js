// OpenSphere Samba-AD plugin — 기능 컨테이너 백엔드.
// D1 승격(2026-07-06): Foundation subShell 내부 뷰였던 Samba-AD를 독립 레포(OpenSphere-plugin-samba-ad,
//   폴더=컨테이너=신뢰·서명 경계)로 승격. 콘솔 DUPA 신뢰체인(UIPluginPackage+서명 이중검증)으로 적재되고,
//   표시는 host(Foundation)가 안층에서 <osp-samba-ad> 마운트(manifest hostRef=foundation).
// 역할: ① /api/samba — Samba-AD 실물(Deployment/pods/events) + 선언 정본(FoundationModel/identity) 집계
//       ② /plugins/* — 서명된 UI 플러그인 자산 서빙(기능 컨테이너가 자기 UI를 소유·배포)
// 의존성 0(node:22 내장). 읽기 전용(전용 SA 최소권한 — rbac.yaml). 쓰기 없음(수명주기는 Foundation 소관).
const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');

const PORT = process.env.PORT || 8080;
const PLUGIN_DIR = process.env.PLUGIN_DIR || '/plugins';
const VERSION = process.env.APP_VERSION || '0.1.0';
const SA = '/var/run/secrets/kubernetes.io/serviceaccount';
const APISERVER = 'https://kubernetes.default.svc';
const FND_NS = process.env.FOUNDATION_NS || 'opensphere-foundation';
const SAMBA = 'foundation-identity-samba';
const KEYCLOAK = 'foundation-identity-keycloak';
// self-contained(2026-07-06): operand(AD DC 실물) 배포 선언을 이 plugin이 소유한다.
// control-plane은 GET /operand/manifests로 이 선언을 받아 SSA apply만 한다("내민 선언을 apply").
const SAMBA_IMAGE = process.env.SAMBA_IMAGE || 'ghcr.io/opensphere-platform/mirror/samba-domain:20260706';
const SAMBA_DATA_PVC = 'foundation-identity-samba-data';

// 설정 정본 = FoundationModel/identity.spec.parameters.samba (없으면 dev 기본값).
// 3단계 설정 페이지가 이 필드를 PATCH하면 control-plane 재조정 시 operand가 재렌더된다.
const SAMBA_DEFAULTS = { domain: 'OPENSPHERE.LOCAL', domainPass: 'OpenSphere2026!', replicas: 1, storageClass: 'standard', dnsForwarder: '8.8.8.8' };
async function readSambaConfig() {
  const fm = await k8sGet('/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity');
  const p = (!fm.__status && fm.spec?.parameters?.samba) || {};
  return {
    domain: p.domain || SAMBA_DEFAULTS.domain,
    domainPass: p.domainPass || SAMBA_DEFAULTS.domainPass,
    replicas: Number.isInteger(p.replicas) ? p.replicas : SAMBA_DEFAULTS.replicas,
    storageClass: p.storageClass || SAMBA_DEFAULTS.storageClass,
    dnsForwarder: p.dnsForwarder || SAMBA_DEFAULTS.dnsForwarder,
  };
}

// buildOperand — Samba-AD DC operand 선언(k8s 오브젝트 JSON 배열). control-plane이 라벨 스탬프 후 SSA.
// PVC는 회수 대상에서 제외(SAM DB 보존) — control-plane bundleKinds 정책과 정합.
function buildOperand(cfg) {
  const meta = (name) => ({ name, namespace: FND_NS });
  return [
    { apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: meta(SAMBA_DATA_PVC),
      spec: { accessModes: ['ReadWriteOnce'], storageClassName: cfg.storageClass, resources: { requests: { storage: '3Gi' } } } },
    { apiVersion: 'v1', kind: 'Service', metadata: meta(SAMBA),
      spec: { selector: { app: SAMBA }, ports: [
        { name: 'ldap', port: 389, targetPort: 389, protocol: 'TCP' },
        { name: 'ldaps', port: 636, targetPort: 636, protocol: 'TCP' },
        { name: 'kerberos', port: 88, targetPort: 88, protocol: 'TCP' },
        { name: 'dns-tcp', port: 53, targetPort: 53, protocol: 'TCP' },
        { name: 'dns-udp', port: 53, targetPort: 53, protocol: 'UDP' },
        { name: 'smb', port: 445, targetPort: 445, protocol: 'TCP' },
      ] } },
    { apiVersion: 'apps/v1', kind: 'Deployment', metadata: meta(SAMBA),
      spec: { replicas: cfg.replicas, strategy: { type: 'Recreate' }, selector: { matchLabels: { app: SAMBA } },
        template: { metadata: { labels: { app: SAMBA } },
          spec: { hostname: 'dc1', automountServiceAccountToken: false,
            containers: [{ name: 'samba', image: SAMBA_IMAGE, imagePullPolicy: 'IfNotPresent',
              securityContext: { privileged: true },
              env: [
                { name: 'DOMAIN', value: cfg.domain },
                { name: 'DOMAINPASS', value: cfg.domainPass },
                { name: 'HOSTIP', valueFrom: { fieldRef: { fieldPath: 'status.podIP' } } },
                { name: 'DNSFORWARDER', value: cfg.dnsForwarder },
                { name: 'NOCOMPLEXITY', value: 'true' },
                { name: 'INSECURELDAP', value: 'true' },
                { name: 'JOIN', value: 'false' },
              ],
              ports: [
                { name: 'ldap', containerPort: 389 }, { name: 'ldaps', containerPort: 636 },
                { name: 'kerberos', containerPort: 88 }, { name: 'dns', containerPort: 53 },
                { name: 'smb', containerPort: 445 },
              ],
              readinessProbe: { tcpSocket: { port: 389 }, initialDelaySeconds: 25, periodSeconds: 10, failureThreshold: 30 },
              resources: { requests: { cpu: '150m', memory: '384Mi' }, limits: { memory: '768Mi' } },
              volumeMounts: [
                { name: 'data', mountPath: '/var/lib/samba', subPath: 'lib' },
                { name: 'data', mountPath: '/etc/samba/external', subPath: 'etc-external' },
              ] }],
            volumes: [{ name: 'data', persistentVolumeClaim: { claimName: SAMBA_DATA_PVC } }] } } } },
    { apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata: meta(SAMBA),
      spec: { podSelector: { matchLabels: { app: SAMBA } }, policyTypes: ['Ingress'],
        ingress: [{ ports: [
          { protocol: 'TCP', port: 389 }, { protocol: 'TCP', port: 636 }, { protocol: 'TCP', port: 88 },
          { protocol: 'TCP', port: 53 }, { protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 445 },
        ] }] } },
  ];
}

function saToken() { return fs.readFileSync(`${SA}/token`, 'utf8').trim(); }

async function k8sGet(p) {
  const res = await fetch(`${APISERVER}${p}`, { headers: { Authorization: `Bearer ${saToken()}` } });
  if (!res.ok) return { __status: res.status };
  return res.json();
}

function workloadView(dep, pods) {
  if (dep.__status) { return { found: false, status: dep.__status }; }
  const pod = (pods.items || [])[0];
  const env = (dep.spec?.template?.spec?.containers?.[0]?.env || []);
  return {
    found: true,
    ready: (dep.status?.readyReplicas ?? 0) >= 1,
    readyReplicas: dep.status?.readyReplicas ?? 0,
    replicas: dep.spec?.replicas ?? 0,
    image: dep.spec?.template?.spec?.containers?.[0]?.image || '',
    node: pod?.spec?.nodeName || '—',
    restarts: (pod?.status?.containerStatuses || []).reduce((a, c) => a + (c.restartCount || 0), 0),
    realmEnv: env.find((e) => e.name === 'DOMAIN')?.value || '',
  };
}

async function sambaPayload() {
  const sel = encodeURIComponent(`app=${SAMBA}`);
  const fsel = encodeURIComponent(`involvedObject.name=${SAMBA}`);
  const [fm, dep, kcDep, pods, events] = await Promise.all([
    k8sGet('/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity'),
    k8sGet(`/apis/apps/v1/namespaces/${FND_NS}/deployments/${SAMBA}`),
    k8sGet(`/apis/apps/v1/namespaces/${FND_NS}/deployments/${KEYCLOAK}`),
    k8sGet(`/api/v1/namespaces/${FND_NS}/pods?labelSelector=${sel}`),
    k8sGet(`/api/v1/namespaces/${FND_NS}/events?fieldSelector=${fsel}&limit=15`),
  ]);
  const model = fm.__status
    ? { found: false, status: fm.__status }
    : {
        found: true,
        phase: fm.status?.phase || '',
        observed: fm.status?.observed || [],
        ldapURL: fm.status?.ldapURL || `ldap://${SAMBA}.${FND_NS}.svc:389`,
        directoryRealm: fm.status?.directoryRealm || '',
        controlPlane: fm.status?.controlPlane || '',
        observedAt: fm.status?.observedAt || '',
        engineOpt: fm.spec?.parameters?.engines?.samba || 'enabled',
      };
  // 현재 설정(3단계 설정 폼이 표시·편집) — FM/identity.spec.parameters.samba(없으면 기본값).
  const sp = (!fm.__status && fm.spec?.parameters?.samba) || {};
  const config = {
    domain: sp.domain || SAMBA_DEFAULTS.domain,
    replicas: Number.isInteger(sp.replicas) ? sp.replicas : SAMBA_DEFAULTS.replicas,
    storageClass: sp.storageClass || SAMBA_DEFAULTS.storageClass,
    dnsForwarder: sp.dnsForwarder || SAMBA_DEFAULTS.dnsForwarder,
  };
  const evs = (events.items || [])
    .map((e) => ({ type: e.type, reason: e.reason, message: e.message, time: e.lastTimestamp || e.eventTime || '' }))
    .sort((a, b) => String(b.time).localeCompare(String(a.time)));
  return {
    meta: { service: 'opensphere-plugin-samba-ad', version: VERSION, servedBy: process.env.HOSTNAME || 'unknown', time: new Date().toISOString(), ns: FND_NS },
    model,
    config,
    workload: workloadView(dep, pods),
    keycloak: kcDep.__status ? { found: false } : { found: true, ready: (kcDep.status?.readyReplicas ?? 0) >= 1, name: KEYCLOAK },
    events: evs,
  };
}

// ── cli:contribute (2026-07-06) — os CLI 명령 기여(headless binding). os가 registry에서 namespace 'ad'를
//   발견해 <console>/api/plugins/samba-ad<manifestPath>의 이 manifest를 조회, os ai와 동일 엔진으로 디스패치.
//   command manifest 스키마 = OAHAgentToolManifest 호환(kind/cli.commandPrefix/tools[]) — os 재사용.
//   현재 명령은 전부 읽기(risk=low) — 디렉터리 내용 변경은 ADR-FND-001상 콘솔/CLI가 하지 않는다(samba-tool).
function cliManifest() {
  const tool = (id, verb, path, description) => ({
    id, command: `os ad ${verb}`, method: 'GET', path, params: [], risk: 'low', scope: 'read', description,
  });
  return {
    kind: 'OpenSphereCLICommandManifest',
    cli: { commandPrefix: 'os ad' },
    tools: [
      tool('ad.status', 'status', '/cli/status', 'Samba-AD 디렉터리 요약(phase·realm·LDAP·모델 신호)'),
      tool('ad.describe', 'describe', '/cli/describe', '전체 상세(실물·연결·모델·소비자·이벤트) JSON'),
      tool('ad.events', 'events', '/cli/events', '최근 K8s 운영 이벤트'),
    ],
  };
}

// ── kube-prometheus-stack 연결(2026-07-06) ──
// /metrics: samba operand 실 신호를 Prometheus exposition으로 노출 → ServiceMonitor(servicemonitor.yaml)로
//   kps가 스크레이프. 위조 0(readyReplicas·restarts·TCP dial 등 실측만).
// /api/metrics/range: UI 차트용 — kps range API 프록시(시계열).
const PROM = process.env.PROMETHEUS_URL || 'http://kps-prometheus.monitoring.svc:9090';
function tcpProbe(host, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let done = false;
    const fin = (ok) => { if (!done) { done = true; try { s.destroy(); } catch {} resolve(ok); } };
    s.setTimeout(timeoutMs);
    s.once('connect', () => fin(true));
    s.once('timeout', () => fin(false));
    s.once('error', () => fin(false));
    s.connect(port, host);
  });
}
async function metricsText() {
  const p = await sambaPayload().catch(() => ({}));
  const w = p.workload || {}, m = p.model || {};
  const ldap = await tcpProbe(`${SAMBA}.${FND_NS}.svc`, 389).catch(() => false);
  const g = (name, help, val, type = 'gauge') =>
    `# HELP ${name} ${help}\n# TYPE ${name} ${type}\n${name}{plugin="samba-ad"} ${val}\n`;
  return [
    g('samba_ad_up', 'Samba-AD DC ready(1)/not(0)', w.ready ? 1 : 0),
    g('samba_ad_replicas_ready', 'ready replicas', w.readyReplicas || 0),
    g('samba_ad_replicas_desired', 'desired replicas', w.replicas || 0),
    g('samba_ad_restarts_total', 'container restarts', w.restarts || 0, 'counter'),
    g('samba_ad_ldap_reachable', 'LDAP :389 TCP reachable', ldap ? 1 : 0),
    g('samba_ad_model_installed', 'FoundationModel/identity phase==Installed', m.phase === 'Installed' ? 1 : 0),
    g('samba_ad_keycloak_federation_up', 'Keycloak(federation 소비자) ready', p.keycloak && p.keycloak.ready ? 1 : 0),
  ].join('');
}
async function promRange(query, minutes) {
  const end = Math.floor(Date.now() / 1000);
  const start = end - Math.max(1, minutes) * 60;
  const step = Math.max(15, Math.floor((end - start) / 120));
  const u = `${PROM}/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${step}`;
  const r = await fetch(u);
  if (!r.ok) return { __status: r.status };
  return r.json();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (url.pathname === '/healthz') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('ok'); }
    if (url.pathname === '/metrics') {
      res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4' });
      return res.end(await metricsText());
    }
    if (url.pathname === '/api/metrics/range') {
      const q = url.searchParams.get('q') || 'samba_ad_up{plugin="samba-ad"}';
      const minutes = parseInt(url.searchParams.get('minutes') || '30', 10);
      const out = await promRange(q, minutes);
      res.writeHead(out.__status ? 502 : 200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(out.__status ? { error: `prometheus HTTP ${out.__status}` } : out));
    }
    if (url.pathname === '/api/samba') {
      const payload = await sambaPayload();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(payload));
    }
    // ── operand 선언(self-contained) — control-plane이 fetch해 SSA apply ──
    if (url.pathname === '/operand/manifests') {
      const cfg = await readSambaConfig();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ engine: 'samba', config: cfg, items: buildOperand(cfg) }));
    }
    // ── os CLI 표면 ──
    if (url.pathname === '/cli/manifest') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(cliManifest()));
    }
    if (url.pathname === '/cli/describe') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(await sambaPayload()));
    }
    if (url.pathname === '/cli/events') {
      const p = await sambaPayload();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ events: p.events }));
    }
    if (url.pathname === '/cli/status') {
      const p = await sambaPayload();
      const w = p.workload || {}, m = p.model || {};
      const up = (p.model?.observed || []).filter((o) => o.id && o.id.endsWith('_up')).reduce((a, o) => (a[o.id] = o.value, a), {});
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({
        plugin: 'samba-ad', phase: w.found ? (w.ready ? 'Running' : 'Pending') : 'NotDeployed',
        replicas: w.found ? `${w.readyReplicas}/${w.replicas}` : '0/0',
        realm: w.realmEnv || m.directoryRealm || '', ldap: m.ldapURL || '',
        modelPhase: m.phase || '', engines: up, engineOpt: m.engineOpt || 'enabled',
      }));
    }
    if (url.pathname === '/plugins' || url.pathname === '/plugins/') {
      const files = fs.existsSync(PLUGIN_DIR) ? fs.readdirSync(PLUGIN_DIR).filter((f) => !f.startsWith('.')) : [];
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ plugins: files }));
    }
    if (url.pathname.startsWith('/plugins/')) {
      const file = path.basename(url.pathname); // 경로 탈출 방지
      const fp = path.join(PLUGIN_DIR, file);
      if (file && fs.existsSync(fp) && fs.statSync(fp).isFile()) {
        const mime = file.endsWith('.js') ? 'text/javascript' : file.endsWith('.json') ? 'application/json' : 'application/octet-stream';
        const stream = fs.createReadStream(fp);
        stream.on('error', (err) => {
          console.error('plugin file stream error:', err.code, fp);
          if (!res.headersSent) res.writeHead(500, { 'content-type': 'text/plain' });
          res.end('plugin file read error');
        });
        stream.once('open', () => res.writeHead(200, { 'content-type': mime }));
        return stream.pipe(res, { end: true });
      }
      res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('plugin not found');
    }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found');
  } catch (e) {
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: String(e) }));
  }
});

server.listen(PORT, () => console.log(`opensphere-plugin-samba-ad v${VERSION} listening :${PORT}`));
