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
// ── 감사 Critical 시정(2026-07-06) — 도메인 부트스트랩 비밀번호를 소스/manifest/응답에 두지 않는다 ──
// Foundation/Identity 소유 Secret(opensphere-foundation ns)에 보관하고, operand는 secretKeyRef로만 참조한다.
// readSambaConfig/operand 응답은 비밀번호를 절대 반환하지 않는다(평문 유출 제거). 소스 하드코딩 폐지.
const SAMBA_CREDS_SECRET = process.env.SAMBA_CREDS_SECRET || 'foundation-identity-samba-creds';
const SAMBA_CREDS_KEY = 'domain-password';

// 설정 정본 = FoundationModel/identity.spec.parameters.samba (없으면 dev 기본값 — 단, 비밀번호는 여기 없음).
// 3단계 설정 페이지가 이 필드를 PATCH하면 control-plane 재조정 시 operand가 재렌더된다.
const SAMBA_DEFAULTS = { domain: 'OPENSPHERE.LOCAL', replicas: 1, storageClass: 'standard', dnsForwarder: '8.8.8.8' };
async function readSambaConfig() {
  const fm = await k8sGet('/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity');
  const p = (!fm.__status && fm.spec?.parameters?.samba) || {};
  // 비밀번호(domainPass)는 의도적으로 제외 — operand는 Secret(secretKeyRef)에서 받는다.
  return {
    domain: p.domain || SAMBA_DEFAULTS.domain,
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
                // 비밀번호는 평문 value 금지 — Foundation/Identity 소유 Secret에서 참조(감사 Critical 시정).
                { name: 'DOMAINPASS', valueFrom: { secretKeyRef: { name: SAMBA_CREDS_SECRET, key: SAMBA_CREDS_KEY } } },
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
        // 감사 High 시정: from 없는 ingress는 전 출처 허용 → 알려진 소비자로 제한.
        // Keycloak(federation) + foundation ns(도메인 멤버·control-plane)만 허용. 타 ns 소비자는 from에 명시 추가.
        ingress: [{
          from: [
            { podSelector: { matchLabels: { app: KEYCLOAK } } },
            { namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': FND_NS } } },
          ],
          ports: [
            { protocol: 'TCP', port: 389 }, { protocol: 'TCP', port: 636 }, { protocol: 'TCP', port: 88 },
            { protocol: 'TCP', port: 53 }, { protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 445 },
          ],
        }] } },
  ];
}

function saToken() { return fs.readFileSync(`${SA}/token`, 'utf8').trim(); }

// 감사 Medium 시정: 의존성(k8s/prometheus/loki/controller)이 느리거나 불통일 때 응답이 무한 대기하지
// 않도록 AbortController 기반 유한 타임아웃. 초과 시 abort→throw → 호출부가 __status/에러로 처리.
async function fetchT(url, opts = {}, ms = 5000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ac.signal }); }
  finally { clearTimeout(t); }
}

async function k8sGet(p) {
  try {
    const res = await fetchT(`${APISERVER}${p}`, { headers: { Authorization: `Bearer ${saToken()}` } }, 5000);
    if (!res.ok) return { __status: res.status };
    return res.json();
  } catch { return { __status: 504 }; }  // 타임아웃/네트워크 → gateway timeout으로 표기
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

function sambaPreflight(payload) {
  const w = payload.workload || {};
  const m = payload.model || {};
  const cfg = payload.config || {};
  const storageClasses = payload.storageClasses || [];
  const domain = String(cfg.domain || '');
  const replicas = Number(cfg.replicas || 0);
  const hasStorageClassCatalog = storageClasses.length > 0;
  const selectedStorageClass = String(cfg.storageClass || '');
  const storageClassKnown = hasStorageClassCatalog
    ? storageClasses.some((sc) => sc.name === selectedStorageClass)
    : !!selectedStorageClass;
  const domainOk = /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(domain);
  const dnsOk = !!String(cfg.dnsForwarder || '').trim();
  const engineEnabled = m.engineOpt !== 'disabled';
  const secretReady = !!payload.bootstrapSecret?.found;
  const check = (id, label, state, message) => ({ id, label, state, message });
  const checks = [
    check('plugin-api', 'Plugin API', 'pass', `Samba-AD plugin backend is reachable (${payload.meta?.servedBy || 'unknown'}).`),
    check('foundation-model', 'FoundationModel/identity', m.found ? 'pass' : 'fail',
      m.found ? `model phase=${m.phase || 'unknown'}` : `FoundationModel/identity is not readable (HTTP ${m.status || 'unknown'}).`),
    check('engine-option', 'engines.samba', engineEnabled ? 'pass' : 'info',
      engineEnabled ? `engine option=${m.engineOpt || 'enabled'}` : 'engine option is disabled; Install step will enable Samba-AD before the control-plane applies the operand.'),
    check('domain-realm', 'Directory realm', domainOk ? 'pass' : 'fail',
      domainOk ? `realm=${domain}` : 'realm must be an FQDN-like value such as OPENSPHERE.LOCAL.'),
    check('storage-class', 'StorageClass', storageClassKnown ? 'pass' : (selectedStorageClass ? 'warn' : 'fail'),
      hasStorageClassCatalog
        ? (storageClassKnown ? `selected=${selectedStorageClass}` : `selected=${selectedStorageClass}; not found in cluster StorageClass catalog.`)
        : `selected=${selectedStorageClass || '(empty)'}; StorageClass catalog is not available to this plugin.`),
    check('dns-forwarder', 'DNS forwarder', dnsOk ? 'pass' : 'fail',
      dnsOk ? `dnsForwarder=${cfg.dnsForwarder}` : 'dnsForwarder is empty.'),
    check('replica-mode', 'Replica mode', replicas === 1 ? 'pass' : 'warn',
      replicas === 1 ? 'single DC/Recreate mode' : `replicas=${replicas}; current Samba-AD operand is designed for single DC mode.`),
    check('domain-secret', 'Domain password Secret', secretReady ? 'pass' : 'warn',
      secretReady
        ? `${SAMBA_CREDS_SECRET}/${SAMBA_CREDS_KEY} exists and is referenced by secretKeyRef; value is intentionally not exposed by the plugin.`
        : `${SAMBA_CREDS_SECRET}/${SAMBA_CREDS_KEY} is not present yet; create it from the Install input step before apply.`),
    check('operand-render', 'Operand manifest', 'pass',
      `/operand/manifests renders PVC, Service, Deployment, and NetworkPolicy for ${SAMBA}.`),
    check('security-profile', 'Security profile', 'warn',
      'Current operand profile is dev/bootstrap: privileged container, INSECURELDAP=true, NOCOMPLEXITY=true. Production hardening remains required.'),
    check('keycloak', 'Keycloak federation consumer', payload.keycloak?.ready ? 'pass' : 'warn',
      payload.keycloak?.found ? (payload.keycloak.ready ? 'Keycloak deployment is ready.' : 'Keycloak deployment exists but is not ready yet.') : 'Keycloak deployment was not found.'),
    check('workload', 'Samba-AD workload', w.found ? (w.ready ? 'pass' : 'warn') : 'info',
      w.found ? `deployment exists; ready=${w.readyReplicas || 0}/${w.replicas || 0}` : 'workload is not deployed yet; this is expected during day-0 preflight.'),
  ];
  const blockers = checks.filter((c) => c.state === 'fail').length;
  const warnings = checks.filter((c) => c.state === 'warn').length;
  const inputBlockers = secretReady ? 0 : 1;
  const installState = w.found
    ? (w.ready ? 'Installed' : 'Deploying')
    : (blockers > 0 ? 'Blocked' : (inputBlockers > 0 ? 'AwaitingInput' : (engineEnabled ? 'ReadyToApply' : 'AwaitingInstall')));
  return {
    mode: w.found ? 'manage' : (blockers > 0 ? 'preflight' : 'install'),
    readyToInstall: blockers === 0 && !w.found,
    readyToApply: blockers === 0 && inputBlockers === 0 && engineEnabled && !w.found,
    installState,
    blockers,
    inputBlockers,
    warnings,
    checks,
  };
}

async function sambaPayload() {
  const sel = encodeURIComponent(`app=${SAMBA}`);
  const fsel = encodeURIComponent(`involvedObject.name=${SAMBA}`);
  const [fm, dep, kcDep, pods, events, scList, secret] = await Promise.all([
    k8sGet('/apis/foundation.opensphere.io/v1alpha1/foundationmodels/identity'),
    k8sGet(`/apis/apps/v1/namespaces/${FND_NS}/deployments/${SAMBA}`),
    k8sGet(`/apis/apps/v1/namespaces/${FND_NS}/deployments/${KEYCLOAK}`),
    k8sGet(`/api/v1/namespaces/${FND_NS}/pods?labelSelector=${sel}`),
    k8sGet(`/api/v1/namespaces/${FND_NS}/events?fieldSelector=${fsel}&limit=15`),
    k8sGet('/apis/storage.k8s.io/v1/storageclasses'),
    k8sGet(`/api/v1/namespaces/${FND_NS}/secrets/${SAMBA_CREDS_SECRET}`),
  ]);
  // 설정 폼 StorageClass 드롭다운 — 클러스터 실 목록(기본 SC 표시). 조회 실패 시 빈 배열(폼은 현재값만).
  const storageClasses = scList.__status ? [] : (scList.items || []).map((s) => ({
    name: s.metadata?.name,
    provisioner: s.provisioner,
    isDefault: (s.metadata?.annotations || {})['storageclass.kubernetes.io/is-default-class'] === 'true',
  }));
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
  // 백업 설정 정본 = FM/identity.spec.parameters.samba.backup. mode=shared(공용 기본 BSL) | dedicated(전용 BSL).
  // 실 Schedule/Backup(velero.io, ns velero)은 UI가 foundation 프록시(사용자 임퍼소네이션)로 읽고 쓴다 —
  // plugin SA에 velero 권한을 주지 않는 최소권한(velero 페이지 install()과 동형 write-path).
  const bk = sp.backup || {};
  const backup = {
    enabled: !!bk.enabled,
    mode: bk.mode === 'dedicated' ? 'dedicated' : 'shared',
    schedule: bk.schedule || '0 2 * * *',
    ttlHours: Number.isInteger(bk.ttlHours) ? bk.ttlHours : 720,
    dedicated: bk.dedicated ? { endpoint: bk.dedicated.endpoint || '', bucket: bk.dedicated.bucket || '', region: bk.dedicated.region || '' } : null,
    scheduleName: 'samba-ad',   // velero.io Schedule 이름(고정) — UI가 이 이름으로 조회/갱신
    bslName: bk.mode === 'dedicated' ? 'samba-ad' : 'default',
    pvc: SAMBA_DATA_PVC, podSelector: `app=${SAMBA}`,
  };
  const evs = (events.items || [])
    .map((e) => ({ type: e.type, reason: e.reason, message: e.message, time: e.lastTimestamp || e.eventTime || '' }))
    .sort((a, b) => String(b.time).localeCompare(String(a.time)));
  const payload = {
    meta: { service: 'opensphere-plugin-samba-ad', version: VERSION, servedBy: process.env.HOSTNAME || 'unknown', time: new Date().toISOString(), ns: FND_NS },
    model,
    config,
    bootstrapSecret: { name: SAMBA_CREDS_SECRET, key: SAMBA_CREDS_KEY, found: !secret.__status, status: secret.__status || 200 },
    backup,
    storageClasses,
    workload: workloadView(dep, pods),
    keycloak: kcDep.__status ? { found: false } : { found: true, ready: (kcDep.status?.readyReplicas ?? 0) >= 1, name: KEYCLOAK },
    events: evs,
  };
  payload.preflight = sambaPreflight(payload);
  return payload;
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
      tool('ad.preflight', 'preflight', '/cli/preflight', 'Samba-AD operand day-0 preflight checks'),
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
// ── Loki 로그 통합(2026-07-06) — 중앙 로그 스택(basic observability) 소비 ──
// promtail이 samba pod stdout을 Loki에 수집 → 이 endpoint가 LogQL query_range로 tail.
const LOKI = process.env.LOKI_URL || 'http://loki.monitoring.svc:3100';
async function lokiTail(minutes, limit) {
  const endNs = Date.now() * 1e6;
  const startNs = (Date.now() - Math.max(1, minutes) * 60000) * 1e6;
  // LogQL은 고정 템플릿(사용자 쿼리 미수용) — samba pod 로그만. 감사 §8 권고 정합.
  const q = encodeURIComponent(`{namespace="${FND_NS}",app="${SAMBA}"}`);
  const u = `${LOKI}/loki/api/v1/query_range?query=${q}&start=${startNs}&end=${endNs}&limit=${limit}&direction=backward`;
  try { const r = await fetchT(u, {}, 6000); if (!r.ok) return { __status: r.status }; return r.json(); }
  catch { return { __status: 504 }; }
}
// 감사 Medium 시정: /api/metrics/range의 q를 samba_ad_* 단일 메트릭(+선택 라벨매처)로만 제한.
// 함수·조인·연산자·타 메트릭을 거부 → 임의 PromQL 프록시화 방지.
function promAllowed(q) {
  return /^\s*samba_ad_[a-z0-9_]+\s*(\{[^{}]*\})?\s*$/.test(String(q || ''));
}
async function promRange(query, minutes) {
  const end = Math.floor(Date.now() / 1000);
  const start = end - Math.max(1, minutes) * 60;
  const step = Math.max(15, Math.floor((end - start) / 120));
  const u = `${PROM}/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${step}`;
  try { const r = await fetchT(u, {}, 6000); if (!r.ok) return { __status: r.status }; return r.json(); }
  catch { return { __status: 504 }; }
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
      if (!promAllowed(q)) { res.writeHead(400, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: '허용되지 않은 쿼리 — samba_ad_* 메트릭만 조회 가능(임의 PromQL 거부).' })); }
      const minutes = parseInt(url.searchParams.get('minutes') || '30', 10);
      const out = await promRange(q, minutes);
      res.writeHead(out.__status ? 502 : 200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(out.__status ? { error: `prometheus HTTP ${out.__status}` } : out));
    }
    if (url.pathname === '/api/logs') {
      const minutes = parseInt(url.searchParams.get('minutes') || '60', 10);
      const out = await lokiTail(minutes, 200);
      if (out.__status) { res.writeHead(502, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: `loki HTTP ${out.__status} — 로그 스택(Loki) 연결 확인` })); }
      const lines = [];
      for (const s of (out.data?.result || [])) for (const [ts, line] of (s.values || [])) lines.push({ ts: Math.floor(Number(ts) / 1e6), line });
      lines.sort((a, b) => b.ts - a.ts);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ lines: lines.slice(0, 120) }));
    }
    if (url.pathname === '/api/samba') {
      const payload = await sambaPayload();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(payload));
    }
    if (url.pathname === '/api/preflight') {
      const payload = await sambaPayload();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(payload.preflight));
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
    if (url.pathname === '/cli/preflight') {
      const p = await sambaPayload();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(p.preflight));
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

// ── 메시지 통합(2026-07-06) — plugin이 자기 이벤트를 콘솔 단일 인박스(audit bus)에 발행 ──
// S2 배선: dupa-registry-controller /api/admin/events(X-Shell-Token=SHELL_SERVICE_TOKEN, podEnv 주입).
// 전이 시에만 발행(dedup — 폴링 스팸 금지). source는 controller가 'ext:'로 강제 태깅(actor 위장 불가).
// best-effort: 발행 실패해도 plugin 본기능 무관(경고 1회 후 억제).
const CONTROLLER = process.env.OSP_CONTROLLER || 'http://dupa-registry-controller.opensphere-system.svc.cluster.local:8080';
const SHELL_TOKEN = process.env.SHELL_SERVICE_TOKEN || '';
let _notifyWarned = false;
async function publishNotify(ev) {
  if (!SHELL_TOKEN) { if (!_notifyWarned) { _notifyWarned = true; console.warn('[notify] SHELL_SERVICE_TOKEN 없음 — 이벤트 발행 생략'); } return; }
  try {
    const res = await fetchT(`${CONTROLLER}/api/admin/events`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-shell-token': SHELL_TOKEN, 'x-opensphere-source': 'samba-ad' },
      body: JSON.stringify({ source: 'samba-ad', ...ev }),
    });
    if (!res.ok && !_notifyWarned) { _notifyWarned = true; console.warn(`[notify] 발행 실패 http=${res.status}(이후 억제)`); }
  } catch (e) { if (!_notifyWarned) { _notifyWarned = true; console.warn(`[notify] 발행 실패 ${(e && (e.code || e.message)) || e}(이후 억제)`); } }
}

// 자기 헬스 전이 감시 — DC ready / LDAP reachable 상태가 바뀔 때만 발행(기준선은 첫 관측서 수립).
let _lastHealth = null;
async function healthTransitionPublish() {
  try {
    const p = await sambaPayload();
    const w = p.workload || {};
    const ldap = await tcpProbe(`${SAMBA}.${FND_NS}.svc`, 389).catch(() => false);
    const cur = { dcReady: !!w.ready, ldap };
    const prev = _lastHealth;
    _lastHealth = cur;
    if (prev === null) { return; } // 첫 관측 = 기준선(재기동 스팸 방지)
    if (prev.dcReady !== cur.dcReady) {
      await publishNotify({ action: cur.dcReady ? 'DirectoryReady' : 'DirectoryDown', target: `Deployment/${SAMBA}`,
        result: cur.dcReady ? 'success' : 'warning', reason: `Samba-AD DC ${cur.dcReady ? 'Running' : '비정상(디렉터리 다운)'}` });
    }
    if (prev.ldap !== cur.ldap) {
      await publishNotify({ action: cur.ldap ? 'LdapReachable' : 'LdapUnreachable', target: `Service/${SAMBA}:389`,
        result: cur.ldap ? 'info' : 'warning', reason: `Samba-AD LDAP :389 ${cur.ldap ? '도달' : '도달 불가(federation 영향)'}` });
    }
  } catch (e) { /* best-effort */ }
}

server.listen(PORT, () => {
  console.log(`opensphere-plugin-samba-ad v${VERSION} listening :${PORT}`);
  // 시작 이벤트 발행 + 60초 헬스 전이 감시(첫 호출=기준선, 발행 없음).
  publishNotify({ action: 'started', target: 'samba-ad', result: 'info', reason: `Samba-AD plugin v${VERSION} 시작` });
  healthTransitionPublish();
  setInterval(healthTransitionPublish, 60000);
});
