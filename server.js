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

const PORT = process.env.PORT || 8080;
const PLUGIN_DIR = process.env.PLUGIN_DIR || '/plugins';
const VERSION = process.env.APP_VERSION || '0.1.0';
const SA = '/var/run/secrets/kubernetes.io/serviceaccount';
const APISERVER = 'https://kubernetes.default.svc';
const FND_NS = process.env.FOUNDATION_NS || 'opensphere-foundation';
const SAMBA = 'foundation-identity-samba';
const KEYCLOAK = 'foundation-identity-keycloak';

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
  const evs = (events.items || [])
    .map((e) => ({ type: e.type, reason: e.reason, message: e.message, time: e.lastTimestamp || e.eventTime || '' }))
    .sort((a, b) => String(b.time).localeCompare(String(a.time)));
  return {
    meta: { service: 'opensphere-plugin-samba-ad', version: VERSION, servedBy: process.env.HOSTNAME || 'unknown', time: new Date().toISOString(), ns: FND_NS },
    model,
    workload: workloadView(dep, pods),
    keycloak: kcDep.__status ? { found: false } : { found: true, ready: (kcDep.status?.readyReplicas ?? 0) >= 1, name: KEYCLOAK },
    events: evs,
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (url.pathname === '/healthz') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('ok'); }
    if (url.pathname === '/api/samba') {
      const payload = await sambaPayload();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(payload));
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
