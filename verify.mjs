#!/usr/bin/env node
// samba-ad 자기검증 — 감사 §4.2 시정. 의존성 0(node 내장만). 실패 시 non-zero exit(CI/pre-commit 게이트).
//   실행: node verify.mjs
// 검사: ① 구문(server.js CJS, ui-shell.plugin.js ESM)
//       ② manifest.entrySha256 == sha256(ui-shell.plugin.js)
//       ③ uipluginpackage.manifest.sha256 == sha256(ui-shell.manifest.json)
//       ④ rbac.yaml plugin SA에 write verb 0(읽기 전용 경계)
//       ⑤ server.js에 하드코딩 비밀번호 0 + DOMAINPASS는 secretKeyRef
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const abs = (p) => fileURLToPath(new URL(p, import.meta.url)); // 크로스플랫폼 경로(win 드라이브 보정)
const read = (p) => readFileSync(abs(p));
const sha = (buf) => createHash('sha256').update(buf).digest('hex');
const pass = [], fail = [];
const check = (name, cond, detail = '') => (cond ? pass : fail).push(name + (detail ? ` — ${detail}` : ''));

// ① 구문
try { execFileSync(process.execPath, ['--check', abs('server.js')]); check('syntax: server.js (CJS)', true); }
catch (e) { check('syntax: server.js', false, String(e.stderr || e).slice(0, 120)); }
try { execFileSync(process.execPath, ['--check', '--input-type=module'], { input: read('ui-shell/ui-shell.plugin.js') }); check('syntax: ui-shell.plugin.js (ESM)', true); }
catch (e) { check('syntax: ui-shell.plugin.js', false, String(e.stderr || e).slice(0, 120)); }
const uiShell = read('ui-shell/ui-shell.plugin.js').toString();
check('ui: canonical addc tab routes (no lifecycle URL branch)',
  /return `\/p\/foundation\/addc\$\{suffix\}/.test(uiShell) && !uiShell.includes('/p/foundation/addc/manage/'));
check('ui: common header and tabs persist across lifecycle states',
  /renderLifecycle\(d, lifecycle\)/.test(uiShell) && /pluginHeader\(d,[\s\S]{0,260}manageNav\(activeTab, d\)/.test(uiShell));
check('ui: install completion returns to canonical overview',
  uiShell.includes("this.managePath('overview')") && !uiShell.includes('stageUrl('));
check('ui: retained custom element reads refreshed host capability context',
  uiShell.includes("Symbol.for('opensphere.plugin.samba-ad.runtime')") &&
  uiShell.includes('RUNTIME.apiFetch') && !uiShell.includes('API_FETCH') && !uiShell.includes('API_BASE'));
check('ui: PostgreSQL reference overview structure is reused exactly',
  /class="pgp-steps"/.test(uiShell) && /class="pgp-dashboard"/.test(uiShell) &&
  /<h2>Package readiness<\/h2>/.test(uiShell) && /<h2>Directory health<\/h2>/.test(uiShell) &&
  /<h2>Operations policy<\/h2>/.test(uiShell) && /class="pgp-description"/.test(uiShell));
check('ui: PostgreSQL reference page shell and tab spine are reused exactly',
  /class="vl-back"/.test(uiShell) && /class="pgp-page-frame"/.test(uiShell) &&
  /\['overview', 'Overview'/.test(uiShell) && /\['operator', 'Operator'/.test(uiShell) &&
  /\['cluster', 'Cluster plan'/.test(uiShell) && /\['configuration', 'Configuration'/.test(uiShell) &&
  /\['directory', 'Directory & Roles'/.test(uiShell) && /\['backups', 'Backups'/.test(uiShell) &&
  /\['claims', 'Claims'/.test(uiShell) && /requiresWorkload && !workloadReady/.test(uiShell));
check('ui: tablist exposes roving focus and keyboard navigation',
  /role="tablist" aria-orientation="horizontal"/.test(uiShell) && /aria-selected=/.test(uiShell) &&
  /tabindex=/.test(uiShell) && /ArrowRight/.test(uiShell) && /ArrowLeft/.test(uiShell) &&
  /e\.key === 'Home'/.test(uiShell) && /e\.key === 'End'/.test(uiShell));

// ② entrySha256 == sha256(entry)
const manifest = JSON.parse(read('ui-shell/ui-shell.manifest.json').toString());
const entryHash = sha(read('ui-shell/ui-shell.plugin.js'));
check('manifest.entrySha256 == sha256(ui-shell.plugin.js)', manifest.entrySha256 === entryHash, `${manifest.entrySha256?.slice(0, 12)} vs ${entryHash.slice(0, 12)}`);

// ③ package manifest.sha256 == sha256(manifest.json)  (YAML 파서 없음 → 정규식)
const pkg = read('uipluginpackage.yaml').toString();
const pkgManifestSha = (pkg.match(/sha256:\s*"([a-f0-9]{64})"/) || [])[1];
const manifestHash = sha(read('ui-shell/ui-shell.manifest.json'));
check('package.manifest.sha256 == sha256(ui-shell.manifest.json)', pkgManifestSha === manifestHash, `${(pkgManifestSha || '?').slice(0, 12)} vs ${manifestHash.slice(0, 12)}`);
check('package.image.digest is sha256-pinned (no tag)', /digest:\s*sha256:[a-f0-9]{64}/.test(pkg));

// ④ rbac.yaml — plugin SA에 write verb 0
const rbac = read('rbac.yaml').toString();
const writeVerbs = (rbac.match(/\b(create|update|patch|delete|deletecollection|impersonate)\b/g) || []);
check('rbac.yaml: plugin SA has zero write verbs', writeVerbs.length === 0, writeVerbs.length ? `found: ${[...new Set(writeVerbs)].join(',')}` : 'read-only');
check('rbac.yaml: no wildcard verb', !/verbs:\s*\[[^\]]*["']?\*/.test(rbac) && !/-\s*["']?\*["']?\s*$/m.test(rbac));

// ⑤ server.js — 하드코딩 비밀번호 0 + DOMAINPASS는 secretKeyRef
const server = read('server.js').toString();
check('server.js: no hardcoded password', !/OpenSphere2026|domainPass\s*:\s*['"]/.test(server));
check('server.js: DOMAINPASS via secretKeyRef', /DOMAINPASS[\s\S]{0,120}secretKeyRef/.test(server));
check('server.js: DOMAINPASS not cleartext value', !/DOMAINPASS['"]\s*,\s*value:/.test(server));
check('server.js: config does not carry domainPass', !/domainPass:\s*(p\.domainPass|cfg\.|SAMBA_DEFAULTS\.domainPass)/.test(server));

// 결과
for (const p of pass) console.log(`  ok   ${p}`);
for (const f of fail) console.error(`  FAIL ${f}`);
console.log(`\n${pass.length} passed, ${fail.length} failed`);
process.exit(fail.length ? 1 : 0);
