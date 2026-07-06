# OpenSphere-plugin-samba-ad Technical Audit

Date: 2026-07-06
Scope: `OpenSphere-plugin-samba-ad` repository, deployed `samba-ad` UIPluginPackage, runtime plugin container, Manual/OAA integration
Audit stance: architecture, implementation quality, security boundary, operational readiness, and reuse as the reference pattern for the next plugin/module such as OpenSearch.

## 1. Executive Summary

`OpenSphere-plugin-samba-ad` is a strong reference implementation for the OpenSphere direction:

- A plugin is an independent repository, container, trust boundary, and signed UI bundle.
- A plugin can be sub-hosted under a parent subShell through `hostRef`, while still using the same mainShell trust chain.
- A plugin can own its backend, UI, CLI manifest, metrics endpoint, manual contribution, and operand declaration.
- Domain writes are intentionally routed through the host's verified write path instead of granting the plugin service account broad write/impersonation permissions.
- The plugin successfully contributes a manual document into the canonical Manual Registry, and OAA can retrieve and cite it.

Overall assessment: **architecturally sound and useful as a standard sample**, with several security hardening items required before this pattern is treated as production-grade for sensitive operands.

## 2. Verified Runtime State

The live cluster matches the repository trust pins:

- UIPluginPackage: `samba-ad`
- Registration phase: `Enabled`
- Workload: `deployment/samba-ad` is running.
- Deployed manifest SHA-256: `0e64ca25cf038cc662ffb868363d86831f68f031cf33e5e0ce509c603fa762db`
- Deployed entry SHA-256: `134351c2cfa44858ab74610d3c42039c9028a1c2178a8b107333d36f3adbe291`
- Package image digest: `sha256:8b6a5ff5c8e34e8466af1bbf22fee075af29429d9558dab643c85d17621ee437`

Runtime endpoints checked:

- `/healthz` returns `ok`.
- `/cli/manifest` returns `os ad` command metadata.
- `/operand/manifests` returns the Samba operand declaration.
- Manual Registry contains `plugin:samba-ad/operations`.
- Header global search returns `Samba-AD 디렉터리 운영 매뉴얼`.
- OAA chat cited `manual/plugin:samba-ad/operations#0` and `#1` when answering a Samba-AD manual question.

## 3. Design Assessment

### 3.1 Correct Direction

The plugin follows the right OpenSphere model:

1. **Independent trust boundary**
   - The repository owns `server.js`, `ui-shell/`, `Dockerfile`, `rbac.yaml`, `servicemonitor.yaml`, and `uipluginpackage.yaml`.
   - The package pins both image digest and manifest hash.
   - The runtime bundle hash matches the deployed bundle.

2. **Sub-hosted plugin pattern**
   - `ui-shell.manifest.json` uses `kind: plugin` and `hostRef: foundation`.
   - `activate(ctx)` defines `<osp-samba-ad>` and intentionally does not call `registerPage`.
   - `UIPluginRegistration.installPolicy.exposeInNavigation` is `false`.
   - Foundation can mount this plugin inside its own Identity/Samba-AD inner menu.

3. **Self-describing plugin**
   - It exposes a UI custom element.
   - It exposes a backend API.
   - It exposes a CLI manifest.
   - It contributes manual content.
   - It exports Prometheus metrics.
   - It exposes operand manifests for a controller to apply.

4. **Minimum plugin SA write boundary**
   - `rbac.yaml` grants only read verbs to the plugin service account:
     - `foundationmodels get`
     - `storageclasses list`
     - `deployments get`
     - `pods/events list`
   - Domain write paths in UI go through the Foundation plugin proxy with `x-os-id-token`, preserving user impersonation and host-owned authorization.

This is the correct strategic direction for OpenSearch as well: OpenSearch should be a self-contained plugin/module that owns its own UI/backend/manual/CLI/metrics/operand declaration, while domain writes remain mediated by an authorized host or controller path.

## 4. Implementation Assessment

### 4.1 Strong Points

- `server.js` has zero npm dependencies and runs on `node:22-alpine`.
- `Dockerfile` runs as non-root `USER node`.
- Plugin file serving uses `path.basename`, preventing simple path traversal under `/plugins/*`.
- UI uses a native custom element and escapes dynamic values with `esc()`.
- The Samba operand has `automountServiceAccountToken: false`.
- OAA/Manual integration is not just theoretical; it is live and searchable.
- The manual content is operationally useful: lifecycle, control point, connection coordinates, backup, and boundary rules.

### 4.2 Weak Points

- There are no automated tests in this plugin repository.
- There is no CI script proving:
  - `node --check server.js`
  - `node --check ui-shell/ui-shell.plugin.js`
  - manifest hash equals entry hash
  - package manifest SHA equals actual file hash
  - RBAC contains no write verbs for plugin SA
- Documentation is extensive, but the current README includes maturity claims that should be tied to test/CI evidence.

## 5. Security Findings

### Critical: Operand manifest leaks the AD bootstrap password

Evidence:

- `server.js` hardcodes `SAMBA_DEFAULTS.domainPass = 'OpenSphere2026!'`.
- `readSambaConfig()` returns `domainPass`.
- `/operand/manifests` returns both `config` and a Deployment env with `DOMAINPASS`.

Impact:

Anyone who can call the plugin API path or access the plugin service can retrieve the domain bootstrap password. Even if the value is described as a dev default, this is a directory control secret and should not be returned in a general manifest response.

Required fix:

- Remove hardcoded `domainPass` from source.
- Store domain credentials in a Kubernetes Secret owned by Foundation/Identity.
- `/operand/manifests` should reference `valueFrom.secretKeyRef`, not return cleartext.
- The returned `config` object must redact secrets.
- Consider splitting endpoints:
  - read-only preview manifest with redaction
  - controller-only internal manifest with secret references only

### High: Samba operand runs privileged and enables insecure LDAP

Evidence:

- Deployment container uses `securityContext: { privileged: true }`.
- Env includes `INSECURELDAP=true`.
- Env includes `NOCOMPLEXITY=true`.

Impact:

This is acceptable only as a dev/PoC exception. As a reference plugin pattern, it must be clearly marked as an operand-specific exception, not a plugin norm.

Required fix:

- Document this as a temporary dev exception in the report and UI.
- Add a production profile that disables insecure LDAP, requires LDAPS, and avoids or tightly justifies privileged mode.
- Use policy admission checks so future plugins cannot copy this privileged pattern accidentally.

### High: NetworkPolicy allows broad ingress to the AD service

Evidence:

- The generated NetworkPolicy contains ingress `ports` but no `from`.

Impact:

In Kubernetes NetworkPolicy semantics, an ingress rule without `from` allows traffic from all sources to those ports. That exposes LDAP/Kerberos/DNS/SMB broadly inside the cluster.

Required fix:

- Add explicit `from` selectors for expected consumers:
  - Keycloak pods
  - Foundation control-plane where needed
  - approved admin/debug namespace if intentionally allowed
- Keep DNS/Kerberos/SMB exposure as narrow as possible.

### Medium: Arbitrary PromQL proxy

Evidence:

- `/api/metrics/range` accepts `q` from URL query and forwards it to Prometheus.

Impact:

This plugin can become a generic Prometheus query proxy. If the console proxy route allows users beyond admins, it may expose unrelated metrics.

Required fix:

- Whitelist allowed metric names/prefixes such as `samba_ad_*`.
- Reject arbitrary PromQL operators, joins, and unrelated metric names.

### Medium: Excess manifest permission

Evidence:

- `permissions` includes `page:register`.
- The plugin intentionally does not call `registerPage`.

Impact:

This violates least privilege at the plugin capability layer. It is not an active exploit by itself, but the reference pattern should be clean.

Required fix:

- Remove `page:register` from `ui-shell.manifest.json` and `uipluginpackage.yaml` unless a future standalone page is actually registered.

### Medium: No backend request timeout

Evidence:

- Kubernetes, Prometheus, and Loki fetch calls do not use `AbortController` timeouts.

Impact:

Slow or unavailable dependencies can hang plugin responses and degrade the UI.

Required fix:

- Add a small helper for timed fetches.
- Use bounded timeout values per dependency.

### Low: Frontend relies on global token bridge

Evidence:

- UI reads `window.__OS_AUTH__`.

Impact:

This is the current console contract, but it is a broad global. It should eventually be replaced with a scoped auth helper from `ctx`.

Recommended fix:

- Extend plugin context with `ctx.auth.token()` or host-mediated request helpers.

## 6. Manual And OAA Verification

Manual contribution path is working:

- Plugin code calls `ctx.extensions.manual.contribute()`.
- The Extension Host syncs the contribution into OAA Gateway via `manual-seed`.
- Backbone PostgreSQL stores:
  - `oaa_knowledge_documents.source_id = 'plugin:samba-ad/operations'`
  - `source_type = 'manual'`
  - 2 chunks
  - metadata source `{ id: 'plugin:samba-ad', type: 'plugin', name: 'Samba-AD' }`

Global search is working:

- Query: `samba`
- Documentation result includes `Samba-AD 디렉터리 운영 매뉴얼`.
- Services result includes `samba-ad`.

OAA is working:

- A live OAA question about Samba-AD control boundaries returned a DeepSeek response grounded in the manual.
- OAA sources included:
  - `manual/plugin:samba-ad/operations#1`
  - `manual/plugin:samba-ad/operations#0`

Gap:

- The Samba manual has no concept graph entries and no action bindings yet.
- That is acceptable for explanatory Q&A.
- For controlled operations such as enabling/disabling Samba-AD or requesting backup, add explicit `ManualActionBinding` records later.

## 7. OpenSearch Plugin Guidance

For the next plugin/module `OpenSearch`, reuse this pattern with the following corrections:

1. **Repository contract**
   - `OpenSphere-plugin-opensearch`
   - `server.js`
   - `ui-shell/ui-shell.plugin.js`
   - `ui-shell/ui-shell.manifest.json`
   - `uipluginpackage.yaml`
   - `rbac.yaml`
   - `servicemonitor.yaml`
   - `docs/`

2. **Decide hosting model**
   - If OpenSearch belongs under Foundation/Data, use `hostRef: foundation` and no `registerPage`.
   - If it is a first-class top-level service, remove `hostRef` and call `registerPage`.

3. **Do not copy Samba secrets pattern**
   - No hardcoded passwords.
   - No cleartext credentials in `/operand/manifests`.
   - Use `secretKeyRef` and redacted config.

4. **Operand declaration**
   - Plugin may own the OpenSearch operand manifest.
   - Controller applies it.
   - Destructive lifecycle and PVC retention rules must be explicit.

5. **Read-only plugin SA**
   - Plugin SA reads only OpenSearch/FSS status.
   - Write operations route through host/controller with user impersonation.

6. **Manual contribution**
   - Contribute an OpenSearch operations manual on activation.
   - Include:
     - lifecycle owner
     - endpoint coordinates
     - data retention
     - snapshot/backup
     - security boundary
     - what console/OAA must not do

7. **OAA action bindings**
   - Add action bindings only after a manual section states the allowed operation.
   - Example future bindings:
     - inspect OpenSearch cluster health
     - view indices
     - trigger snapshot
     - restart deployment with confirmation

8. **Metrics and logs**
   - Expose only `opensearch_*` or plugin-owned metrics through a whitelist.
   - Query logs through fixed LogQL templates, not arbitrary user-provided queries.

## 8. Audit Conclusion

`OpenSphere-plugin-samba-ad` is a good architectural sample for OpenSphere's plugin future. It proves the core model:

- independent signed plugin
- subShell-hosted composition
- self-owned UI/backend/manual/CLI/metrics/operand declaration
- canonical Manual Registry integration
- OAA retrieval and citation
- read-only plugin service account
- host-mediated write path

Before using it as a production security baseline, fix the critical credential exposure, narrow network access, remove unused capability grants, and add automated CI checks.

Final status: **Audit complete. Approved as a reference architecture with required security hardening before production reuse.**
