import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname);
const keyPath = process.env.DUPA_SIGNING_KEY;
if (!keyPath) throw new Error('DUPA_SIGNING_KEY must point to the approved P-256 signing key');
const keyId = process.env.DUPA_SIGNING_KEY_ID || 'opensphere-plugins-v4';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const signature = (text, key) => sign('sha256', Buffer.from(text), { key, dsaEncoding: 'ieee-p1363' }).toString('base64');
const key = createPrivateKey(readFileSync(keyPath));

const entryPath = resolve(root, 'ui-shell/ui-shell.plugin.js');
const manifestPath = resolve(root, 'ui-shell/ui-shell.manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
manifest.entrySha256 = hash(readFileSync(entryPath));
const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
writeFileSync(manifestPath, manifestText);
writeFileSync(resolve(root, 'ui-shell/ui-shell.manifest.json.sig'), `${signature(manifestText, key)}\n`);

const descriptor = {
  schemaVersion: 1,
  id: manifest.id,
  kind: manifest.kind,
  displayName: manifest.title,
  version: manifest.version,
  owner: 'opensphere-platform',
  description: manifest.description,
  hostRef: manifest.hostRef,
  hostApiVersion: manifest.hostApiVersion,
  hostCompat: manifest.hostCompat,
  shellCompat: manifest.shellCompat,
  sdkVersion: manifest.sdkVersion,
  permissions: manifest.permissions,
  permissionProfile: 'cluster-observer-v1',
  runtime: {
    port: 8080,
    healthPath: '/healthz',
    serviceAccountName: 'opensphere-plugin-samba-ad',
    resources: { cpuRequest: '25m', memoryRequest: '64Mi', cpuLimit: '250m', memoryLimit: '256Mi' },
  },
  manifest: {
    path: '/plugins/ui-shell.manifest.json',
    sha256: hash(manifestText),
    signaturePath: '/plugins/ui-shell.manifest.json.sig',
  },
  trust: { keyId },
  api: { basePath: manifest.apiBase },
  contributions: manifest.contributions,
};
const descriptorText = JSON.stringify(descriptor);
const sdkEntry = resolve(process.env.OPENSPHERE_SDK || resolve(root, '../OpenSphere-SDK'), 'dist/index.js');
const { validateModulePackage } = await import(pathToFileURL(sdkEntry));
const issues = validateModulePackage(descriptor);
if (issues.length) throw new Error(`OpenSphere SDK rejected module package: ${JSON.stringify(issues)}`);
writeFileSync(resolve(root, 'module-package.json'), descriptorText);
writeFileSync(resolve(root, 'module-package.json.sig'), `${signature(descriptorText, key)}\n`);

const packagePath = resolve(root, 'uipluginpackage.yaml');
const packageYaml = readFileSync(packagePath, 'utf8');
const manifestSha = hash(manifestText);
const pinnedPackageYaml = packageYaml.replace(
  /(\n\s{4}sha256:\s*")[a-f0-9]{64}(")/,
  `$1${manifestSha}$2`,
);
if (pinnedPackageYaml === packageYaml && !packageYaml.includes(`sha256: "${manifestSha}"`)) {
  throw new Error('uipluginpackage.yaml manifest sha256 pin was not updated');
}
writeFileSync(packagePath, pinnedPackageYaml);
console.log(`packaged ${manifest.id}@${manifest.version} manifest=${manifestSha}`);
