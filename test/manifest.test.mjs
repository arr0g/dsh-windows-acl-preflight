/**
 * Manifest and packaging checks.
 *
 *   node --test test/manifest.test.mjs
 *
 * These are hand-written filesystem-and-JSON assertions — **not** a JSON-Schema
 * validator: every rule below is spelled out by hand, so anything the upstream
 * schema grows must be added here explicitly. There is no network, no `icacls`
 * and no Windows-only API. They therefore run on every CI leg, and they guard the
 * promises this repository makes by shipping `dsh-plugin.json` plus a
 * display-facing `package.json`:
 *
 *   - the manifest stays parseable, LF-only, BOM-free and internally consistent
 *     with `package.json`;
 *   - every path the manifest points at really exists, and the icon stays
 *     within the size the plugin manager accepts (256 KiB);
 *   - the tree never grows a hard-coded path or identifier from the machine it
 *     was written on (see the last test — that one is a regression guard for
 *     "don't leak personal data", not a style check).
 */

import assert from 'node:assert/strict'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (relative) => readFileSync(join(root, relative), 'utf8')

const manifest = JSON.parse(read('dsh-plugin.json'))
const pkg = JSON.parse(read('package.json'))

const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
const NAMESPACED_ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9][a-z0-9-]*)+$/
/** A 40-hex revision, either as a path segment or as `?rev=`. */
const PINNED_REVISION = /(?:\/|\?rev=)[0-9a-f]{40}(?:\/|$)/

/** The only account SIDs allowed to appear: obviously fake ones. */
const SYNTHETIC_USER_SIDS = new Set([
  'S-1-5-21-1111111111-2222222222-3333333333-1001', // test/offline.test.mjs
  'S-1-5-21-1-2-3-1001', // lib/repair.js, in a comment
])
const SYNTHETIC_CAPABILITY_SIDS = new Set([
  'S-1-4-11-22',
  'S-1-4-9-9',
])

/** Every text file that ships in the repository. */
const SHIPPED_TEXT_FILES = [
  '.gitattributes',
  '.github/workflows/test.yml',
  '.gitignore',
  'LICENSE',
  'README.md',
  'README.zh.md',
  'cordis.patch.yml',
  'docs/terminal-output.svg',
  'dsh-plugin.json',
  'install.ps1',
  'lib/acl-helper.ps1',
  'lib/index.js',
  'lib/propagate.js',
  'lib/repair.js',
  'locale/en.json',
  'locale/zh.json',
  'package.json',
  'test/offline.test.mjs',
]

test('dsh-plugin.json is parseable JSON with no BOM and no CR bytes', () => {
  const raw = readFileSync(join(root, 'dsh-plugin.json'))
  assert.notEqual(raw[0], 0xef, 'the manifest must not start with a UTF-8 BOM')
  assert.equal(raw.includes(13), false, 'the manifest must use LF, not CRLF')
  assert.equal(raw[raw.length - 1], 10, 'the manifest must end with exactly one LF')
  assert.doesNotThrow(() => JSON.parse(raw.toString('utf8')))
})

test('the manifest declares a namespaced identity that matches package.json', () => {
  assert.equal(manifest.manifestVersion, '0.15')
  assert.match(manifest.id, NAMESPACED_ID, '`id` must be namespaced kebab-case')
  assert.equal(manifest.name, pkg.name)
  assert.equal(manifest.version, pkg.version)
  assert.match(manifest.version, SEMVER)
  assert.equal(manifest.license, pkg.license)
  assert.match(read('LICENSE'), /^MIT License/, 'LICENSE must be the MIT text')
})

test('$schema is pinned to an immutable revision of the published schema', () => {
  assert.match(manifest.$schema, /^https:\/\/raw\.githubusercontent\.com\/T-Auto\/dsh-std\//)
  assert.match(manifest.$schema, /dsh-plugin-0\.15\.schema\.json$/)
  // A branch name here would silently change under the plugin's feet.
  assert.match(manifest.$schema, PINNED_REVISION, 'the URL must pin a 40-hex revision, not a branch')
})

test('the host facet points at a file that exists', () => {
  assert.equal(manifest.facets.host.apiVersion, 'v1alpha1')
  assert.equal(manifest.facets.host.entry, pkg.main)
  assert.ok(existsSync(join(root, manifest.facets.host.entry)), `${manifest.facets.host.entry} must exist`)
  assert.ok(Array.isArray(manifest.requires.contracts))
  assert.ok(Array.isArray(manifest.subscriptions))
})

test('every declared permission is namespaced, unique, scoped and justified', () => {
  const namespace = `${manifest.id.split('.')[0]}.`
  const seen = new Set()
  for (const permission of manifest.permissions) {
    assert.ok(permission.name.startsWith(namespace), `${permission.name} must start with ${namespace}`)
    assert.equal(seen.has(permission.name), false, `${permission.name} is declared twice`)
    seen.add(permission.name)
    assert.ok(typeof permission.scope === 'string' && permission.scope.length > 0)
    assert.ok(typeof permission.reason === 'string' && permission.reason.length > 10)
  }
  assert.ok(seen.size > 0, 'the manifest must declare the permissions the plugin really uses')
})

test('contributes only carries x- keys, and x-display resolves to real files', () => {
  for (const key of Object.keys(manifest.contributes)) assert.match(key, /^x-/)

  const display = manifest.contributes['x-display']
  assert.ok(Array.isArray(display) && display.length === 1)
  const [entry] = display
  assert.equal(entry.icon, pkg.icon, 'the manifest icon and package.json `icon` must agree')
  for (const field of ['title', 'description']) assert.ok(entry[field].length > 0, `x-display needs ${field}`)

  const icon = statSync(join(root, entry.icon))
  assert.ok(icon.size <= 256 * 1024, 'the plugin manager only accepts icons up to 256 KiB')

  assert.ok(entry.locales.length >= 2)
  for (const locale of entry.locales) {
    const parsed = JSON.parse(read(locale))
    assert.ok(parsed.meta.title.length > 0, `${locale} needs meta.title`)
    assert.ok(parsed.meta.description.length > 0, `${locale} needs meta.description`)
  }
})

test('the manifest names the published repository, consistently with package.json', () => {
  const url = manifest.source.repository
  assert.match(url, /^https:\/\/github\.com\/[^/]+\/[^/]+$/)
  assert.equal(pkg.repository.url, `git+${url}.git`)
  assert.equal(pkg.homepage, `${url}#readme`)
  assert.equal(pkg.bugs.url, `${url}/issues`)
})

test('package.json stays installable by pnpm and displayable by the plugin manager', () => {
  assert.equal('private' in pkg, false, 'pnpm refuses to install a package marked `private`')
  assert.equal(pkg.type, 'module')
  assert.equal(pkg.main, manifest.facets.host.entry)
  assert.ok(pkg.exports['./locale/*.json'], 'the manager reads <package>/locale/en.json through this export')
  assert.ok(pkg.icon, 'the manager reads the icon from package.json, not from the manifest')
  assert.ok(pkg.engines.node)
  assert.ok(pkg.peerDependencies['@deepseek-ai/dsh'])
  assert.ok(pkg.peerDependencies['@deepseek-ai/cordis'])
  assert.equal(pkg.dsh.bundle.patch, './cordis.patch.yml')

  // The bundle patch and install.ps1 must mount the plugin under the same id,
  // or the two installation routes would produce two different plugins.
  const entryIdMatch = read('install.ps1').match(/\$entryId = '([^']+)'/)
  assert.ok(entryIdMatch, 'install.ps1 must still declare `$entryId = ...`')
  const entryId = entryIdMatch[1]
  assert.ok(read('cordis.patch.yml').includes(`id: ${entryId}`), `cordis.patch.yml must mount id: ${entryId}`)
})

test('the tree carries no path or account from the machine it was written on', () => {
  // This file is deliberately not in SHIPPED_TEXT_FILES: it has to spell the
  // forbidden patterns out, so scanning itself would always fail.
  const forbidden = [/ASUS/, /YMH/, /dsh-home/, /ATM10SKY/, /2ec44c86/, /#DSH/, /<YOUR NAME>/, /<用户名>/, /<你的用户名>/, /\bTODO\b/, /\bFIXME\b/]

  for (const file of SHIPPED_TEXT_FILES) {
    const text = read(file)
    for (const pattern of forbidden) {
      assert.equal(pattern.test(text), false, `${file} must not contain ${pattern}`)
    }
    for (const sid of text.match(/S-1-5-21-\d+(?:-\d+)*/g) ?? []) {
      assert.ok(SYNTHETIC_USER_SIDS.has(sid), `${file} must not contain the real user SID (found ${sid})`)
    }
    for (const sid of text.match(/S-1-4-\d+(?:-\d+)*/g) ?? []) {
      assert.ok(SYNTHETIC_CAPABILITY_SIDS.has(sid), `${file} must not contain a real capability SID (found ${sid})`)
    }
  }
})

test('the manifest declares nothing the schema would reject at the root', () => {
  // dsh-std's dsh-plugin-0.15.schema.json sets `additionalProperties: false` on
  // the root, so an unknown top-level key is a schema violation. This test locks
  // the known root keys; `x-` extensions stay allowed.
  const KNOWN_ROOT_KEYS = ['$schema', 'manifestVersion', 'id', 'name', 'version', 'license', 'source', 'facets', 'requires', 'permissions', 'contributes', 'subscriptions']
  const extra = Object.keys(manifest).filter((key) => !key.startsWith('x-') && !KNOWN_ROOT_KEYS.includes(key))
  assert.deepEqual(extra, [], 'dsh-plugin.json must not carry unknown root keys (schema: additionalProperties: false)')
})
