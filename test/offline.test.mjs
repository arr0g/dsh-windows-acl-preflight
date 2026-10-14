/**
 * Offline tests for dsh-windows-acl-preflight.
 *
 *   node --test test/offline.test.mjs
 *
 * Every process-spawning path is driven through an injected fake runner, except
 * the last test, which really calls `icacls`/`whoami` on a throwaway directory.
 *
 * To integration-test the real failing condition (a fresh directory under a
 * drive root, which inherits no Full-control ACE for the user), point the test
 * at one:
 *
 *   $env:DSH_ACL_PREFLIGHT_TEST_DIR = 'E:\acl-preflight-test'
 *   node --test test/offline.test.mjs
 *
 * The directory is created if missing and left in place when it was named by the
 * environment.
 */

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { apply, inject, mount, name } from '../lib/index.js'
import { capabilitySid, helperPath, makePropagator, parseHelperStats } from '../lib/propagate.js'
import { canonicalPath, grantTarget, makeRepairer, runCommand } from '../lib/repair.js'

const SID = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
const windowsOnly = process.platform === 'win32' ? false : 'Windows only'

/** @param {number} [ms] */
const delay = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * A cordis-shaped context with no real services.
 *
 * @param {{ workspaceRoot?: string, sandbox?: unknown, services?: Record<string, unknown> }} [options]
 */
function fakeContext(options = {}) {
  const workspaceRoot = options.workspaceRoot ?? 'E:\\ws-root'
  const services = { ...(options.services ?? {}) }
  const handlers = new Map()
  const logs = []
  const logger = {
    debug: (message) => logs.push(['debug', message]),
    info: (message) => logs.push(['info', message]),
    warn: (message) => logs.push(['warn', message]),
    error: (message) => logs.push(['error', message]),
  }
  const ctx = {
    sandboxPolicy: { defaultMode: 'workspace-write', workspaceRoot },
    logger,
    get: (serviceName) => (serviceName === 'sandbox' ? options.sandbox : services[serviceName]),
    on: (event, handler) => {
      handlers.set(event, handler)
      return () => handlers.delete(event)
    },
    inject: () => () => {},
  }
  return {
    ctx,
    logs,
    services,
    events: () => [...handlers.keys()],
    fire: async (event, payload) => handlers.get(event)?.(payload),
  }
}

/**
 * A fake `runCommand` that answers per executable and records every call.
 *
 * @param {Record<string, (args: string[]) => { code: number, stdout?: string, stderr?: string }>} script
 */
function fakeRun(script) {
  const calls = []
  const run = async (file, args) => {
    calls.push({ file, args })
    const answer = script[file] ?? script[file.replace(/\.exe$/, '')]
    const result = answer ? answer(args) : { code: 0 }
    return { code: result.code, stdout: result.stdout ?? '', stderr: result.stderr ?? '', error: undefined }
  }
  return { run, calls, icacls: () => calls.filter((call) => call.file === 'icacls.exe') }
}

/** A fake propagator that records the directories it was asked about. */
function fakePropagator() {
  const calls = []
  return {
    calls,
    propagate: async (dir, propagateOptions = {}) => (calls.push({ dir, ...propagateOptions }), { ok: true, dir, objects: 1, failures: 0 }),
  }
}

test('module contract: named exports only, as the loader requires', async () => {
  const module = await import('../lib/index.js')
  assert.equal(name, 'dsh-windows-acl-preflight')
  assert.deepEqual(inject, ['sandboxPolicy'])
  assert.equal(typeof apply, 'function')
  assert.ok(!('default' in module), 'a default export would discard `inject` and silently no-op the plugin')
})

test('canonicalPath and grantTarget parse DSH failures', { skip: windowsOnly }, () => {
  assert.equal(canonicalPath('E:\\my-workspace\\'), 'E:\\my-workspace')
  assert.equal(canonicalPath('  E:\\ws  '), 'E:\\ws')
  assert.equal(canonicalPath(''), undefined)
  assert.equal(canonicalPath(undefined), undefined)
  assert.equal(grantTarget(new Error('SetNamedSecurityInfoW failed (Win32 5): grantWrite(E:\\my-workspace)')), 'E:\\my-workspace')
  assert.equal(grantTarget(new Error('something else failed')), undefined)
})

test('repairer grants Full control once per directory and memoizes case-insensitively', { skip: windowsOnly }, async () => {
  const fake = fakeRun({
    'whoami.exe': () => ({ code: 0, stdout: `"DOMAIN\\user","${SID}"\r\n` }),
    'icacls.exe': () => ({ code: 0, stdout: 'Successfully processed 1 files; Failed processing 0 files.' }),
  })
  const repairer = makeRepairer({ run: fake.run })

  const first = await repairer.repair('E:\\ws-one\\')
  assert.equal(first.ok, true)
  assert.deepEqual(fake.icacls().at(-1).args, ['E:\\ws-one', '/grant:r', `*${SID}:(OI)(CI)(F)`])

  const second = await repairer.repair('e:\\WS-ONE')
  assert.equal(second.ok, true)
  assert.equal(second.cached, true)
  assert.equal(fake.icacls().length, 1, 'a memoized directory must not spawn icacls again')
})

test('repairer reports, without throwing, when it cannot resolve the user SID', { skip: windowsOnly }, async () => {
  const repairer = makeRepairer({ run: async () => ({ code: 1, stdout: '', stderr: 'ERROR: no such user\n' }) })
  const result = await repairer.repair('E:\\ws-nosid')
  assert.equal(result.ok, false)
  assert.match(String(result.detail), /whoami exited 1 without a user SID/)
})

test('repairer keeps a failed repair retryable', { skip: windowsOnly }, async () => {
  let attempts = 0
  const repairer = makeRepairer({
    retryDelayMs: 1,
    run: async (file) => {
      if (file === 'whoami.exe') return { code: 0, stdout: `"DOMAIN\\user","${SID}"`, stderr: '' }
      attempts += 1
      return attempts === 1
        ? { code: 5, stdout: '', stderr: 'E:\\ws-flaky: Access is denied.\r\nFailed processing 1 files.' }
        : { code: 0, stdout: 'ok', stderr: '' }
    },
  })

  const first = await repairer.repair('E:\\ws-flaky')
  assert.equal(first.ok, false)
  assert.equal(first.detail, 'Failed processing 1 files.')

  await delay(25)
  const second = await repairer.repair('E:\\ws-flaky')
  assert.equal(second.ok, true)
  assert.equal(attempts, 2)
})

test('mount repairs the configured root, every session cwd and the agent cwd', { skip: windowsOnly }, async () => {
  const repairs = []
  const propagation = fakePropagator()
  const statCwds = new Map([['s-stat', 'E:\\ws-stat']])
  const env = fakeContext({
    workspaceRoot: 'E:\\ws-root',
    services: { sessionPersistence: { stat: async (id) => (statCwds.has(id) ? { header: { cwd: statCwds.get(id) } } : undefined) } },
  })
  mount(
    env.ctx,
    { verbose: true },
    { repairer: { repair: async (dir, repairOptions = {}) => (repairs.push({ dir, ...repairOptions }), { ok: true, dir }) }, propagator: propagation },
  )

  assert.deepEqual(env.events().sort(), ['agent/created', 'session/created'])
  await delay()
  assert.deepEqual(repairs.map((repair) => repair.dir), ['E:\\ws-root'], 'prong 0 repairs the configured fallback root')
  assert.deepEqual(propagation.calls.map((call) => call.dir), ['E:\\ws-root'], 'prong 0 also propagates the root tree')

  await env.fire('session/created', { id: 's1', header: { cwd: 'E:\\ws-one' } })
  await delay()
  assert.ok(repairs.some((repair) => repair.dir === 'E:\\ws-one'), 'prong 1 repairs the session cwd')

  await env.fire('agent/created', { agent: { id: 's1' } })
  assert.equal(repairs.at(-1).dir, 'E:\\ws-one', 'prong 2 reuses the cwd remembered from session/created')

  await env.fire('agent/created', { agent: { id: 's-stat' } })
  assert.equal(repairs.at(-1).dir, 'E:\\ws-stat', 'prong 2 falls back to sessionPersistence.stat')

  await env.fire('agent/created', { agent: { id: 's-nowhere' } })
  assert.equal(repairs.at(-1).dir, 'E:\\ws-root', 'prong 2 finally falls back to the configured root')

  assert.ok(env.logs.some(([level, message]) => level === 'info' && message.includes('E:\\ws-one')))
})

test('mount never rejects an awaited serial event', { skip: windowsOnly }, async () => {
  const repairs = []
  const env = fakeContext({
    workspaceRoot: 'E:\\ws-root',
    services: {
      sessionPersistence: {
        stat: async () => {
          throw new Error('persistence exploded')
        },
      },
    },
  })
  mount(env.ctx, {}, { repairer: { repair: async (dir) => (repairs.push({ dir }), { ok: true, dir }) }, propagator: fakePropagator() })
  await env.fire('agent/created', { agent: { id: 's-boom' } })
  assert.equal(repairs.at(-1).dir, 'E:\\ws-root')
})

test('mount pre-repairs sandbox.confine, propagates after it, and retries a grant failure once', { skip: windowsOnly }, async () => {
  const repairs = []
  const propagation = fakePropagator()
  let confineCalls = 0
  const sandbox = {
    confine: async (argv, policy) => {
      confineCalls += 1
      if (confineCalls === 1) throw new Error('SetNamedSecurityInfoW failed (Win32 5): grantWrite(E:\\ws-two)')
      return { argv, mode: policy.mode }
    },
  }
  const env = fakeContext({ workspaceRoot: 'E:\\ws-root', sandbox })
  mount(
    env.ctx,
    {},
    { repairer: { repair: async (dir, repairOptions = {}) => (repairs.push({ dir, ...repairOptions }), { ok: true, dir }) }, propagator: propagation },
  )
  await delay()

  const result = await sandbox.confine(['pwsh', '-NoProfile'], { mode: 'workspace-write', workspaceRoot: 'E:\\ws-two' }, undefined)
  assert.equal(confineCalls, 2, 'the wrapper retries the confined call exactly once')
  assert.equal(result.mode, 'workspace-write')
  assert.ok(
    repairs.some((repair) => repair.dir === 'E:\\ws-two' && repair.force === true),
    'the retry forces an uncached repair of the path named in the error',
  )
  assert.ok(
    propagation.calls.some((call) => call.dir === 'E:\\ws-two'),
    'the confined tree is propagated before the child can be spawned',
  )

  const before = repairs.length
  const propagationBefore = propagation.calls.length
  await sandbox.confine(['pwsh'], { mode: 'danger-full-access', workspaceRoot: 'E:\\ws-three' })
  assert.equal(repairs.length, before, 'danger-full-access needs no repair')
  assert.equal(propagation.calls.length, propagationBefore, 'danger-full-access needs no propagation either')
})

test('propagator re-evaluates inheritance then runs the label helper, once per root', { skip: windowsOnly }, async () => {
  const fake = fakeRun({
    'icacls.exe': (args) => (args.length === 1 ? { code: 0, stdout: 'E:\\ws-tree S-1-4-11-22:(OI)(CI)(W,D,DC)\r\nE:\\ws-tree BUILTIN\\Users:(I)(RX)\r\n' } : { code: 0, stdout: 'Successfully processed 4 files; Failed processing 0 files.' }),
    'powershell.exe': () => ({ code: 0, stdout: 'objects=7 failures=0 firstRc=0 ms=3\r\n' }),
  })
  const propagator = makePropagator({ run: fake.run })

  const first = await propagator.propagate('E:\\ws-tree\\')
  assert.equal(first.ok, true)
  assert.equal(first.sid, 'S-1-4-11-22')
  assert.equal(first.objects, 7)
  assert.equal(first.failures, 0)

  assert.deepEqual(fake.icacls().at(-1).args, ['E:\\ws-tree', '/inheritance:e', '/T', '/C', '/Q'], 'the DACL pass enables inheritance tree-wide')
  const powerShell = fake.calls.filter((call) => call.file === 'powershell.exe')
  assert.equal(powerShell.length, 1)
  assert.deepEqual(powerShell[0].args.slice(0, 6), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', propagator.helperPath])
  assert.deepEqual(powerShell[0].args.slice(6), ['-Path', 'E:\\ws-tree'])

  const spawns = fake.calls.length
  const second = await propagator.propagate('e:\\WS-TREE')
  assert.equal(second.cached, true)
  assert.equal(fake.calls.length, spawns, 'a memoized root must not spawn again')
})

test('propagator skips a workspace DSH has not provisioned yet, without memoizing it', { skip: windowsOnly }, async () => {
  let reads = 0
  const propagator = makePropagator({
    run: async (file, args) => {
      if (file !== 'icacls.exe') return { code: 0, stdout: 'objects=1 failures=0 firstRc=0 ms=1', stderr: '', error: undefined }
      reads += 1
      return { code: 0, stdout: reads === 1 ? 'E:\\ws-plain BUILTIN\\Users:(I)(RX)\r\n' : 'E:\\ws-plain S-1-4-11-22:(OI)(CI)(W,D,DC)\r\n', stderr: '', error: undefined }
    },
  })

  const first = await propagator.propagate('E:\\ws-plain')
  assert.equal(first.ok, true)
  assert.equal(first.skipped, 'no-capability-sid')

  const second = await propagator.propagate('E:\\ws-plain')
  assert.equal(second.skipped, undefined, 'a later call must re-read the root once DSH has granted it')
  assert.equal(second.sid, 'S-1-4-11-22')
})

test('propagator reports a failed DACL pass instead of throwing', { skip: windowsOnly }, async () => {
  const propagator = makePropagator({
    run: async (file, args) =>
      file !== 'icacls.exe'
        ? { code: 0, stdout: '', stderr: '', error: undefined }
        : args.length === 1
          ? { code: 0, stdout: 'E:\\ws-bad S-1-4-9-9:(OI)(CI)(W,D,DC)\r\n', stderr: '', error: undefined }
          : { code: 5, stdout: '', stderr: 'E:\\ws-bad\\child: Access is denied.\r\n', error: undefined },
  })

  const result = await propagator.propagate('E:\\ws-bad')
  assert.equal(result.ok, false)
  assert.equal(result.stage, 'dacl')
  assert.match(String(result.detail), /Access is denied/)
})

test('capabilitySid and parseHelperStats read what the tools really print', { skip: windowsOnly }, () => {
  assert.equal(capabilitySid('E:\\my-workspace S-1-4-11-22:(OI)(CI)(W,D,DC)'), 'S-1-4-11-22')
  assert.equal(capabilitySid('E:\\my-workspace BUILTIN\\Users:(F)\r\n'), undefined)
  assert.deepEqual(parseHelperStats('objects=4040 failures=249 firstRc=5 ms=1\r\n'), { objects: 4040, failures: 249, firstRc: 5, ms: 1 })
  assert.deepEqual(parseHelperStats('garbage'), { objects: undefined, failures: undefined, firstRc: undefined, ms: undefined })
})

test('integration: the repair really grants the signed-in account', { skip: windowsOnly }, async (t) => {
  const named = process.env.DSH_ACL_PREFLIGHT_TEST_DIR
  let dir = named
  if (dir) {
    await mkdir(dir, { recursive: true })
  } else {
    dir = await mkdtemp(join(tmpdir(), 'dsh-acl-preflight-'))
    // Clean up the auto-created workspace through a test hook rather than at the
    // end of the body: a run that failed an assertion halfway used to leak one
    // directory in %TEMP% every time (an interrupted run leaked one too). A named
    // directory belongs to the caller, so it is never removed. `maxRetries` covers
    // the brief window in which a just-exited powershell.exe still holds a handle.
    t.after(() =>
      rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch((error) =>
        process.stderr.write(`warning: could not remove the test workspace ${dir}: ${error.message}\n`),
      ),
    )
  }

  const repairer = makeRepairer()
  const sid = await repairer.userSid()
  assert.match(sid, /^S-1-[0-9-]+$/)

  const result = await repairer.repair(dir, { force: true })
  assert.equal(result.ok, true, `icacls failed: ${JSON.stringify(result)}`)

  const listing = await new Promise((resolve, reject) => {
    execFile('icacls.exe', [dir], (error, stdout) => (error ? reject(error) : resolve(String(stdout))))
  })
  // `icacls` resolves the SID back to the account name. The repair adds an
  // INHERITABLE Full-control ACE, so it prints as `account:(OI)(CI)(F)`; an
  // inherited ACE from the parent prints as `account:(I)(OI)(CI)(F)`. Matching
  // the optional OI/CI pair while refusing the `(I)` marker therefore accepts
  // exactly the explicit ACE this repair adds, on any starting DACL.
  const account = await new Promise((resolve, reject) => {
    execFile('whoami.exe', ['/user', '/fo', 'csv', '/nh'], (error, stdout) => (error ? reject(error) : resolve(String(stdout))))
  })
  const accountName = /^"([^"]+)"/.exec(account.trim())?.[1]
  assert.ok(accountName, `could not read the account name from: ${account}`)
  const escaped = accountName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const explicit = new RegExp(`${escaped}:\\((?:OI\\)\\(CI\\))?\\(F\\)`, 'i')
  assert.ok(explicit.test(listing), `expected an explicit (non-inherited) ${accountName}:(F) ACE in icacls output:\n${listing}`)

  // The shipped label helper must really write the Low label on every object, and
  // it can only do that because the repair made the Full-control ACE inheritable
  // (WRITE_OWNER is what a SACL write needs).
  const child = join(dir, 'pack', 'config')
  await mkdir(child, { recursive: true })
  const label = await runCommand(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helperPath(), '-Path', dir],
    { timeout: 120_000 },
  )
  const stats = parseHelperStats(label.stdout)
  assert.equal(label.code, 0, `the label helper exited ${label.code}: ${label.stderr}`)
  assert.equal(stats.firstRc, 0, `the label helper failed on an object: ${label.stdout.trim()}`)
  assert.equal(stats.failures, 0, `the label helper could not label every object: ${label.stdout.trim()}`)
  assert.ok((stats.objects ?? 0) >= 3, `the label helper walked too little of the tree: ${label.stdout.trim()}`)

})
