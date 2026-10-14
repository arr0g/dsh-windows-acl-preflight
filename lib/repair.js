/**
 * Windows ACL repair for DSH's workspace-write sandbox.
 *
 * DSH's Windows sandbox runner (`@deepseek-ai/dsh-sandbox-windows-acl`) prepares
 * a workspace root in ONE `SetNamedSecurityInfoW` call that must, at the same
 * time:
 *
 *   1. add the capability-SID allow ACE (mask 0x110156) for the sandboxed child,
 *   2. add a `DELETE_CHILD` deny ACE for Everyone, and
 *   3. write the Low mandatory integrity label — which lives in the SACL.
 *
 * Step 3 is the problem. An object's owner holds only the *implicit* rights
 * `READ_CONTROL` and `WRITE_DAC`; writing a SACL additionally needs
 * `WRITE_OWNER`. A directory that grants the signed-in account merely `Modify`
 * (exactly what a directory created under a drive root inherits, via
 * `NT AUTHORITY\Authenticated Users`) therefore fails the whole call:
 *
 *   SetNamedSecurityInfoW failed (Win32 5): grantWrite(<workspace root>)
 *
 * and every confined `pwsh` call in that workspace dies before the child is ever
 * spawned. The bundled `diagnose-windows-sandbox-acl` skill repairs this, but it
 * has to be run by hand, per workspace, from an unconfined shell.
 *
 * This module does that repair automatically and unelevated: it grants the
 * signed-in account Full control on the offending directory with `icacls`:
 *
 *   icacls.exe <dir> /grant:r *<user SID>:(OI)(CI)(F)
 *
 * That works precisely because the caller already OWNS the directory (ownership
 * gives the implicit `WRITE_DAC` the repair itself needs). It is a DACL-only,
 * additive, idempotent edit: existing ACEs — including DSH's own denies and
 * capability grant — are untouched. The `(OI)(CI)` flags make the ACE
 * inheritable so it also reaches pre-existing children; without them a child
 * directory that windows has already stamped with explicit ACEs (or with
 * inheritance disabled) stays un-repairable by the later label pass, which needs
 * `WRITE_OWNER` on each object it touches.
 */

import { execFile } from 'node:child_process'
import { resolve } from 'node:path'

export const DEFAULT_TIMEOUT_MS = 15_000
export const DEFAULT_RETRY_DELAY_MS = 5_000

/** Upper bound on memoized directories; a session map, not a filesystem index. */
const MAX_CACHE_ENTRIES = 512

/** Matches a local or domain SID, e.g. `S-1-5-21-1-2-3-1001`. */
const USER_SID = /S-1-[0-9]+(?:-[0-9]+)+/

/**
 * Run a command and settle with its exit code instead of rejecting.
 *
 * @param {string} file — executable to run (resolved through `PATH`).
 * @param {string[]} args — argv, passed as separate elements (no shell quoting).
 * @param {{ timeout?: number }} [options]
 * @returns {Promise<{ code: number, stdout: string, stderr: string, error?: unknown }>}
 */
export function runCommand(file, args, options = {}) {
  return new Promise((settle) => {
    try {
      execFile(file, args, { windowsHide: true, ...options }, (error, stdout, stderr) => {
        const code = error ? (typeof error.code === 'number' ? error.code : 1) : 0
        settle({ code, stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), error })
      })
    } catch (error) {
      settle({ code: 1, stdout: '', stderr: '', error })
    }
  })
}

/**
 * Normalize a directory for use as a cache key and as an `icacls` argument.
 *
 * @param {unknown} dir
 * @returns {string | undefined} absolute path without a trailing separator.
 */
export function canonicalPath(dir) {
  if (typeof dir !== 'string') return undefined
  const trimmed = dir.trim()
  if (!trimmed) return undefined
  let absolute
  try {
    absolute = resolve(trimmed)
  } catch {
    return undefined
  }
  return absolute.replace(/[\\/]+$/, '') || absolute
}

/**
 * Extract the directory out of DSH's grant failure, whose message ends in
 * `grantWrite(<path>)`.
 *
 * @param {unknown} error
 * @returns {string | undefined}
 */
export function grantTarget(error) {
  const text = error instanceof Error ? error.message : String(error ?? '')
  const match = /grantWrite\((.+)\)/.exec(text)
  return match ? match[1].trim() : undefined
}

/** @param {unknown} error */
export function describeError(error) {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Build a repairer.
 *
 * @param {{
 *   run?: typeof runCommand,
 *   timeoutMs?: number,
 *   retryDelayMs?: number,
 *   icacls?: string,
 *   whoami?: string,
 * }} [options] — `run` is injectable so the offline tests never spawn a process.
 */
export function makeRepairer(options = {}) {
  const run = options.run ?? runCommand
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS
  const icacls = options.icacls ?? 'icacls.exe'
  const whoami = options.whoami ?? 'whoami.exe'

  /** @type {Map<string, Promise<{ ok: boolean, dir: string }>>} */
  const cache = new Map()
  /** @type {Promise<string> | undefined} */
  let sidPromise

  /** The signed-in account's SID, resolved once per process. */
  function userSid() {
    sidPromise ??= (async () => {
      const result = await run(whoami, ['/user', '/fo', 'csv', '/nh'], { timeout: timeoutMs })
      const match = USER_SID.exec(result.stdout)
      if (result.code !== 0 || !match) {
        throw new Error(`whoami exited ${result.code} without a user SID: ${lastLine(result.stderr || result.stdout)} (a confined environment may block piped child processes)`)
      }
      return match[0]
    })()
    return sidPromise
  }

  /** Grant the signed-in account Full control on one directory. */
  async function grant(target) {
    try {
      const sid = await userSid()
      const result = await run(icacls, [target, '/grant:r', `*${sid}:(OI)(CI)(F)`], { timeout: timeoutMs })
      if (result.code === 0) return { ok: true, dir: target }
      return { ok: false, dir: target, code: result.code, detail: lastLine(result.stderr || result.stdout) }
    } catch (error) {
      return { ok: false, dir: target, detail: describeError(error) }
    }
  }

  /**
   * Repair one directory. Never rejects; results are memoized per canonical path
   * (successes for the process lifetime, failures only for `retryDelayMs`).
   *
   * @param {string} dir
   * @param {{ force?: boolean }} [repairOptions] — `force` drops the memo first.
   */
  function repair(dir, repairOptions = {}) {
    const target = canonicalPath(dir)
    if (process.platform !== 'win32') {
      return Promise.resolve({ ok: true, dir: target ?? String(dir), skipped: 'unsupported-platform' })
    }
    if (!target) return Promise.resolve({ ok: false, dir: String(dir), skipped: 'no-path' })
    const key = target.toLowerCase()
    if (repairOptions.force) cache.delete(key)
    const memo = cache.get(key)
    if (memo) return memo.then((result) => ({ ...result, cached: true }))
    const pending = grant(target)
    cache.set(key, pending)
    if (cache.size > MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value)
    void pending.then((result) => {
      if (result.ok) return
      // A failure must stay retryable, but must not spawn an icacls per call.
      const timer = setTimeout(() => {
        if (cache.get(key) === pending) cache.delete(key)
      }, retryDelayMs)
      timer.unref?.()
    })
    return pending
  }

  return { repair, userSid, canonicalPath }
}

/** @param {string} text */
function lastLine(text) {
  const lines = String(text ?? '').trim().split(/\r?\n/)
  return lines[lines.length - 1].trim()
}
