/**
 * Workspace tree propagation for DSH's workspace-write sandbox.
 *
 * `lib/repair.js` fixes the *root* precondition: after it runs, DSH's own
 * `SetNamedSecurityInfoW` grant succeeds and stamps three things onto the
 * workspace root — the capability-SID allow ACE (mask 0x110156), a
 * `DELETE_CHILD` deny for Everyone, and the Low mandatory integrity label.
 *
 * Windows is supposed to hand those down to pre-existing children, and for a
 * normally-inheriting child it does (verified). But a child whose ACL was
 * stamped by an unpacker/extractor — inheritance disabled, or explicit ACEs
 * materialized — never receives them. The confined child is a WRITE_RESTRICTED,
 * Low-integrity token, so a directory that lacks the capability ACE and/or the
 * Low label is simply unwritable, even though `confine()` itself succeeded. The
 * sandbox then reports the failure as `Access to the path ... is denied.`, which
 * the agent can only answer with an escalation approval prompt.
 *
 * This module closes that gap with the two passes that were measured to work
 * unelevated (see README for the A/B/C lab evidence):
 *
 *   1. `icacls <root> /inheritance:e /T /C /Q`
 *      Re-evaluates inheritance for every existing object, so the capability ACE
 *      and the Everyone deny reach the whole tree. Explicit ACEs are preserved.
 *
 *   2. `powershell -File lib/acl-helper.ps1 -Path <root>`
 *      Writes the Low mandatory label to every object via
 *      `SetNamedSecurityInfoW(..., LABEL_SECURITY_INFORMATION, ...)`. The label
 *      lives in the SACL, which `icacls` cannot write unelevated
 *      (`/setintegritylevel` prints `Access is denied.` for every object), and
 *      which no DACL pass propagates. `WRITE_OWNER` for that call comes from the
 *      Full-control ACE step 1 of `lib/repair.js` just made inheritable.
 *
 * Both passes are idempotent, additive, bounded by a timeout, and memoized per
 * canonical workspace root for the process lifetime on success.
 */

import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalPath, describeError, runCommand, DEFAULT_TIMEOUT_MS } from './repair.js'

/** A capability SID: `S-1-4-<authority>-<subauthority…>` (DSH's workspace write SID). */
const CAPABILITY_SID = /S-1-4-\d+(?:-\d+)+/

export const DEFAULT_PROPAGATE_TIMEOUT_MS = 120_000
export const DEFAULT_PROPAGATE_RETRY_DELAY_MS = 15_000

/** Cap on memoized workspace roots. */
const MAX_CACHE_ENTRIES = 64

/**
 * Pull DSH's capability SID out of `icacls <dir>` output.
 *
 * Reading the SID back is deliberate: DSH derives it deterministically from the
 * canonical workspace path, but re-deriving that hash here would silently drift
 * from the real implementation, while the ACL itself is the ground truth.
 *
 * @param {unknown} text
 * @returns {string | undefined}
 */
export function capabilitySid(text) {
  const match = CAPABILITY_SID.exec(String(text ?? ''))
  return match ? match[0] : undefined
}

/** Absolute path of the shipped PowerShell label helper. */
export function helperPath() {
  return join(dirname(fileURLToPath(import.meta.url)), 'acl-helper.ps1')
}

/**
 * Parse the helper's single stdout line: `objects=<n> failures=<f> firstRc=<rc> ms=<ms>`.
 *
 * @param {unknown} text
 * @returns {{ objects?: number, failures?: number, firstRc?: number, ms?: number }}
 */
export function parseHelperStats(text) {
  const line = String(text ?? '')
  const number = (key) => {
    const match = new RegExp(`${key}=(-?\\d+)`).exec(line)
    return match ? Number(match[1]) : undefined
  }
  return { objects: number('objects'), failures: number('failures'), firstRc: number('firstRc'), ms: number('ms') }
}

/**
 * Build a tree propagator.
 *
 * @param {{
 *   run?: typeof runCommand,
 *   timeoutMs?: number,
 *   retryDelayMs?: number,
 *   icacls?: string,
 *   powershell?: string,
 *   helper?: string,
 * }} [options] — `run` is injectable so the offline tests never spawn a process.
 */
export function makePropagator(options = {}) {
  const run = options.run ?? runCommand
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROPAGATE_TIMEOUT_MS
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_PROPAGATE_RETRY_DELAY_MS
  const icacls = options.icacls ?? 'icacls.exe'
  const powershell = options.powershell ?? 'powershell.exe'
  const helper = options.helper ?? helperPath()

  /** @type {Map<string, Promise<object>>} */
  const cache = new Map()

  /** Read the workspace root's capability SID (empty output ⇒ DSH has not granted yet). */
  async function readCapabilitySid(target) {
    const listed = await run(icacls, [target], { timeout: timeoutMs })
    if (listed.code !== 0) {
      return { ok: false, dir: target, stage: 'read', code: listed.code, detail: lastLine(listed.stderr || listed.stdout) }
    }
    const sid = capabilitySid(listed.stdout)
    return sid ? { ok: true, sid } : { ok: true, sid: undefined }
  }

  /** Run both passes once. Never rejects. */
  async function propagateOnce(target) {
    const read = await readCapabilitySid(target)
    if (!read.ok) return read
    if (!read.sid) {
      // DSH has not provisioned this workspace yet; nothing to propagate. Not
      // memoized, so a later call re-checks.
      return { ok: true, dir: target, skipped: 'no-capability-sid' }
    }

    const dacl = await run(icacls, [target, '/inheritance:e', '/T', '/C', '/Q'], { timeout: timeoutMs })
    if (dacl.code !== 0) {
      return { ok: false, dir: target, stage: 'dacl', sid: read.sid, code: dacl.code, detail: lastLine(dacl.stderr || dacl.stdout) }
    }

    const label = await run(
      powershell,
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', helper, '-Path', target],
      { timeout: timeoutMs },
    )
    const stats = parseHelperStats(label.stdout)
    if (label.code !== 0) {
      return { ok: false, dir: target, stage: 'label', sid: read.sid, code: label.code, detail: lastLine(label.stderr || label.stdout) }
    }
    return { ok: true, dir: target, sid: read.sid, objects: stats.objects, failures: stats.failures ?? 0, ms: stats.ms }
  }

  /**
   * Propagate workspace permissions through one workspace tree. Never rejects.
   *
   * @param {string} dir
   * @param {{ force?: boolean }} [propagateOptions]
   */
  function propagate(dir, propagateOptions = {}) {
    const target = canonicalPath(dir)
    if (process.platform !== 'win32') {
      return Promise.resolve({ ok: true, dir: target ?? String(dir), skipped: 'unsupported-platform' })
    }
    if (!target) return Promise.resolve({ ok: false, dir: String(dir), skipped: 'no-path' })

    const key = target.toLowerCase()
    if (propagateOptions.force) cache.delete(key)
    const memo = cache.get(key)
    if (memo) return memo.then((result) => ({ ...result, cached: true }))

    const pending = propagateOnce(target).catch((error) => ({ ok: false, dir: target, detail: describeError(error) }))
    cache.set(key, pending)
    if (cache.size > MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value)
    void pending.then((result) => {
      const forget = () => {
        if (cache.get(key) === pending) cache.delete(key)
      }
      // "not provisioned yet" is not a result: drop the memo at once so a later
      // call (e.g. after DSH granted the root) re-reads the ACL.
      if (result.skipped) {
        forget()
        return
      }
      if (result.ok) return
      // A real failure stays retryable, but must not spawn icacls per call.
      const timer = setTimeout(forget, retryDelayMs)
      timer.unref?.()
    })
    return pending
  }

  return { propagate, capabilitySid, helperPath: helper }
}

/** @param {string} text */
function lastLine(text) {
  const lines = String(text ?? '').trim().split(/\r?\n/)
  return lines[lines.length - 1].trim()
}

export { DEFAULT_TIMEOUT_MS }
