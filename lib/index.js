/**
 * dsh-windows-acl-preflight — makes `pwsh` usable in a brand-new workspace.
 *
 * On Windows DSH confines shell commands with a restricted-token runner that
 * first provisions the workspace root's security descriptor. That provisioning
 * needs `WRITE_OWNER` on the directory (it writes the Low mandatory label into
 * the SACL), which a directory granting the user only `Modify` does not give.
 * A freshly created workspace root — e.g. any new folder directly under `E:\` —
 * inherits exactly that, so DSH fails before spawning anything:
 *
 *   SetNamedSecurityInfoW failed (Win32 5): grantWrite(E:\my-workspace)
 *
 * This plugin repairs the precondition ahead of every confined execution:
 *
 *   prong 0  at mount time   → `ctx.sandboxPolicy.workspaceRoot` (the fallback
 *                              root used by agentless/confined calls)
 *   prong 1  `session/created` → `session.header.cwd` (the session's real root)
 *   prong 2  `agent/created`   → awaited, so the repair completes before the
 *                              agent's first command can run
 *   prong 3  `ctx.sandbox.confine` (best effort) → pre-repairs the policy's
 *                              workspaceRoot, and if the original call still
 *                              fails with `grantWrite(<path>)`, repairs that
 *                              path and retries the call exactly once
 *
 * The root grant alone is not enough for a workspace that already contained
 * files: a child whose ACL an unpacker stamped (inheritance disabled, or
 * explicit ACEs materialized) never receives the capability ACE or the Low
 * mandatory label, so the confined child is denied even though `confine()`
 * succeeded. Once DSH's own grant has provisioned the root, prong 3 therefore
 * also runs `lib/propagate.js` — an inheritance re-evaluation plus a label pass
 * over the tree — before it hands the argv back, i.e. before the child spawns.
 * The event prongs run the same propagation when the root is already provisioned
 * from an earlier session, so the first command does not pay for it.
 *
 * It never widens the sandbox policy, never edits the registry, and never
 * throws: a failure is logged and the sandbox behaves exactly as it did before.
 *
 * The loader mounts a plugin from its module namespace, so this file uses ONLY
 * named exports — a `export default` here would discard `inject` and the plugin
 * would silently no-op.
 */

import { canonicalPath, describeError, grantTarget, makeRepairer } from './repair.js'
import { makePropagator } from './propagate.js'

export const name = 'dsh-windows-acl-preflight'

/** Hard dependencies only: the rest is resolved lazily at call time. */
export const inject = ['sandboxPolicy']

const PREFIX = '[dsh-windows-acl-preflight]'

/** Cap on remembered session → cwd pairs. */
const MAX_REMEMBERED_SESSIONS = 256

/** Marks a `confine` wrapper as ours so it is never wrapped twice. */
const WRAPPED = Symbol.for('dsh-windows-acl-preflight.confine')

/** @param {string} level @param {unknown} value */
const positive = (value, fallback) => (typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : fallback)

/** @param {unknown} value */
const nonEmptyString = (value) => (typeof value === 'string' && value.trim() ? value.trim() : undefined)

/**
 * Mount the plugin. Called by the loader; kept non-async and non-throwing so a
 * problem here can never fail the boot of the application.
 *
 * @param {any} ctx — cordis context.
 * @param {any} [config] — plugin config (see README).
 */
export function apply(ctx, config = {}) {
  try {
    mount(ctx, config)
  } catch (error) {
    try {
      ctx?.logger?.error?.(`${PREFIX} mount failed: ${describeError(error)}`)
    } catch {
      /* logging is best effort */
    }
  }
}

/**
 * Internal seam: does the actual wiring, with an injectable repairer so the
 * offline tests can drive every prong without spawning `icacls`.
 *
 * @param {any} ctx
 * @param {any} [config]
 * @param {{
 *   repairer?: ReturnType<typeof makeRepairer>,
 *   propagator?: ReturnType<typeof makePropagator>,
 * }} [options]
 */
export function mount(ctx, config = {}, options = {}) {
  if (process.platform !== 'win32') return
  if (config.enabled === false) return
  if (!ctx || typeof ctx !== 'object') return

  const repairer =
    options.repairer ??
    makeRepairer({ timeoutMs: positive(config.timeoutMs, undefined), retryDelayMs: positive(config.retryDelayMs, undefined) })
  const propagator =
    options.propagator ??
    makePropagator({
      timeoutMs: positive(config.propagateTimeoutMs, undefined),
      powershell: nonEmptyString(config.powershell),
    })
  const verbose = config.verbose === true
  const repairUnconfined = config.repairUnconfined === true
  const propagateTree = config.propagateTree !== false

  const logger = pickLogger(ctx)
  /** @param {'debug'|'info'|'warn'|'error'} level @param {string} message */
  const log = (level, message) => {
    try {
      logger?.[level]?.(`${PREFIX} ${message}`)
    } catch {
      /* logging is best effort */
    }
  }

  /** @type {Map<string, string>} */
  const knownCwds = new Map()

  /** The configured fallback workspace root, if the service exposes one. */
  function fallbackRoot() {
    try {
      const root = ctx.sandboxPolicy?.workspaceRoot
      return typeof root === 'string' && root ? root : undefined
    } catch {
      return undefined
    }
  }

  /** Remember a session's workspace root, bounded. */
  function remember(id, cwd) {
    if (!id || !cwd) return
    knownCwds.set(id, cwd)
    while (knownCwds.size > MAX_REMEMBERED_SESSIONS) knownCwds.delete(knownCwds.keys().next().value)
  }

  /**
   * Repair one directory. Never rejects.
   *
   * @param {unknown} dir
   * @param {string} reason — what asked for the repair (for the log line).
   * @param {{ force?: boolean }} [repairOptions]
   */
  async function preflight(dir, reason, repairOptions) {
    if (typeof dir !== 'string' || !dir) return { ok: true, skipped: 'no-directory' }
    try {
      const target = canonicalPath(dir) ?? dir
      const result = await repairer.repair(dir, repairOptions)
      if (result.ok) {
        if (!result.cached || verbose) {
          log('info', `${result.cached ? 'Full control already present on' : 'granted Full control on'} ${target} (${reason})`)
        }
      } else {
        log('warn', `could not grant Full control on ${target} (${reason}): ${result.detail ?? result.skipped ?? 'unknown reason'}`)
      }
      return result
    } catch (error) {
      log('warn', `repair of ${dir} failed (${reason}): ${describeError(error)}`)
      return { ok: false, dir, error: describeError(error) }
    }
  }

  /**
   * Propagate the workspace grant through the tree of one workspace root. Never
   * rejects. Only meaningful once DSH has provisioned the root; when it has not,
   * the propagator reports `skipped: 'no-capability-sid'`.
   *
   * @param {unknown} dir
   * @param {string} reason
   * @param {{ force?: boolean }} [propagateOptions]
   */
  async function propagateWorkspace(dir, reason, propagateOptions) {
    if (!propagateTree) return { ok: true, skipped: 'disabled' }
    if (typeof dir !== 'string' || !dir) return { ok: true, skipped: 'no-directory' }
    try {
      const target = canonicalPath(dir) ?? dir
      const result = await propagator.propagate(dir, propagateOptions)
      if (!result.ok) {
        log(
          'warn',
          `could not propagate workspace permissions through ${target} (${reason}): ${result.detail ?? result.stage ?? result.skipped ?? 'unknown reason'}`,
        )
      } else if (result.skipped) {
        if (verbose) log('debug', `tree propagation skipped for ${target} (${reason}): ${result.skipped}`)
      } else if (!result.cached || verbose) {
        const failures = result.failures ? `, ${result.failures} object(s) failed` : ''
        log('info', `propagated workspace permissions to ${result.objects ?? '?'} object(s) in ${target} (${reason})${failures}`)
      }
      return result
    } catch (error) {
      log('warn', `tree propagation in ${dir} failed (${reason}): ${describeError(error)}`)
      return { ok: false, dir, error: describeError(error) }
    }
  }

  /**
   * Wrap `ctx.sandbox.confine` if the resolved service object is writable. The
   * wrapper is verified by identity and abandoned when the patch does not stick,
   * so the event prongs above remain the primary mechanism.
   */
  function ensureConfinePatch() {
    try {
      const sandbox = lookup(ctx, 'sandbox')
      if (!sandbox || typeof sandbox.confine !== 'function') return
      if (sandbox.confine[WRAPPED]) return
      const original = sandbox.confine
      const wrapped = async function confinedWithPreflight(argv, policy, signal) {
        const mode = policy?.mode
        const prepare = !policy || repairUnconfined || mode !== 'danger-full-access'
        if (prepare) {
          await preflight(policy.workspaceRoot, `confine:${mode ?? 'unknown'}`)
        }
        try {
          // Propagate *after* the original call: DSH's grant is what materializes
          // the capability ACE on the root, and the child is only spawned once
          // this promise resolves — so the tree is ready before it starts.
          const confined = await original.call(this, argv, policy, signal)
          if (prepare) await propagateWorkspace(policy?.workspaceRoot, `confine:${mode ?? 'unknown'}`)
          return confined
        } catch (error) {
          const target = grantTarget(error)
          if (!target) throw error
          // The grant is provisioned before any child is spawned, so a retried
          // `confine` cannot double-execute the command.
          const result = await preflight(target, 'retry after grant failure', { force: true })
          if (!result.ok) throw error
          const confined = await original.call(this, argv, policy, signal)
          await propagateWorkspace(policy?.workspaceRoot ?? target, 'retry after grant failure')
          return confined
        }
      }
      wrapped[WRAPPED] = true
      try {
        sandbox.confine = wrapped
      } catch (error) {
        log('warn', `sandbox.confine is not writable; relying on session preflight only: ${describeError(error)}`)
        return
      }
      if (sandbox.confine !== wrapped) {
        log('warn', 'sandbox.confine did not accept the wrapper; relying on session preflight only')
        return
      }
      log('debug', 'sandbox.confine wrapped for preflight repair')
    } catch (error) {
      log('debug', `confine patch skipped: ${describeError(error)}`)
    }
  }

  const root = fallbackRoot()
  if (root) {
    void preflight(root, 'mount').then(() => propagateWorkspace(root, 'mount'))
  }
  ensureConfinePatch()

  if (typeof ctx.on !== 'function') {
    log('warn', 'ctx.on is unavailable; only the configured workspace root was repaired')
    return
  }

  // Sessions announce their workspace root as soon as they are published.
  ctx.on('session/created', (session) => {
    try {
      const cwd = session?.header?.cwd
      remember(session?.id, cwd)
      if (cwd) {
        void preflight(cwd, 'session/created').then(() => propagateWorkspace(cwd, 'session/created'))
      }
      ensureConfinePatch()
    } catch (error) {
      log('warn', `session/created handler failed: ${describeError(error)}`)
    }
  })

  // Serial event: awaited, and it runs before the agent's first step.
  ctx.on('agent/created', async (payload) => {
    try {
      ensureConfinePatch()
      const agent = payload?.agent ?? payload
      const id = agent?.id
      const dir = (id ? knownCwds.get(id) : undefined) ?? (await sessionCwd(ctx, id)) ?? root
      if (dir) {
        await preflight(dir, 'agent/created')
        await propagateWorkspace(dir, 'agent/created')
      }
    } catch (error) {
      log('warn', `agent/created preflight failed: ${describeError(error)}`)
    }
  })
}

/**
 * Resolve a service lazily: `ctx.get` first (never stalls the plugin), the
 * proxy property as a fallback.
 *
 * @param {any} ctx @param {string} serviceName
 */
function lookup(ctx, serviceName) {
  try {
    const service = ctx.get?.(serviceName)
    if (service) return service
  } catch {
    /* fall through to the property access */
  }
  try {
    return ctx[serviceName]
  } catch {
    return undefined
  }
}

/**
 * A session's workspace root without a live `Session` object.
 *
 * @param {any} ctx @param {unknown} id
 */
async function sessionCwd(ctx, id) {
  if (!id) return undefined
  try {
    const persistence = lookup(ctx, 'sessionPersistence')
    if (!persistence || typeof persistence.stat !== 'function') return undefined
    const snapshot = await persistence.stat(id)
    const cwd = snapshot?.header?.cwd
    return typeof cwd === 'string' && cwd ? cwd : undefined
  } catch {
    return undefined
  }
}

/** @param {any} ctx */
function pickLogger(ctx) {
  try {
    const named = ctx.logger?.(name)
    if (named && typeof named.info === 'function') return named
  } catch {
    /* fall back to the service itself */
  }
  try {
    const service = ctx.logger
    if (service && typeof service.info === 'function') return service
  } catch {
    /* no logger */
  }
  return undefined
}
