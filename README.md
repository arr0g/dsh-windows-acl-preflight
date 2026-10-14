English | [简体中文](README.zh.md)

# dsh-windows-acl-preflight

[![test](https://github.com/arr0g/dsh-windows-acl-preflight/actions/workflows/test.yml/badge.svg)](https://github.com/arr0g/dsh-windows-acl-preflight/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform: Windows](https://img.shields.io/badge/platform-Windows-0078d4.svg)](README.md#9-known-limitations)
[![node 20 | 22 | 24](https://img.shields.io/badge/node-20%20%7C%2022%20%7C%2024-339933.svg)](.github/workflows/test.yml)

Make **new workspaces work out of the box**: no more hand-fixing ACLs, `pwsh` runs the moment you open it;
and you can also write to subdirectories that **already existed and were only later brought under the sandbox** (typically: an extracted modpack directory).

---

## 1. The problem it solves

On Windows, sessions in workspace mode (`workspace-write`) run into **two** kinds of situations that pop an approval prompt or fail outright.

### Problem A: no pwsh command runs at all in a new workspace

```
Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite(E:\my-workspace)
```

(Win32 5 = `ERROR_ACCESS_DENIED`. The failure happens at the moment DSH builds the sandbox grant, **before the child process has even been created**,
so no command can run at all; the only way around it is to raise the permissions to `danger-full-access` — which is not a fix.)

**Root cause**: DSH's Windows sandbox runner (`@deepseek-ai/dsh-sandbox-windows-acl`) makes **one**
`SetNamedSecurityInfoW` call that writes three things at once:

1. a write-permission ACE for the sandbox child process's capability SID (mask `0x110156`);
2. a `DELETE_CHILD` deny ACE for Everyone;
3. the Low integrity label — **the label lives in the SACL**.

Step 3 is what makes the whole call require `WRITE_OWNER` on the directory. And **an owner only implicitly holds `READ_CONTROL` and
`WRITE_DAC`, never `WRITE_OWNER`**. A new folder created directly under a drive root (for example `E:\new-workspace`)
inherits only `NT AUTHORITY\Authenticated Users:Modify` from its parent, so the whole call fails and
pwsh becomes unusable across the entire workspace.

**The fix (one line, no elevation, touches only the DACL)**:

```
icacls.exe <directory> /grant:r *<current user SID>:(OI)(CI)(F)
```

It succeeds without elevation because **the caller is already the owner of that directory** (an owner implicitly holds `WRITE_DAC`, which is exactly
the right needed to change the DACL). Adding `(OI)(CI)` makes it inheritable, so this single command also satisfies the precondition for Problem B below.

### Problem B: commands run now, but writes into "already there" subdirectories fail

A confined child process runs with a **WRITE_RESTRICTED + Low integrity** token, and it can only write where both conditions hold:
"the capability SID appears in the DACL" and "the object carries a Low label". But DSH's grant only applies to
the **workspace root directory**:

- `SetNamedSecurityInfoW` does not push the newly added inheritable ACE down to **already existing** child objects;

- so a subtree that was dropped in or extracted **after the workspace was created** (for example `E:\my-workspace\vendor-pack`, 325 directories / 2005 files)
  has neither the capability SID ACE nor a Low label — writes are rejected by the system,
  
  ```
  Set-Content: Access to the path 'E:\my-workspace\vendor-pack\...' is denied.
  ```
  
  and the model can only ask for elevation, which **pops another approval prompt**. Subdirectories **created** after the workspace exists are unaffected (they inherit normally).

**The fix (two steps, neither needs elevation)**:

```
icacls.exe <workspace root> /inheritance:e /T /C /Q          # push the DACL (capability SID + deny ACE) down the whole existing subtree
powershell.exe -File lib\acl-helper.ps1 -Path <root>     # use P/Invoke to add Low labels to the whole tree (icacls cannot)
```

> `icacls /setintegritylevel` returns `Access is denied.` for every child object (rc is still 0), and it **cannot** be used to add labels;
> labels have to be written object by object with `SetNamedSecurityInfoW(..., LABEL_SECURITY_INFORMATION, ...)`, which is why this package ships its own helper.
> The label ACE must be the **inheritable** form `S:(ML;OICI;NW;;;LW)`, otherwise it never reaches already existing child objects.

---

## 2. Measured evidence

### 2.1 Granting on the root directory (Problem A)

On a **freshly created directory under a drive root** (`E:\acl-raw`, the equivalent of a "new workspace"), reproduced with exactly the same
Win32 call the runner under test uses (`SetNamedSecurityInfoW`, SecurityInfo `0x14` = DACL|LABEL):

| Step                              | Result                                  |
| --------------------------------- | --------------------------------------- |
| Unfixed, called directly          | `rc = 5` (ERROR_ACCESS_DENIED), label still `''` |
| Run this plugin's repair (`icacls /grant:r`, exit code 0) | `repair: {"ok":true}`                   |
| Retry the same call               | `rc = 0`, label becomes `S:AI(ML;;NW;;;LW)` |

![Illustrative transcript from a real repair run (not a screen capture): rc = 5 before the repair, rc = 0 with the Low label after it](docs/terminal-output.svg)

### 2.2 Driving all three stages with **DSH's own runner** (Problems A + B)

Take `dsh-sandbox-windows-acl/lib/runner.js` as-is and run it as a black box
(`--workspace <ws> --temp <temp> --mode workspace-write -- pwsh ...`; standalone mode is exactly the path where DSH's grant fails):

| Stage | Scenario                                                          | Result                                                                                                           |
| --- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| A   | Brand-new workspace, no repair                                    | runner exits **127**, verbatim stderr: `windows-acl-run: SetNamedSecurityInfoW failed (Win32 5): grantWrite(E:\ws)` |
| B′  | root already repaired; subdirectory `pack` has its inheritance broken with `icacls /inheritance:d` (= the real shape of a subtree "dropped in later") | `confine` succeeds, but the child's file write is denied: `err: Set-Content: Access to the path '…\pack\config\file.txt' is denied.` |
| C   | then run this package's tree propagation (`/inheritance:e /T` + label helper) | the same confined child writes successfully, file content `WRITTEN-BY-CONFINED-CHILD-…` |

### 2.3 End to end, driven by **this package's own modules**

The table below is the recorded output of a development script that ran inside a DSH confined session: it `import`ed this package's
`lib/repair.js` / `lib/propagate.js` directly and walked a tree with broken inheritance
in the real order (repair root → first confined call triggers DSH's grant → propagate → call again):

| Step                         | Result                                                                        |
| ---------------------------- | ----------------------------------------------------------------------------- |
| 1 `repairer.repair(ws)`      | `{"ok":true,"dir":"E:\\ws-e2e"}`                                         |
| 2 Confined write             | the target is still `ORIGINAL` (**denied**)                                       |
| 3 `propagator.propagate(ws)` | `{"ok":true,"sid":"S-1-4-11-22","objects":6,"failures":0,"ms":1}` |
| 4 Confined write             | `WRITTEN-AFTER-PROPAGATION`                                                   |

In other words: **"repair the root + propagate" is sufficient for a confined child process to write into an existing subtree**.

---

## 3. How it works

Once the plugin is mounted, it repairs the directory **before every confined command actually runs**, along four paths;
besides repairing the root, path 3 also pushes permissions down the entire existing subtree **after** DSH's grant:

| #   | When                                | Which directory gets repaired                                                                       | Tree propagation                                                    |
| --- | ----------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------ |
| 0   | plugin mount                        | `ctx.sandboxPolicy.workspaceRoot` (the fallback root when there is no session cwd)                            | Yes                                                      |
| 1   | `session/created`                   | `session.header.cwd` (the session's real workspace, i.e. the workspace-write boundary)                          | Yes                                                      |
| 2   | `agent/created` (**serial, awaited**) | the cwd remembered above → `sessionPersistence.stat()` → fallback root                               | Yes                                                      |
| 3   | wraps `ctx.sandbox.confine` (best effort) | repairs `policy.workspaceRoot` first; if the call still fails with `grantWrite(<path>)`, it force-repairs that path and retries **exactly once** | Yes: runs **after** `confine` resolves (= DSH's grant is done) and **before** the child process is created |

The order is deliberate: the capability SID ACE is written to the root directory by **DSH's grant**, so tree propagation has to wait for it to succeed;
and `confine` only spawns the child process after that promise resolves, so propagation still finishes before the command.
If the capability SID is **not yet visible** on the root directory (DSH has not granted yet), propagation is skipped outright and that conclusion is **not cached**, so it is checked again next time.

Design constraints:

- **does not loosen the sandbox policy**, does not touch the registry, does not elevate;
- **never throws**: if a repair or a propagation fails, the command is let through unchanged and behavior falls back to the "plugin not installed" state, leaving only one warning line in the log;
- each directory is repaired once and each tree is propagated once (remembered in-process by normalized path, case-insensitively);
  failure records are remembered for only a few seconds before retrying, and "not yet granted" never enters the cache;
- path 3 verifies with an **identity comparison** right after assignment that it really took effect; if not, it silently falls back to the first three;
- `danger-full-access` calls neither repair the root nor propagate (nobody is confined, so it is unnecessary).

The log prefix is always `[dsh-windows-acl-preflight]`.

---

## 4. Directory layout

```
dsh-windows-acl-preflight/
├── package.json          # package metadata + dsh.bundle.patch (read when the plugin manager installs it as a bundle)
├── cordis.patch.yml      # mount record used when installed as a bundle (inserts one loader entry)
├── dsh-plugin.json       # plugin marketplace manifest (dsh-std manifest v0.15: id / facets / permissions / x-display)
├── icon.png              # 256×256, referenced by package.json "icon" (and by x-display)
├── locale/
│   ├── en.json           # { "meta": { "title", "description" } }
│   └── zh.json
├── lib/
│   ├── index.js          # the plugin itself (four paths, the confine wrapper; Node built-ins only)
│   ├── repair.js         # icacls root repair (runner injectable, for offline tests)
│   ├── propagate.js      # tree propagation orchestration: icacls /inheritance:e /T + helper call
│   └── acl-helper.ps1    # P/Invoke writes Low labels object by object (ASCII-only, readable by PS 5.1)
├── test/
│   ├── offline.test.mjs  # 13 tests: the ACL behaviour itself (Windows-only cases skip elsewhere)
│   └── manifest.test.mjs # 9 tests: manifest + package.json consistency (offline, platform-independent)
├── docs/
│   └── terminal-output.svg  # the transcript printed in §2 (hand-rendered, not a screen capture)
├── install.ps1           # idempotent install/uninstall script (manual route)
├── LICENSE               # MIT
├── .gitattributes        # LF-only checkout (acl-helper.ps1 is deliberately pure ASCII)
├── .gitignore
├── .github/workflows/test.yml  # CI: windows + ubuntu × node 20/22/24 — the ACL suite, then the manifest check
├── README.md             # English (this file)
└── README.zh.md          # Simplified Chinese
```

> `dsh-plugin.json` is the **dsh-std community plugin manifest** (marketplaces/toolchains use it to show the icon and permission declarations).
> DSH's own plugin manager (`@deepseek-ai/dsh-plugin-manager`) does not read it — it only looks at
> `dsh.bundle.patch` in `package.json`. Shipping this manifest is meant to make this package
> a first-class citizen in the various dsh toolchains (it has an id, an icon, permission declarations), not to make DSH able to load it.

---

## 5. Installation

Two routes, **pick one** (using both inserts two mount records with the same id, i.e. mounts the plugin twice).

### 5.1 The proper bundle route (recommended)

Have DSH's own plugin manager install it into the profile as a local bundle:

From a local directory:

```
plugin_manager install_bundle target='file:<this package's directory>'
```

Once the repository is published, you can also install straight from GitHub (see §5.3 for the full set of spec forms):

```
plugin_manager install_bundle target='github:arr0g/dsh-windows-acl-preflight'
```

What it does (measured):

1. runs `pnpm add file:<this package's directory>` in the profile
   → `dependencies` in `package.json` gains
   `"dsh-windows-acl-preflight": "file:<this package's directory>"`,
   and the lockfile is updated; `node_modules\dsh-windows-acl-preflight` lands according to the profile's linker
   (a real directory copy under pnpm's `hoisted` mode).
2. reads that dependency's `package.json`, requires `dsh.bundle.patch` to be present (this package has it),
   loads `cordis.patch.yml` (that `insert` entry is the mount record), runs one compatibility check
   (semver validation of `@deepseek-ai/dsh*` in `peerDependencies` against the runtime version), and finally appends the package name to `dsh.profile.bundles`.
3. because this is a **new** dependency, the profile config is hot-reloaded right after installation → it is mounted **without restarting DSH**.

Upside: it is a **declarative dependency** of the profile, so no future `pnpm install` will sweep it away the way "hand-stuffing it into
node_modules" would.

Cost: what gets installed is a **copy**, so after editing this package's source you have to refresh that local copy. Two refresh methods, measured:

- Re-run the same `install_bundle`: pnpm **does** copy the source back into
  `node_modules\dsh-windows-acl-preflight\` (hashes verified identical), but the manager then reports
  `ambiguous-install` because "the dependency set gained nothing" — the files are already refreshed, only this step is not counted as a successful return;
  and that `pnpm add` will incidentally bump other dependencies to the newest version inside their declared ranges (measured: `billion-context`
  went from 0.1.195 to 0.1.196).

- For zero side effects, just overwrite (`node_modules` is generated output, overwriting is harmless; a real installation later still lands from source):
  
  ```powershell
  Copy-Item -Path '<this package's directory>\*' -Destination '<profile>\node_modules\dsh-windows-acl-preflight\' -Recurse -Force
  ```

### 5.2 Manual route (for offline / on-site debugging)

First see what would change (**read only**):

```powershell
& '<this package's directory>\install.ps1' -DryRun
```

Actually run it (`-Link` creates a directory junction instead, so source edits take effect immediately):

```powershell
& '<this package's directory>\install.ps1'
```

It does two things (both idempotent):

1. copies this package to `<profile>\node_modules\dsh-windows-acl-preflight` (with `-Link`, creates a directory junction instead);

2. appends one mount record to the end of `<profile>\cordis.patch.yml`, **auto-backing up** the previous file as
   `cordis.patch.yml.bak-acl-preflight-<timestamp>`:
   
   ```yaml
   - insert:
       - id: windows-acl-preflight
         name: dsh-windows-acl-preflight
   ```

After that, **restart DSH** (or reload the profile) for it to take effect.

> Why does "copying the package into node_modules" not stand on its own? Because that profile is managed by pnpm
> (`.pnpm/`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`), and a single `pnpm install` can sweep it
> away as a "stray package". So keep this package's source under `<DSH_HOME>\plugins\` (out of pnpm's reach),
> and `install.ps1` can reinstall it in one step at any time.

### 5.3 Installing from the GitHub repository

Once the repository is published, the spec can be the repository address directly. The plugin manager accepts all of these forms
(the rules come from `install-spec` in `@deepseek-ai/dsh-plugin-manager`):

| Form    | Example                                                                                                           |
| ------- | ----------------------------------------------------------------------------------------------------------------- |
| host shorthand | `github:arr0g/dsh-windows-acl-preflight` (also supports `gitlab:` / `bitbucket:` / `gist:`)                                  |
| git URL | `git+https://github.com/arr0g/dsh-windows-acl-preflight.git`, `git@github.com:arr0g/dsh-windows-acl-preflight.git` |
| repository web address | `https://github.com/arr0g/dsh-windows-acl-preflight` (only the three-level `host/owner/repo` form is recognized)                                     |
| packed artifact | `https://…/dsh-windows-acl-preflight-1.0.0.tgz` (`.tgz` / `.tar.gz`)                                               |

Note: a local-path spec **must be an absolute path** (relative paths are explicitly rejected); only `*.tgz` / `*.tar.gz`
are treated as a tarball, and any other http(s) address must point at a git repository.

The install flow is exactly the same as 5.1: `pnpm add <spec>` → read `dsh.bundle.patch` → load `cordis.patch.yml`
→ validate the `@deepseek-ai/dsh*` versions in `peerDependencies` → write into `dsh.profile.bundles` → hot reload.

---

## 6. Uninstalling

- Bundle route (5.1): uninstall that bundle with the plugin manager, or run this in the profile directory
  
  ```
  pnpm remove dsh-windows-acl-preflight
  ```
  
  then remove the package name from `dsh.profile.bundles` (the plugin manager handles this itself when it disables/uninstalls).

- Manual route (5.2):
  
  ```powershell
  & '<this package's directory>\install.ps1' -Uninstall
  ```
  
  This undoes only the two changes that route wrote (the package directory + that one mount record), backing up `cordis.patch.yml` first as well.

---

## 7. Configuration (optional)

Just override the configuration by entry id in the **profile's own** `cordis.patch.yml` (this applies to both install routes; on the
bundle route, `config` goes here rather than into the `cordis.patch.yml` inside the package):

| Key                  | Default          | Meaning                                        |
| -------------------- | ---------------- | ---------------------------------------------- |
| `enabled`            | `true`           | when `false` the plugin does nothing at all                               |
| `verbose`            | `false`          | log even when the directory was already repaired before                                  |
| `propagateTree`      | `true`           | whether to push permissions and Low labels onto **already existing** subtrees in the workspace                  |
| `timeoutMs`          | `15000`          | timeout for a single `icacls`/`whoami` call                        |
| `propagateTimeoutMs` | `120000`         | timeout for one tree propagation (`icacls /T`, label helper)                 |
| `retryDelayMs`       | `5000`           | how long after a failed repair before a retry is allowed                                    |
| `powershell`         | `powershell.exe` | interpreter used to run the label helper (can point at `pwsh.exe`)               |
| `repairUnconfined`   | `false`          | when `true`, `danger-full-access` calls get repaired too (untouched by default) |

Example:

```yaml
- id: windows-acl-preflight
  config:
    verbose: true
```

### 7.1 Turning it off

- Bundle route: set `disabled: true` on the row the plugin manager wrote into the profile's
  `cordis.patch.yml`, or use the plugin manager's own enable/disable toggle. The `insert:` row is
  never the toggle target — the manager writes a separate row keyed by the plugin id.
- Manual route: `install.ps1 -Uninstall` removes both things that route wrote (the package directory
  and the mount record), backing up `cordis.patch.yml` first (see §6).
- The mount id is `windows-acl-preflight`; the bundle name is `dsh-windows-acl-preflight`. Setting
  `enabled: false` (the table above) is the cheapest way to keep it installed but inert.

---

## 8. Tests

In this package's directory — the first form also works inside a confined session
(no child process is spawned), the second is the plain runner invocation and what CI uses:

```powershell
node -e "import('./test/offline.test.mjs')"    # confined-friendly
node --test test/offline.test.mjs              # unconfined shell / CI
```

All 13 tests really run on Windows (including an integration test that actually invokes `icacls` and executes the bundled label helper).
Note: under a confined *(workspace-write)* environment that blocks piped child processes, `node --test` itself cannot spawn the test file,
and the last case (`whoami`) fails with `EPERM`; run the suite with the interpreter directly
(`node -e "import('./test/offline.test.mjs')"`), or from an unconfined shell, to get 13/13. On a normal Windows shell the suite is 13/13.
With no environment variable set, the integration test creates and deletes a small tree of its own in the system temp directory; to make it use a fixed
directory instead (handy for inspecting things afterwards), point it at a **freshly created directory that sits directly under a drive root**:

```powershell
$env:DSH_ACL_PREFLIGHT_TEST_DIR = 'E:\acl-preflight-test'
node -e "import('./test/offline.test.mjs')"
```

(With that variable set, the directory is created and granted full control to the current user, but it is **not deleted**, so you have to clean it up yourself.)
On non-Windows platforms, the ACL-related cases skip automatically.
A separate, platform-independent manifest suite — 9 hand-written checks over `dsh-plugin.json` and
`package.json`, not a JSON-Schema validator (`node --test test/manifest.test.mjs`) — needs neither Windows nor the network, so CI runs it on every OS.

---

## 9. Known limitations

- Windows only; on other platforms `apply()` returns immediately.
- It can only repair directories **owned by the current user** — `icacls /grant:r` relies on the owner's implicit `WRITE_DAC`.
  A directory owned by someone else that does not grant you `WRITE_DAC` still cannot be repaired (and DSH should not be treating such a directory as a workspace in the first place).
- Tree propagation relies on the same thing: every object must carry a (explicit or inherited) full-control ACE that provides
  `WRITE_OWNER`, otherwise the Low label cannot be written on that object (`rc = 5`). The first step,
  `icacls /grant:r *<SID>:(OI)(CI)(F)`, exists exactly for this, and it pushes full control down the whole existing subtree.
- After a repair, the directory keeps: the capability SID ACE, the Everyone deny ACE, the Low integrity label (`S:(ML;;NW;;;LW)`)
  and your full-control ACE. The first three are **permanent** changes left behind by the DSH sandbox itself; this is also the standard
  approach of DSH's first-party `diagnose-windows-sandbox-acl` skill, not something this plugin introduces on its own.
- Cost: `icacls /T` does roughly 7 000–12 000 objects/second, and pure label writing (the C# recursion in the helper) roughly
  16 000 objects/second; a modpack directory with 325 directories / 2005 files takes on the order of 0.1 seconds.
- Repair/propagation failures are only logged and never block the command; in that case the error is exactly the same as before installing.
- This plugin **does not modify** `cordis.yml` (that is generated output); it mounts only through the profile's own
  `cordis.patch.yml`.

---

## 10. License

MIT, see [LICENSE](LICENSE).
