# acl-helper.ps1 - apply the Low mandatory integrity label to an existing tree.
#
# Called by lib/propagate.js after DSH has provisioned the workspace root.
#
# Why a helper at all: the mandatory label lives in the object's SACL, and
# `icacls /setintegritylevel <level> /T` cannot write it unelevated (it prints
# `Access is denied.` for every object and changes nothing). Writing a SACL needs
# WRITE_OWNER, which the signed-in account does have once lib/repair.js has made
# its Full-control ACE inheritable across the tree, so the label can be applied
# by calling SetNamedSecurityInfoW with LABEL_SECURITY_INFORMATION directly.
#
# This file is deliberately ASCII-only: Windows PowerShell 5.1 reads a
# BOM-less file as ANSI, so non-ASCII text here would corrupt.
#
# Output (one line, always exit 0):
#   objects=<n> failures=<f> firstRc=<rc> ms=<ms>
# or, when the label descriptor cannot be built:
#   objects=0 failures=0 firstRc=-1 error=<reason>

param(
  [Parameter(Mandatory = $true)][string]$Path,
  [string]$Label = 'S:(ML;OICI;NW;;;LW)'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
  Write-Output 'objects=0 failures=0 firstRc=-1 error=missing-path'
  exit 0
}

Add-Type -Namespace DshAclPreflight -Name LabelWriter -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out System.IntPtr descriptor, out uint size);

[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool GetSecurityDescriptorSacl(System.IntPtr descriptor, out bool present, out System.IntPtr sacl, out bool isDefault);

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern uint SetNamedSecurityInfoW(string objectName, int objectType, uint securityInfo, System.IntPtr owner, System.IntPtr group, System.IntPtr dacl, System.IntPtr sacl);

[DllImport("kernel32.dll")]
public static extern System.IntPtr LocalFree(System.IntPtr handle);

private const uint LABEL_SECURITY_INFORMATION = 0x00000010;
private const int SE_FILE_OBJECT = 1;

private static string WriteOne(string path, System.IntPtr sacl, ref uint firstError, ref long objects, ref long failures)
{
  objects++;
  uint rc = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, System.IntPtr.Zero, System.IntPtr.Zero, System.IntPtr.Zero, sacl);
  if (rc != 0)
  {
    failures++;
    if (firstError == 0) firstError = rc;
    return "rc=" + rc;
  }
  return null;
}

public static string Walk(string root, string labelSddl)
{
  System.IntPtr descriptor;
  uint size;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(labelSddl, 1, out descriptor, out size))
    return "objects=0 failures=0 firstRc=-1 error=sddl";

  bool present;
  bool isDefault;
  System.IntPtr sacl;
  if (!GetSecurityDescriptorSacl(descriptor, out present, out sacl, out isDefault) || !present)
  {
    LocalFree(descriptor);
    return "objects=0 failures=0 firstRc=-1 error=sacl";
  }

  long objects = 0;
  long failures = 0;
  uint firstError = 0;
  System.Diagnostics.Stopwatch watch = System.Diagnostics.Stopwatch.StartNew();
  System.Collections.Generic.Stack<string> pending = new System.Collections.Generic.Stack<string>();
  pending.Push(root);

  while (pending.Count > 0)
  {
    string dir = pending.Pop();
    WriteOne(dir, sacl, ref firstError, ref objects, ref failures);

    string[] files;
    try { files = System.IO.Directory.GetFiles(dir); }
    catch (System.Exception) { files = new string[0]; }
    foreach (string file in files) WriteOne(file, sacl, ref firstError, ref objects, ref failures);

    string[] subs;
    try { subs = System.IO.Directory.GetDirectories(dir); }
    catch (System.Exception) { subs = new string[0]; }
    foreach (string sub in subs)
    {
      // Never follow a junction or symlink: it can leave the workspace tree.
      bool reparse = false;
      try { reparse = (System.IO.File.GetAttributes(sub) & System.IO.FileAttributes.ReparsePoint) != 0; }
      catch (System.Exception) { }
      WriteOne(sub, sacl, ref firstError, ref objects, ref failures);
      if (!reparse) pending.Push(sub);
    }
  }

  watch.Stop();
  LocalFree(descriptor);
  return "objects=" + objects + " failures=" + failures + " firstRc=" + firstError + " ms=" + watch.ElapsedMilliseconds;
}
'@

try {
  $result = [DshAclPreflight.LabelWriter]::Walk($Path, $Label)
  Write-Output $result
} catch {
  Write-Output ('objects=0 failures=0 firstRc=-1 error=' + $_.Exception.GetType().Name)
}
exit 0
