<#
.SYNOPSIS
    Provision sample TOTP test profiles onto a Token2 key via the t2totp CLI,
    including one tagged for Auto-OTP ([A]).

.DESCRIPTION
    Adds a handful of profiles using well-known RFC-style test secrets so the
    codes are reproducible and can be cross-checked against any other
    authenticator. These are TEST secrets — do not use them for real accounts.

    Each secret is sent to `t2totp add` on standard input, never as an argument.

.PARAMETER Args
    Any extra arguments (e.g. -Transport nfc) are forwarded to every t2totp call.
    Pass them through after a `--`, e.g.:
        .\add-sample-profiles.ps1 --transport nfc
        .\add-sample-profiles.ps1 --reader "ACS ACR1252 1S CL Reader"

.EXAMPLE
    .\add-sample-profiles.ps1

.EXAMPLE
    $env:T2TOTP = ".\target\release\t2totp.exe"; .\add-sample-profiles.ps1
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CommonArgs
)

$ErrorActionPreference = 'Stop'

# Locate the binary: $env:T2TOTP, then PATH, then .\target\release, then debug.
$t2totp = $env:T2TOTP
if (-not $t2totp) {
    if (Get-Command t2totp -ErrorAction SilentlyContinue) {
        $t2totp = 't2totp'
    } elseif (Test-Path '.\target\release\t2totp.exe') {
        $t2totp = '.\target\release\t2totp.exe'
    } elseif (Test-Path '.\target\debug\t2totp.exe') {
        $t2totp = '.\target\debug\t2totp.exe'
    } else {
        Write-Error 't2totp binary not found. Build it (cargo build --release) or set $env:T2TOTP.'
        exit 1
    }
}

if (-not $CommonArgs) { $CommonArgs = @() }

# Add a profile, piping the Base32 secret on stdin (never on the command line).
function Add-Profile {
    param(
        [string]$Issuer,
        [string]$Account,
        [string]$Secret,
        [string[]]$Extra = @()
    )
    Write-Host "  + ${Issuer}:${Account} $($Extra -join ' ')"
    # Send the secret via stdin. `--%` would stop PS parsing, but we build the
    # argument array explicitly instead.
    $arguments = @($CommonArgs + @('add', $Issuer, $Account) + $Extra)
    $Secret | & $t2totp @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "t2totp add failed for ${Issuer}:${Account} (exit $LASTEXITCODE)"
    }
}

Write-Host "Using: $t2totp $($CommonArgs -join ' ')"
Write-Host 'Adding sample TOTP profiles...'

# Standard SHA-1 / 30s / 6-digit (RFC 6238 test seed "12345678901234567890").
Add-Profile -Issuer 'Example' -Account 'alice@example.com' `
    -Secret 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

# SHA-256 variant.
Add-Profile -Issuer 'Acme' -Account 'bob@acme.test' `
    -Secret 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' -Extra @('--sha256')

# 8 digits, 60-second step.
Add-Profile -Issuer 'Widgets' -Account 'carol' `
    -Secret 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' -Extra @('--digits', '8', '--period', '60')

# Touch-required profile.
Add-Profile -Issuer 'Bank' -Account 'dave' `
    -Secret 'KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU' -Extra @('--touch')

# The Auto-OTP profile: tagged [A] so the global hotkey targets it. Only ONE
# profile should carry the [A] tag.
Add-Profile -Issuer 'MyAuto' -Account 'me@auto.test' `
    -Secret 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' -Extra @('--auto')

Write-Host ''
Write-Host 'Done. Current profiles:'
& $t2totp @CommonArgs list
