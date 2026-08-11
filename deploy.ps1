[CmdletBinding()]
param(
    [string]$Server = "root@135.106.181.55",
    [ValidateRange(1, 65535)]
    [int]$Port = 22,
    [string]$IdentityFile = "",
    [string]$Branch = "main",
    [string]$RemoteName = "origin",
    [string]$RemoteAppDir = "/opt/khudoverdiev",
    [string]$ServiceName = "khudoverdiev.service"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Step {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message" -ForegroundColor Cyan
}

function Assert-NativeSuccess {
    param([string]$Operation)
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

function Assert-SafeValue {
    param(
        [string]$Name,
        [string]$Value,
        [string]$Pattern
    )
    if ($Value -notmatch $Pattern) {
        throw "Invalid ${Name} value: $Value"
    }
}

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    throw "SSH was not found. Install the Windows OpenSSH Client feature."
}

Assert-SafeValue -Name "Server" -Value $Server -Pattern '^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$'
Assert-SafeValue -Name "Branch" -Value $Branch -Pattern '^[A-Za-z0-9._/-]+$'
Assert-SafeValue -Name "RemoteName" -Value $RemoteName -Pattern '^[A-Za-z0-9._-]+$'
Assert-SafeValue -Name "RemoteAppDir" -Value $RemoteAppDir -Pattern '^/[A-Za-z0-9._/-]+$'
Assert-SafeValue -Name "ServiceName" -Value $ServiceName -Pattern '^[A-Za-z0-9_.@-]+$'

$RemoteCommand = "cd '$RemoteAppDir' && APP_DIR='$RemoteAppDir' BRANCH='$Branch' REMOTE='$RemoteName' SERVICE='$ServiceName' ./deploy.sh"
$SshArguments = @("-p", $Port.ToString())
if ($IdentityFile) {
    $ResolvedIdentityFile = (Resolve-Path -LiteralPath $IdentityFile).Path
    $SshArguments += @("-i", $ResolvedIdentityFile)
}
$SshArguments += @($Server, $RemoteCommand)

Write-Step "Loading $RemoteName/$Branch from GitHub on $Server"
& ssh @SshArguments
Assert-NativeSuccess "Remote deployment"

Write-Host "Deployment completed successfully." -ForegroundColor Green
