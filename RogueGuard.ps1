#requires -version 5.1
<#
RogueGuard
Detects and optionally contains RoguePlanet-style Windows Defender LPE staging.

Run as Administrator.
#>

[CmdletBinding()]
param(
    [switch]$Mitigate,
    [switch]$Quarantine,
    [switch]$DetachSuspiciousDiskImages,
    [switch]$DisableWerQueueReporting,
    [int]$RecentHours = 24,
    [string]$QuarantineRoot = "$env:ProgramData\RogueGuard\Quarantine"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Log {
    param(
        [ValidateSet("INFO", "OK", "WARN", "HIGH", "ACTION")]
        [string]$Level,
        [string]$Message,
        [object]$Data = $null
    )

    $color = switch ($Level) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "HIGH" { "Red" }
        "ACTION" { "Cyan" }
        default { "Gray" }
    }

    Write-Host "[$Level] $Message" -ForegroundColor $color
    if ($null -ne $Data) {
        Write-Host ("       " + ($Data | ConvertTo-Json -Compress -Depth 5)) -ForegroundColor DarkGray
    }
}

function Get-HashSafe {
    param([string]$Path)
    try { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash } catch { $null }
}

function Quarantine-Or-Remove {
    param([string]$Path)

    if ($Quarantine) {
        New-Item -ItemType Directory -Force -Path $QuarantineRoot | Out-Null
        $safeName = ($Path -replace "[:\\\/]", "_").Trim("_")
        $dest = Join-Path $QuarantineRoot ("{0}_{1}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), $safeName)
        Move-Item -LiteralPath $Path -Destination $dest -Force
        Log ACTION "Quarantined artifact" @{ source = $Path; destination = $dest }
        return
    }

    Remove-Item -LiteralPath $Path -Recurse -Force
    Log ACTION "Removed artifact" @{ path = $Path }
}

function Get-TempRoots {
    $roots = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($root in @($env:TEMP, $env:TMP, "$env:SystemRoot\Temp")) {
        if ($root -and (Test-Path -LiteralPath $root)) { [void]$roots.Add($root) }
    }
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $temp = Join-Path $_.FullName "AppData\Local\Temp"
        if (Test-Path -LiteralPath $temp) { [void]$roots.Add($temp) }
    }
    @($roots)
}

if (-not (Test-Admin)) {
    throw "Run from elevated PowerShell."
}

Log INFO "RogueGuard audit started" @{
    mitigate = [bool]$Mitigate
    quarantine = [bool]$Quarantine
    recentHours = $RecentHours
}

$findings = 0
$cutoff = (Get-Date).AddHours(-1 * [math]::Abs($RecentHours))

# 1. Named pipe used by the PoC.
try {
    $pipe = Get-ChildItem "\\.\pipe\" -ErrorAction Stop | Where-Object Name -eq "RoguePlanet"
    if ($pipe) {
        $findings++
        Log HIGH "RoguePlanet named pipe found" "\\.\pipe\RoguePlanet"
    }
} catch {
    Log WARN "Could not enumerate named pipes" $_.Exception.Message
}

# 2. Suspicious processes from temp/RP paths.
$processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -in @("RoguePlanet.exe", "wermgr.exe", "conhost.exe") -and
    ($_.CommandLine -match "RoguePlanet|\\RP_[^\\]+\\|wermgr\.exe" -or $_.ExecutablePath -match "\\Temp\\RP_")
}

foreach ($proc in $processes) {
    $findings++
    Log HIGH "Suspicious process found" @{
        pid = $proc.ProcessId
        name = $proc.Name
        path = $proc.ExecutablePath
        commandLine = $proc.CommandLine
    }

    if ($Mitigate) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        Log ACTION "Stopped suspicious process" @{ pid = $proc.ProcessId }
    }
}

# 3. RP_* temp staging folders/files.
foreach ($root in Get-TempRoots) {
    Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "RP_*" -and ($_.CreationTime -ge $cutoff -or $_.LastWriteTime -ge $cutoff)
    } | ForEach-Object {
        $findings++
        Log HIGH "RoguePlanet temp staging artifact found" @{
            path = $_.FullName
            sha256 = if ($_.PSIsContainer) { $null } else { Get-HashSafe $_.FullName }
            created = $_.CreationTimeUtc.ToString("o")
            modified = $_.LastWriteTimeUtc.ToString("o")
        }

        if ($Mitigate) {
            Quarantine-Or-Remove $_.FullName
        }
    }
}

# 4. Mounted disk images from suspicious temp paths.
try {
    $images = Get-CimInstance -Namespace "root/Microsoft/Windows/Storage" -ClassName "MSFT_DiskImage" -ErrorAction Stop |
        Where-Object { $_.Attached -and ($_.ImagePath -match "\\Temp\\RP_|RoguePlanet") }

    foreach ($image in $images) {
        $findings++
        Log HIGH "Suspicious mounted disk image found" @{
            imagePath = $image.ImagePath
            devicePath = $image.DevicePath
        }

        if ($Mitigate -and $DetachSuspiciousDiskImages) {
            Dismount-DiskImage -ImagePath $image.ImagePath -ErrorAction SilentlyContinue
            Log ACTION "Detached disk image" @{ imagePath = $image.ImagePath }
        }
    }
} catch {
    Log WARN "Could not enumerate mounted disk images" $_.Exception.Message
}

# 5. Defender events that match the PoC flow.
try {
    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Windows Defender/Operational"
        Id = 1006,1007,1116,1117,5007
        StartTime = $cutoff
    } -ErrorAction Stop | Where-Object {
        $_.Message -match "EICAR|RoguePlanet|RP_|wermgr\.exe|Windows Error Reporting"
    } | Select-Object -First 10 | ForEach-Object {
        $findings++
        Log WARN "Defender event matches RoguePlanet indicators" @{
            time = $_.TimeCreated.ToString("o")
            id = $_.Id
            message = ($_.Message -replace "\s+", " ").Trim()
        }
    }
} catch {
    Log INFO "No matching Defender events found or log unavailable"
}

# 6. WER task used by the PoC.
$task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Error Reporting\" -TaskName "QueueReporting" -ErrorAction SilentlyContinue
if ($task) {
    Log INFO "WER QueueReporting task" @{
        state = $task.State.ToString()
        task = "$($task.TaskPath)$($task.TaskName)"
    }

    if ($Mitigate -and $DisableWerQueueReporting) {
        Disable-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName | Out-Null
        Log ACTION "Disabled WER QueueReporting task" "$($task.TaskPath)$($task.TaskName)"
    }
}

if ($findings -eq 0) {
    Log OK "No RoguePlanet-style indicators found"
} else {
    Log WARN "Audit completed with findings" @{ count = $findings }
}
