param(
    [string]$VmxPath = $env:MEMSCOPE_VMX,
    [string]$IsoPath = 'D:\MayAo\win11-tu-cai.iso',
    [string]$VmrunPath = $env:MEMSCOPE_VMRUN,
    [string]$ToolsIso,
    [switch]$SnapshotOnly
)

$ErrorActionPreference = 'Stop'
if (!$VmxPath) { $VmxPath = 'D:\MayAo\Win11-IE105\Win11-IE105.vmx' }
$vmx = (Resolve-Path -LiteralPath $VmxPath).ProviderPath
if (!$VmrunPath) {
    $command = Get-Command vmrun.exe -ErrorAction SilentlyContinue
    $VmrunPath = if ($command) { $command.Source } else {
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    }
}
$vmrun = (Resolve-Path -LiteralPath $VmrunPath).ProviderPath
if (!$ToolsIso) { $ToolsIso = Join-Path (Split-Path $vmrun) 'windows.iso' }
$password = $env:MEMSCOPE_WINDOWS_PASSWORD
if (!$password) { $password = $env:IE105_WINDOWS_PASSWORD }
if (!$password) { $password = 'ie105test' }

function Invoke-VMware {
    $output = & $vmrun '-T' 'ws' @args
    if ($LASTEXITCODE -ne 0) { throw "vmrun $($args[0]) failed. $($output -join ' ')" }
    return $output
}

function Test-VMRunning {
    return [bool]((Invoke-VMware list) -contains $vmx)
}

function Set-GuestConfiguration([bool]$Attach) {
    if (Test-VMRunning) { throw 'Power off the guest before editing its configuration.' }
    if (Get-ChildItem -LiteralPath (Split-Path $vmx) -Filter '*.lck') {
        throw 'VMware still holds a lock. Close the guest tab and try again.'
    }

    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    try {
        $config = $utf8.GetString([IO.File]::ReadAllBytes($vmx)).TrimStart([char]0xfeff)
    } catch {
        $config = [IO.File]::ReadAllText($vmx, [Text.Encoding]::GetEncoding(1252))
    }
    if ($Attach -and $config -match '(?im)^\s*(vtpm|tpm)\.present\s*=\s*"TRUE"') {
        throw 'Use a blank IE105 lab guest without a virtual TPM or encrypted VMX.'
    }
    $settings = [ordered]@{
        '.encoding' = 'UTF-8'
        'firmware' = 'efi'
        'isolation.tools.hgfs.disable' = 'TRUE'
        'isolation.tools.copy.disable' = 'TRUE'
        'isolation.tools.paste.disable' = 'TRUE'
        'isolation.tools.dnd.disable' = 'TRUE'
        'mainMem.useNamedFile' = 'TRUE'
        'sata0:1.present' = 'FALSE'
        'sata0:1.startConnected' = 'FALSE'
        'sata0:2.present' = 'FALSE'
        'sata0:2.startConnected' = 'FALSE'
    }
    foreach ($nic in [regex]::Matches($config, '(?im)^\s*(ethernet\d+)\.present\s*=')) {
        $settings[$nic.Groups[1].Value + '.present'] = 'FALSE'
        $settings[$nic.Groups[1].Value + '.startConnected'] = 'FALSE'
    }
    foreach ($share in [regex]::Matches($config, '(?im)^\s*(sharedfolder\d+\.enabled)\s*=')) {
        $settings[$share.Groups[1].Value] = 'FALSE'
    }

    if ($Attach) {
        $settings['sata0:1.present'] = 'TRUE'
        $settings['sata0:1.startConnected'] = 'TRUE'
        $settings['sata0:1.deviceType'] = 'cdrom-image'
        $settings['sata0:1.fileName'] = $IsoPath
        $settings['sata0:2.present'] = 'TRUE'
        $settings['sata0:2.startConnected'] = 'TRUE'
        $settings['sata0:2.deviceType'] = 'cdrom-image'
        $settings['sata0:2.fileName'] = $ToolsIso
    } else {
        $config = $config -replace '(?im)^\s*sata0:[12]\.fileName\s*=[^\r\n]*(?:\r?\n|$)', ''
    }
    foreach ($key in $settings.Keys) {
        $config = $config -replace "(?im)^\s*$([regex]::Escape($key))\s*=[^\r\n]*(?:\r?\n|$)", ''
    }
    $lines = foreach ($key in $settings.Keys) { '{0} = "{1}"' -f $key, $settings[$key] }
    $config = ($lines -join [Environment]::NewLine) + [Environment]::NewLine + $config
    [IO.File]::WriteAllText($vmx, $config, $utf8)
}

function Test-GuestReady {
    $state = & $vmrun '-T' 'ws' checkToolsState $vmx
    if ($LASTEXITCODE -ne 0 -or (($state -join ' ').Trim() -notin 'running', 'installed')) {
        return $false
    }
    $processes = & $vmrun '-T' 'ws' '-gu' 'test' '-gp' $password listProcessesInGuest $vmx
    return ($LASTEXITCODE -eq 0 -and ($processes -join " ") -match '\bexplorer\.exe\b')
}

if ((Invoke-VMware listSnapshots $vmx) -contains 'sach') {
    throw 'A snapshot named sach already exists.'
}

if (!$SnapshotOnly) {
    $IsoPath = (Resolve-Path -LiteralPath $IsoPath).ProviderPath
    $ToolsIso = (Resolve-Path -LiteralPath $ToolsIso).ProviderPath
    if (Test-Path -LiteralPath "$vmx.before-install") {
        throw 'Installation was already started. Inspect the VM and use -SnapshotOnly to finish.'
    }
    if (Test-VMRunning) { throw 'Power off the blank guest before unattended installation.' }
    Copy-Item -LiteralPath $vmx -Destination "$vmx.before-install"
    Set-GuestConfiguration $true
    Write-Host 'Starting unattended Windows installation and waiting for VMware Tools.'
    Invoke-VMware start $vmx nogui
} elseif (!(Test-VMRunning)) {
    Set-GuestConfiguration $false
    Write-Host 'Starting the installed guest to verify VMware Tools and sign-in.'
    Invoke-VMware start $vmx nogui
}

$watch = [Diagnostics.Stopwatch]::StartNew()
$readySince = $null
while ($watch.Elapsed.TotalMinutes -lt 60) {
    if (Test-GuestReady) {
        if ($null -eq $readySince) { $readySince = $watch.Elapsed.TotalSeconds }
        if ($watch.Elapsed.TotalSeconds - $readySince -ge 45) { break }
    } else {
        $readySince = $null
    }
    Start-Sleep -Seconds 5
}
if ($watch.Elapsed.TotalMinutes -ge 60) { throw 'VMware Tools and guest sign-in did not become ready within 60 minutes.' }

Invoke-VMware stop $vmx soft
$shutdown = [Diagnostics.Stopwatch]::StartNew()
while ((Test-VMRunning) -and $shutdown.Elapsed.TotalSeconds -lt 120) { Start-Sleep -Seconds 3 }
Set-GuestConfiguration $false
Invoke-VMware snapshot $vmx sach
Invoke-VMware listSnapshots $vmx
