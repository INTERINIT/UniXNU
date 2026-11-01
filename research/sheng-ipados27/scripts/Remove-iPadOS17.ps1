[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Delete
)

$ErrorActionPreference = 'Stop'
$taskRoot = (Resolve-Path -LiteralPath 'D:\iOS6sp').ProviderPath.TrimEnd('\')
$taskTargets = @(
    'D:\iOS6sp\package17',
    'D:\iOS6sp\iPadOS17-Start',
    'D:\iOS6sp\iPadOS17-DataGPU',
    'D:\iOS6sp\boot17-v4',
    'D:\iOS6sp\iPadOS27\reference17',
    'D:\iOS6sp\iPadOS17-sheng-RAM-Start.zip',
    'D:\iOS6sp\iPadOS17-sheng-RAM-Start.package.json',
    'D:\iOS6sp\resources\apple',
    'D:\iOS6sp\resources\community\run41022950787-candidate',
    'D:\iOS6sp\resources\community\run41026091408-candidate',
    'D:\iOS6sp\resources\community\run41026540374-candidate',
    'D:\iOS6sp\resources\community\sheng-inputs21H461',
    'D:\iOS6sp\resources\community\sheng-upstream-39919525158',
    'D:\iOS6sp\resources\community\sheng-21H461-v1.tar.gz',
    'D:\iOS6sp\resources\community\sheng-upstream-xnu-39919525158.zip',
    'D:\iOS6sp\research\continue17',
    'D:\iOS6sp\research\gpu17-baseline',
    'D:\iOS6sp\work\build17-repo',
    'D:\iOS6sp\work\volumes21H461'
)

# Validate every existing absolute target before performing any deletion.
# Generic sources, Android vendor files, UEFI tools and iPadOS27 are preserved.
$taskRecords = @()
foreach ($taskTarget in $taskTargets) {
    if (-not (Test-Path -LiteralPath $taskTarget)) {
        continue
    }
    $taskItem = Get-Item -LiteralPath $taskTarget -Force
    $taskAbsolute = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $taskTarget).ProviderPath)
    if ($taskAbsolute -eq $taskRoot -or
        -not $taskAbsolute.StartsWith($taskRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        -not $taskAbsolute.Equals([IO.Path]::GetFullPath($taskTarget), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Resolved deletion path escaped the reviewed target: $taskTarget"
    }
    if ($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Review reparse-point target separately: $taskAbsolute"
    }
    if ($taskItem.PSIsContainer) {
        $taskChildren = @(Get-ChildItem -LiteralPath $taskAbsolute -Force -Recurse)
        if (@($taskChildren | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
            throw "Review nested reparse points separately: $taskAbsolute"
        }
        $taskBytes = [long](($taskChildren | Where-Object { -not $_.PSIsContainer } |
            Measure-Object -Property Length -Sum).Sum)
    }
    else {
        $taskBytes = [long]$taskItem.Length
    }
    $taskRecords += [pscustomobject]@{
        Path = $taskAbsolute
        LogicalBytes = $taskBytes
        Directory = [bool]$taskItem.PSIsContainer
    }
}

$taskRecords | Select-Object Path, @{Name='LogicalGiB';Expression={[Math]::Round($_.LogicalBytes / 1GB, 3)}} |
    Format-Table -AutoSize
$taskLogical = [long](($taskRecords | Measure-Object -Property LogicalBytes -Sum).Sum)
Write-Host ("Reviewed logical total: {0:N2} GiB (actual freed space can differ)." -f ($taskLogical / 1GB))
if (-not $Delete) {
    Write-Host 'Preview only. Run this script with -Delete to remove the reviewed targets.'
    return
}

$taskBefore = [long](Get-PSDrive -Name D).Free
$taskReport = [ordered]@{
    Request = 'iPadOS17 route abandoned by user; delete only reviewed 17 packages and caches'
    StartedUtc = [DateTime]::UtcNow.ToString('o')
    FreeBeforeBytes = $taskBefore
    ReviewedTargets = $taskRecords
    DeletedTargets = @()
    Status = 'deleting'
    DeviceOperations = $false
}
$taskLogPath = Join-Path $taskRoot ('cleanup-ipados17-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fffffff') + '.json')
$taskReport | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $taskLogPath -Encoding UTF8

try {
    foreach ($taskRecord in $taskRecords) {
        if (-not $PSCmdlet.ShouldProcess($taskRecord.Path, 'Delete iPadOS17 package/cache')) {
            continue
        }
        Remove-Item -LiteralPath $taskRecord.Path -Recurse -Force
        if (Test-Path -LiteralPath $taskRecord.Path) {
            throw "Target still exists after deletion: $($taskRecord.Path)"
        }
        $taskReport.DeletedTargets += $taskRecord.Path
        $taskReport | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $taskLogPath -Encoding UTF8
    }
    $taskReport.Status = 'completed'
}
catch {
    $taskReport.Status = 'partial_failure'
    $taskReport.Error = $_.Exception.Message
    throw
}
finally {
    $taskReport.FreeAfterBytes = [long](Get-PSDrive -Name D).Free
    $taskReport.FreedBytes = $taskReport.FreeAfterBytes - $taskBefore
    $taskReport.CompletedUtc = [DateTime]::UtcNow.ToString('o')
    $taskReport | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $taskLogPath -Encoding UTF8
    Write-Host ("Actual free-space change: {0:N2} GiB" -f ($taskReport.FreedBytes / 1GB))
    Write-Host ("Report: " + $taskLogPath)
}
