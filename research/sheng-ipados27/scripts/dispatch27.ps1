[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('prepare', 'policies', 'data', 'bootstrap', 'kernel', 'gpu', 'firmware', 'package')]
    [string]$Stage,
    [string]$ResearchRef = 'research/sheng-ipados27',
    [string]$ResearchRepo = 'INTERINIT/UniXNU',
    [string]$BuildRepo = 'INTERINIT/sheng-ipados27-build-20261031',
    [string]$GhPath = 'D:\iOS6sp\tools\github-cli\bin\gh.exe',
    [switch]$Plan
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $GhPath -PathType Leaf)) {
    $GhPath = (Get-Command gh -ErrorAction Stop).Source
}

# Resolve names and short IDs before checkout@v4; it accepts only a full SHA
# as a detached commit. This also verifies that the revision is published.
$revision = & $GhPath api --method GET "repos/$ResearchRepo/commits" `
    -f "sha=$ResearchRef" -f 'per_page=1' --jq '.[0].sha'
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve one published full research commit'
}

Write-Output "Stage: $Stage"
Write-Output "Source: https://github.com/$ResearchRepo/commit/$revision"
Write-Output "Runner: $BuildRepo (host only; no device operation)"
if ($Plan) {
    return
}
& $GhPath workflow run ipados27.yml --repo $BuildRepo --ref main `
    -f "stage=$Stage" -f "research_ref=$revision"
if ($LASTEXITCODE -ne 0) {
    throw 'GitHub did not accept the workflow dispatch'
}
