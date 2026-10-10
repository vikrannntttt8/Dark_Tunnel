# scripts/test.ps1 - Cross-package test runner for Windows
param (
    [string]$Package = "./..."
)

$ErrorActionPreference = "Stop"
$env:GOTOOLCHAIN = "local"
$env:Path = "$env:USERPROFILE\go-sdk\go\bin;$env:Path"

Write-Host "==> Discovering packages for: $Package" -ForegroundColor Cyan
$packages = go list $Package | Where-Object { $_ -notlike "*contracts" }

$binDir = Join-Path $PSScriptRoot "..\bin"
if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir | Out-Null
}

$allPassed = $true

foreach ($pkg in $packages) {
    $pkgName = Split-Path $pkg -Leaf
    $testExe = Join-Path $binDir "run_${pkgName}_test.exe"
    
    Write-Host "--> Building test binary for $pkg..." -ForegroundColor Yellow
    go test -c $pkg -o $testExe
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to compile tests for $pkg" -ForegroundColor Red
        $allPassed = $false
        continue
    }

    Write-Host "--> Running tests for $pkg..." -ForegroundColor Green
    Unblock-File -Path $testExe -ErrorAction SilentlyContinue
    & $testExe "-test.v"
    if ($LASTEXITCODE -ne 0) {
        $allPassed = $false
    }
    
    Remove-Item -Force $testExe -ErrorAction SilentlyContinue
}

if ($allPassed) {
    Write-Host "==> ALL TESTS PASSED!" -ForegroundColor Green
} else {
    Write-Host "==> SOME TESTS FAILED!" -ForegroundColor Red
    exit 1
}
