$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Dist = Join-Path $Root "dist\PuzzleSlipstream-v0.1.0-windows-x64"

Push-Location $Root
try {
    cargo fmt --all -- --check
    cargo test --workspace
    cargo build --release --workspace

    if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
    New-Item -ItemType Directory -Path $Dist | Out-Null

    Copy-Item "target\release\puzzle-slipstream-signer.exe" $Dist
    Copy-Item "target\release\puzzle-slipstream-relay.exe" $Dist
    Copy-Item "README.md", "THREAT_MODEL.md", "DISCLAIMER.md", "DONATE.md", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE" $Dist

    $Hashes = Get-ChildItem $Dist -File | Get-FileHash -Algorithm SHA256
    $Hashes | ForEach-Object { "$($_.Hash.ToLower())  $($_.Path | Split-Path -Leaf)" } | Set-Content (Join-Path $Dist "SHA256SUMS.txt")

    $Zip = "$Dist.zip"
    if (Test-Path $Zip) { Remove-Item -Force $Zip }
    Compress-Archive -Path "$Dist\*" -DestinationPath $Zip
    Write-Host "Created $Zip"
}
finally {
    Pop-Location
}
