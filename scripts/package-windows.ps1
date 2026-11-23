# Buduje paczke instalacyjna Nanshe dla Windows: katalog i plik zip z programem, baza wiedzy,
# instalatorem i lista skrotow SHA-256. Uruchamiac na hoscie z toolchainem MSVC, z katalogu repo:
#   powershell -ExecutionPolicy Bypass -File scripts\package-windows.ps1 [-Bin <katalog z nanshe.exe>] [-Out <katalog>]
param([string]$Bin = "", [string]$Out = "dist")
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repo
if (-not $Bin) {
    cmd /c "cargo build --release -p nanshe-cli --features llm 2>&1"
    if ($LASTEXITCODE -ne 0) { Write-Host "BLAD: build nie powiodl sie"; exit 1 }
    $Bin = if ($env:CARGO_TARGET_DIR) { Join-Path $env:CARGO_TARGET_DIR "release" } else { Join-Path $repo "target\release" }
}
$exe = Join-Path $Bin "nanshe.exe"
if (-not (Test-Path $exe)) { Write-Host "BLAD: brak $exe"; exit 1 }
$ver = "0.0.0"
$v = & $exe --version 2>$null
if ($v -match "(\d+\.\d+\.\d+)") { $ver = $Matches[1] }
$name = "nanshe-$ver-windows-x64"
$stage = Join-Path $Out $name
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item $exe $stage
Copy-Item (Join-Path $repo "kb") $stage -Recurse
Copy-Item (Join-Path $repo "packaging\windows\install.ps1") $stage
Copy-Item (Join-Path $repo "packaging\windows\uninstall.ps1") $stage
# licencja programu (Apache-2.0) i plik NOTICE ida z kazda kopia; brak pliku przerywa budowanie paczki
foreach ($f in @("README.md", "LICENSE", "NOTICE")) { Copy-Item (Join-Path $repo $f) $stage }
# czcionka DejaVu jest wbudowana w program (raport PDF): jej licencja idzie z paczka
Copy-Item (Join-Path $repo "crates\nanshe-report\fonts\LICENSE-DejaVu.txt") $stage
# lista skrotow wszystkich plikow paczki (sciezki wzgledne); instalator sprawdza ja przed kopiowaniem
$lines = Get-ChildItem $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring((Resolve-Path $stage).Path.Length + 1)
    (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() + "  " + $rel
}
[IO.File]::WriteAllLines((Join-Path (Resolve-Path $stage).Path "SHA256SUMS"), $lines)
$zip = Join-Path $Out "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip
"paczka: " + (Resolve-Path $zip).Path
"sha256: " + (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
exit 0
