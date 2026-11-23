# Buduje instalator MSI Nanshe dla Windows (WiX Toolset 3.14, licencja MS-RL; narzedzie tylko do budowania,
# nie trafia do paczki). Uruchamiac na hoscie budujacym:
#   powershell -ExecutionPolicy Bypass -File scripts\package-msi.ps1 -Bin <katalog z nanshe.exe> -Wix <katalog z candle.exe> [-Out <katalog>]
# WiX: https://github.com/wixtoolset/wix3/releases (wix314-binaries.zip). Pliki WiX nie maja podpisu cyfrowego,
# dlatego skrypt sprawdza skrot archiwum, jesli lezy obok katalogu -Wix pod nazwa wix314-binaries.zip.
param([string]$Bin, [string]$Wix, [string]$Out = "dist")
$ErrorActionPreference = "Stop"
$WixZipSha256 = "6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31"
# Staly identyfikator rodziny produktu: po nim nowsza wersja rozpoznaje i zastepuje starsza. Nie zmieniac.
$UpgradeCode = "491BD779-E986-41A9-8916-B89D9052A28F"
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
function Fail($t) { Write-Host "BLAD: $t"; exit 1 }
$exe = Join-Path $Bin "nanshe.exe"
if (-not (Test-Path $exe)) { Fail "brak $exe" }
$candle = Join-Path $Wix "candle.exe"; $light = Join-Path $Wix "light.exe"
if (-not ((Test-Path $candle) -and (Test-Path $light))) { Fail "brak candle.exe albo light.exe w $Wix" }
$zip = Join-Path (Split-Path -Parent $Wix) "wix314-binaries.zip"
if (Test-Path $zip) {
    if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $WixZipSha256) { Fail "archiwum WiX ma inny skrot SHA-256 niz zapisany w skrypcie" }
}
$ver = "0.0.0"
$v = & $exe --version 2>$null
if ($v -match "(\d+\.\d+\.\d+)") { $ver = $Matches[1] }
$name = "nanshe-$ver-windows-x64"
New-Item -ItemType Directory -Force $Out | Out-Null
$work = Join-Path $Out "msi-work"
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $work | Out-Null

# licencja w formacie RTF do okna instalatora (tresc pliku LICENSE bez zmian)
$esc = (Get-Content (Join-Path $repo "LICENSE") -Raw -Encoding UTF8) -replace "\\", "\\" -replace "\{", "\{" -replace "\}", "\}" -replace "`r?`n", "\par`r`n"
$rtf = Join-Path $work "License.rtf"
[IO.File]::WriteAllText($rtf, "{\rtf1\ansi\deff0{\fonttbl{\f0 Consolas;}}\fs16 " + $esc + "}", [Text.Encoding]::ASCII)

# skrot w menu Start uruchamia ten plik: konsola z podniesionymi uprawnieniami w katalogu wynikow
$console = Join-Path $work "nanshe-console.cmd"
[IO.File]::WriteAllText($console, "@echo off`r`npowershell -NoProfile -Command ""Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','Set-Location -LiteralPath ''%~dp0wyniki''; & ''%~dp0nanshe.exe'' --help'""`r`n", [Text.Encoding]::ASCII)

# pliki bazy wiedzy: kazdy plik to osobny skladnik (identyfikatory skladnikow wylicza WiX ze sciezki docelowej)
function KbComponents($dir, $prefix) {
    (Get-ChildItem $dir -File -Filter *.json | Sort-Object Name | ForEach-Object {
        $id = $prefix + ($_.BaseName -replace "[^A-Za-z0-9]", "_")
        "        <Component Id=""c_$id"" Guid=""*""><File Id=""f_$id"" Source=""$($_.FullName)"" KeyPath=""yes"" /></Component>"
    }) -join "`r`n"
}
$kb = Join-Path $repo "kb"
$kbPl = KbComponents $kb "kb_"
$kbEn = KbComponents (Join-Path $kb "en") "kben_"
$refs = (([regex]::Matches($kbPl + $kbEn, 'Component Id="([^"]+)"') | ForEach-Object { "      <ComponentRef Id=""$($_.Groups[1].Value)"" />" }) -join "`r`n")

$wxs = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Nanshe" Language="1033" Version="$ver" Manufacturer="HoneyLens" UpgradeCode="$UpgradeCode">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" Platform="x64" Description="Nanshe: memory triage" Comments="Apache-2.0" />
    <MajorUpgrade AllowSameVersionUpgrades="yes" DowngradeErrorMessage="A newer version of Nanshe is already installed." />
    <MediaTemplate EmbedCab="yes" />
    <!-- wersja zainstalowana skryptem install.ps1 uzywa tego samego katalogu: najpierw trzeba ja usunac -->
    <Property Id="SCRIPTINSTALL"><RegistrySearch Id="rs_script" Root="HKLM" Key="SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nanshe" Name="DisplayName" Type="raw" Win64="yes" /></Property>
    <Condition Message="Nanshe installed with install.ps1 was found. Remove it first (Programs and Features or uninstall.ps1).">Installed OR NOT SCRIPTINSTALL</Condition>
    <Property Id="ARPURLINFOABOUT" Value="https://honeylens.io" />
    <WixVariable Id="WixUILicenseRtf" Value="$rtf" />
    <UIRef Id="WixUI_Minimal" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLDIR" Name="Nanshe">
          <Directory Id="KBDIR" Name="kb"><Directory Id="KBENDIR" Name="en" /></Directory>
          <Directory Id="RESULTSDIR" Name="wyniki" />
        </Directory>
      </Directory>
      <Directory Id="ProgramMenuFolder"><Directory Id="NansheMenuDir" Name="Nanshe" /></Directory>
    </Directory>
    <DirectoryRef Id="INSTALLDIR">
      <Component Id="c_exe" Guid="*"><File Id="f_exe" Source="$exe" KeyPath="yes" /></Component>
      <Component Id="c_console" Guid="*"><File Id="f_console" Source="$console" KeyPath="yes" /></Component>
      <Component Id="c_notice" Guid="*"><File Id="f_notice" Source="$(Join-Path $repo 'NOTICE')" KeyPath="yes" /></Component>
      <Component Id="c_license" Guid="*"><File Id="f_license" Source="$(Join-Path $repo 'LICENSE')" KeyPath="yes" /></Component>
      <Component Id="c_fontlicense" Guid="*"><File Id="f_fontlicense" Source="$(Join-Path $repo 'crates\nanshe-report\fonts\LICENSE-DejaVu.txt')" KeyPath="yes" /></Component>
      <Component Id="c_readme" Guid="*"><File Id="f_readme" Source="$(Join-Path $repo 'README.md')" KeyPath="yes" /></Component>
      <!-- PATH systemowy: dopisanie przy instalacji, usuniecie wpisu przy odinstalowaniu -->
      <Component Id="c_path" Guid="{B6B0C0B5-6C0E-4B7B-9C55-0A1B2C3D4E01}" KeyPath="yes">
        <Environment Id="env_path" Name="PATH" Value="[INSTALLDIR]" Permanent="no" Part="last" Action="set" System="yes" />
      </Component>
    </DirectoryRef>
    <!-- katalog na wyniki: raporty zawieraja dane z pamieci, wiec dostep maja tylko administratorzy i SYSTEM.
         Lezy w Program Files, gdzie zwykly uzytkownik nie moze niczego przygotowac przed instalacja. -->
    <DirectoryRef Id="RESULTSDIR">
      <Component Id="c_results" Guid="{B6B0C0B5-6C0E-4B7B-9C55-0A1B2C3D4E02}" KeyPath="yes">
        <CreateFolder>
          <!-- wlasciciel Administratorzy; tylko Administratorzy i SYSTEM; bez dziedziczenia z katalogu nadrzednego.
               Zapis SDDL nie zalezy od jezyka systemu (nazwy grup sa tlumaczone). -->
          <PermissionEx Sddl="O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)" />
        </CreateFolder>
      </Component>
    </DirectoryRef>
    <DirectoryRef Id="KBDIR">
$kbPl
    </DirectoryRef>
    <DirectoryRef Id="KBENDIR">
$kbEn
    </DirectoryRef>
    <DirectoryRef Id="NansheMenuDir">
      <Component Id="c_menu" Guid="{B6B0C0B5-6C0E-4B7B-9C55-0A1B2C3D4E03}">
        <Shortcut Id="sc_console" Name="Nanshe (administrator console)" Description="Nanshe: memory triage (requires administrator privileges)" Target="[INSTALLDIR]nanshe-console.cmd" WorkingDirectory="INSTALLDIR" />
        <RemoveFolder Id="rm_menu" On="uninstall" />
        <!-- skladnik ze skrotem musi miec klucz w HKCU (wymog Instalatora Windows), takze przy instalacji dla wszystkich -->
        <RegistryValue Root="HKCU" Key="SOFTWARE\HoneyLens\Nanshe" Name="menu" Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </DirectoryRef>
    <Feature Id="Main" Title="Nanshe" Level="1">
      <ComponentRef Id="c_exe" /><ComponentRef Id="c_console" /><ComponentRef Id="c_license" /><ComponentRef Id="c_notice" /><ComponentRef Id="c_fontlicense" /><ComponentRef Id="c_readme" />
      <ComponentRef Id="c_path" /><ComponentRef Id="c_results" /><ComponentRef Id="c_menu" />
$refs
    </Feature>
  </Product>
</Wix>
"@
$src = Join-Path $work "nanshe.wxs"
[IO.File]::WriteAllText($src, $wxs, (New-Object Text.UTF8Encoding($false)))
$obj = Join-Path $work "nanshe.wixobj"
$msi = Join-Path $Out "$name.msi"
if (Test-Path $msi) { Remove-Item $msi -Force }
$o1 = & $candle -nologo -arch x64 -out $obj $src 2>&1
if ($LASTEXITCODE -ne 0) { $o1 | ForEach-Object { Write-Host $_ }; Fail "candle.exe" }
# Sprawdzenie spojnosci (ICE) wymaga uslugi Instalatora Windows w sesji interaktywnej; w sesji zdalnej bywa
# niedostepne. Najpierw proba ze sprawdzeniem, a gdy sama usluga odmowi (LGHT0217), budowanie bez niego.
$o2 = & $light -nologo -ext WixUIExtension -cultures:en-us -out $msi $obj 2>&1
$validated = $true
if ($LASTEXITCODE -ne 0 -and (($o2 | Out-String) -match "LGHT0217")) {
    $validated = $false
    $o2 = & $light -nologo -sval -ext WixUIExtension -cultures:en-us -out $msi $obj 2>&1
}
if ($LASTEXITCODE -ne 0) { $o2 | ForEach-Object { Write-Host $_ }; if (Test-Path $msi) { Remove-Item $msi -Force }; Fail "light.exe" }
$o2 | Where-Object { "$_" -match "warning|error" } | ForEach-Object { Write-Host $_ }
Remove-Item $work -Recurse -Force
Get-ChildItem $Out -Filter "$name.wixpdb" -ErrorAction SilentlyContinue | Remove-Item -Force
"msi: " + (Resolve-Path $msi).Path
"sha256: " + (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
"sprawdzenie ICE: " + $(if ($validated) { "wykonane" } else { "pominiete (usluga niedostepna w tej sesji)" })
exit 0
