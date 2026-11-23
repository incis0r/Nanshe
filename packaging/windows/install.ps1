# Instalator Nanshe dla Windows. Uruchamiac z podniesionymi uprawnieniami:
#   powershell -ExecutionPolicy Bypass -File install.ps1
# Opcje: -InstallDir <katalog>, -NoPath (nie dopisuj do PATH), -NoShortcut, -Quiet
# Instaluje do katalogu, ktory moga zmieniac tylko administratorzy: narzedzie dziala z wysokimi
# uprawnieniami, wiec jego pliki nie moga byc zapisywalne dla zwyklych uzytkownikow.
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "Nanshe"),
    [switch]$NoPath,
    [switch]$NoShortcut,
    [switch]$Quiet
)
$ErrorActionPreference = "Stop"
function Say($t) { if (-not $Quiet) { Write-Host $t } }
function Fail($t) { Write-Host "BLAD: $t" -ForegroundColor Red; exit 1 }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "instalator wymaga uprawnien administratora (uruchom PowerShell jako administrator)" }

$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $src "nanshe.exe"
$sums = Join-Path $src "SHA256SUMS"
if (-not (Test-Path $exe)) { Fail "brak nanshe.exe obok instalatora" }
if (-not (Test-Path $sums)) { Fail "brak pliku SHA256SUMS obok instalatora" }

# 1. Zgodnosc plikow paczki z lista skrotow (wykrywa uszkodzenie albo podmiane pliku w paczce)
Say "Sprawdzam pliki paczki..."
foreach ($line in Get-Content $sums) {
    if ($line -notmatch "^([0-9a-f]{64})\s+\*?(.+)$") { continue }
    $want = $Matches[1]; $rel = $Matches[2]
    $f = Join-Path $src $rel
    if (-not (Test-Path $f)) { Fail "brak pliku z listy skrotow: $rel" }
    $got = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want) { Fail "skrot pliku $rel nie zgadza sie z lista (paczka uszkodzona albo zmieniona)" }
}

# Zabezpiecza katalog: tylko podane konta, bez dziedziczenia z katalogu nadrzednego, wlasciciel
# Administratorzy. Katalog, ktory juz istnieje, mogl zostac przygotowany przez zwyklego uzytkownika
# (w ProgramData kazdy moze tworzyc katalogi), wiec: dowiazanie albo obcy wlasciciel przerywa
# instalacje, a istniejaca zawartosc dostaje uprawnienia dziedziczone z zabezpieczonego katalogu.
$inherit = [Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$trusted = @("S-1-5-32-544", "S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
function Assert-DirSafe($path) {
    if (-not (Test-Path $path)) { return }
    $it = Get-Item $path -Force
    if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$path jest dowiazaniem, a nie zwyklym katalogiem; usun je i uruchom instalator ponownie" }
    $owner = (Get-Acl $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) { Fail "katalog $path juz istnieje i nalezy do konta $owner; sprawdz jego zawartosc, usun go i uruchom instalator ponownie" }
    $link = Get-ChildItem $path -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($link) { Fail "katalog $path zawiera dowiazanie ($($link.FullName)); usun je i uruchom instalator ponownie" }
}
function Protect-Dir($path, $rules) {
    Assert-DirSafe $path
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force $path | Out-Null }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($r in $rules) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($r[0])), $r[1], $inherit, "None", "Allow")))
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")))
    Set-Acl -Path $path -AclObject $acl
    # istniejace pliki i podkatalogi: wlasciciel Administratorzy i uprawnienia wylacznie dziedziczone
    if (Get-ChildItem $path -Force | Select-Object -First 1) {
        cmd /c "icacls `"$path\*`" /setowner *S-1-5-32-544 /T /C /L /Q >nul 2>&1"
        cmd /c "icacls `"$path\*`" /reset /T /C /L /Q >nul 2>&1"
    }
}

# Oba katalogi sa sprawdzane, zanim instalator cokolwiek zmieni: blad nie zostawia polowicznej instalacji.
$root = Join-Path $env:ProgramData "Nanshe"
Assert-DirSafe $InstallDir
Assert-DirSafe $root

# 2. Katalog instalacji: administratorzy i SYSTEM pelne prawa, uzytkownicy tylko odczyt
Say "Instaluje do $InstallDir"
Protect-Dir $InstallDir @(@("S-1-5-32-544", "FullControl"), @("S-1-5-18", "FullControl"), @("S-1-5-32-545", "ReadAndExecute"))

Copy-Item $exe $InstallDir -Force
foreach ($extra in @("kb", "LICENSE", "NOTICE", "LICENSE-DejaVu.txt", "README.md", "uninstall.ps1", "SHA256SUMS")) {
    $p = Join-Path $src $extra
    if (Test-Path $p) { Copy-Item $p $InstallDir -Recurse -Force }
}

# 3. Katalog na wyniki: raporty zawieraja dane z pamieci, wiec tylko administratorzy i SYSTEM
Protect-Dir $root @(@("S-1-5-32-544", "FullControl"), @("S-1-5-18", "FullControl"))
$data = Join-Path $root "wyniki"
New-Item -ItemType Directory -Force $data | Out-Null

# 4. PATH systemowy
if (-not $NoPath) {
    $path = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (($path -split ";") -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable("Path", ($path.TrimEnd(";") + ";" + $InstallDir), "Machine")
        Say "Dodano do PATH (nowe okna konsoli)"
    }
}

# 5. Skrot w menu Start: konsola administratora w katalogu wynikow
if (-not $NoShortcut) {
    $menu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Nanshe"
    New-Item -ItemType Directory -Force $menu | Out-Null
    $lnk = Join-Path $menu "Nanshe (konsola administratora).lnk"
    $sh = New-Object -ComObject WScript.Shell
    $s = $sh.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $s.Arguments = "-NoExit -Command `"Set-Location '$data'; & '$InstallDir\nanshe.exe' --help`""
    $s.WorkingDirectory = $data
    $s.Description = "Nanshe: triage pamieci (wymaga uprawnien administratora)"
    $s.Save()
    # flaga "uruchom jako administrator" w pliku skrotu (bajt 0x15, bit 0x20)
    $bytes = [IO.File]::ReadAllBytes($lnk); $bytes[0x15] = $bytes[0x15] -bor 0x20; [IO.File]::WriteAllBytes($lnk, $bytes)
}

# 6. Wpis w "Programy i funkcje"
$ver = "0.0.0"
try { $out = & (Join-Path $InstallDir "nanshe.exe") --version 2>$null; if ($out -match "(\d+\.\d+\.\d+)") { $ver = $Matches[1] } } catch {}
$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nanshe"
New-Item -Path $key -Force | Out-Null
$un = "powershell.exe -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
foreach ($kv in @(@("DisplayName", "Nanshe"), @("DisplayVersion", $ver), @("Publisher", "HoneyLens"), @("InstallLocation", $InstallDir),
        @("UninstallString", $un), @("QuietUninstallString", "$un -Quiet"))) {
    Set-ItemProperty -Path $key -Name $kv[0] -Value $kv[1]
}
Set-ItemProperty -Path $key -Name "NoModify" -Value 1 -Type DWord
Set-ItemProperty -Path $key -Name "NoRepair" -Value 1 -Type DWord

Say ""
Say "Zainstalowano Nanshe $ver"
Say "  program:  $InstallDir\nanshe.exe"
Say "  wyniki:   $data (dostep tylko dla administratorow)"
Say "  uzycie:   otworz konsole jako administrator i uruchom: nanshe scan --all --json wynik.json"
Say "  usuwanie: Programy i funkcje albo $InstallDir\uninstall.ps1"
exit 0
