# Test instalatora Windows na hoscie testowym: paczka, odmowa dla zmienionej paczki i dla dowiazania,
# instalacja, sprawdzenie uprawnien i wpisow, odinstalowanie. Zmienia host (Program Files, ProgramData,
# PATH, rejestr) i sprzata po sobie. Uruchamiac jako administrator z katalogu repo:
#   powershell -ExecutionPolicy Bypass -File scripts\test-installer.ps1 -Bin <katalog z nanshe.exe> -Work <katalog roboczy>
param([string]$Bin, [string]$Work)
$ErrorActionPreference = "Continue"
$fail = 0
function Check($name, $ok) { if ($ok) { "{0}: OK" -f $name } else { $script:fail = 1; "{0}: FAIL" -f $name } }
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$dist = Join-Path $Work "dist"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
$inst = Join-Path $env:ProgramFiles "Nanshe"
$data = Join-Path $env:ProgramData "Nanshe"
$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nanshe"
if ((Test-Path $inst) -or (Test-Path $data) -or (Test-Path $key)) { "host ma juz instalacje Nanshe; test przerwany, niczego nie zmieniam"; exit 2 }

powershell -ExecutionPolicy Bypass -File (Join-Path $repo "scripts\package-windows.ps1") -Bin $Bin -Out $dist | Out-Null
$zip = Get-ChildItem $dist -Filter *.zip | Select-Object -First 1
$stage = Get-ChildItem $dist -Directory | Select-Object -First 1
Check "paczka zip i lista skrotow" ($zip -and (Test-Path (Join-Path $stage.FullName "SHA256SUMS")) -and (Test-Path (Join-Path $stage.FullName "kb\common.json")))

# 1. Zmieniony plik w paczce: instalator musi odmowic i niczego nie zainstalowac
$bad = Join-Path $Work "dist-zmieniona"
if (Test-Path $bad) { Remove-Item $bad -Recurse -Force }
Copy-Item $stage.FullName $bad -Recurse
Add-Content (Join-Path $bad "kb\common.json") " "
powershell -ExecutionPolicy Bypass -File (Join-Path $bad "install.ps1") -Quiet *> $null; $rc = $LASTEXITCODE
Check "zmieniona paczka odrzucona" ($rc -eq 1 -and -not (Test-Path $inst))

# 2. Katalog wynikow podstawiony jako dowiazanie: odmowa przed jakakolwiek zmiana
$target = Join-Path $Work "cel-dowiazania"
New-Item -ItemType Directory -Force $target | Out-Null
cmd /c "mklink /J `"$data`" `"$target`" >nul"
powershell -ExecutionPolicy Bypass -File (Join-Path $stage.FullName "install.ps1") -Quiet *> $null; $rc = $LASTEXITCODE
Check "dowiazanie w ProgramData odrzucone" ($rc -eq 1 -and -not (Test-Path $inst) -and -not (Get-ChildItem $target -Force))
cmd /c "rmdir `"$data`""
Remove-Item $target -Recurse -Force

# 3. Wlasciwa instalacja
powershell -ExecutionPolicy Bypass -File (Join-Path $stage.FullName "install.ps1") -Quiet *> $null; $rc = $LASTEXITCODE
Check "instalacja kod 0" ($rc -eq 0)
$exe = Join-Path $inst "nanshe.exe"
$ver = if (Test-Path $exe) { (& $exe --version 2>$null) } else { "" }
Check "program dziala z katalogu instalacji ($ver)" ($ver -match "\d+\.\d+\.\d+")
Check "baza wiedzy i skrypt usuwania zainstalowane" ((Test-Path (Join-Path $inst "kb\windows.json")) -and (Test-Path (Join-Path $inst "kb\en\windows.json")) -and (Test-Path (Join-Path $inst "uninstall.ps1")))
function Rights($path) { (Get-Acl $path).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value + "=" + $_.FileSystemRights } }
$ri = Rights $inst; $rd = Rights $data
# zwykly uzytkownik (S-1-5-32-545) ma w katalogu programu tylko odczyt, a do wynikow nie ma dostepu wcale;
# nikt poza administratorami i SYSTEM nie ma prawa zapisu
$writers = @($ri + $rd | Where-Object { $_ -match "FullControl|Modify|Write" -and $_ -notmatch "^S-1-5-32-544=|^S-1-5-18=" })
Check "katalog programu: uzytkownicy tylko odczyt" (($ri -join ";") -match "S-1-5-32-545=ReadAndExecute, Synchronize" -and $writers.Count -eq 0)
Check "katalog wynikow: tylko administratorzy i SYSTEM" (@($rd | Where-Object { $_ -notmatch "^S-1-5-32-544=|^S-1-5-18=" }).Count -eq 0 -and (Test-Path (Join-Path $data "wyniki")))
Check "dziedziczenie uprawnien wylaczone" ((Get-Acl $inst).AreAccessRulesProtected -and (Get-Acl $data).AreAccessRulesProtected)
Check "PATH systemowy" (([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";") -contains $inst)
Check "wpis w Programy i funkcje" ((Get-ItemProperty $key -ErrorAction SilentlyContinue).DisplayName -eq "Nanshe" -and (Get-ItemProperty $key).UninstallString -match "uninstall.ps1")
Check "skrot w menu Start" (Test-Path (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Nanshe\Nanshe (konsola administratora).lnk"))
# ponowna instalacja na istniejaca (aktualizacja) przechodzi i nie dubluje PATH
powershell -ExecutionPolicy Bypass -File (Join-Path $stage.FullName "install.ps1") -Quiet *> $null; $rc = $LASTEXITCODE
Check "ponowna instalacja" ($rc -eq 0 -and @(([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";") | Where-Object { $_ -eq $inst }).Count -eq 1)

# 4a. Odinstalowanie z -RemoveData musi odmowic, gdy w katalogu wynikow jest dowiazanie:
#     usuwanie rekurencyjne z uprawnieniami administratora nie moze wyjsc poza katalog
$victim = Join-Path $Work "cel-usuwania"
New-Item -ItemType Directory -Force $victim | Out-Null
Set-Content (Join-Path $victim "wazny.txt") "nie usuwac"
cmd /c "mklink /J `"$data\wyniki\podstawione`" `"$victim`" >nul"
powershell -ExecutionPolicy Bypass -File (Join-Path $inst "uninstall.ps1") -RemoveData -Quiet *> $null; $rc = $LASTEXITCODE
Check "odinstalowanie odmawia przy dowiazaniu i niczego nie usuwa" ($rc -eq 1 -and (Test-Path (Join-Path $victim "wazny.txt")) -and (Test-Path (Join-Path $inst "nanshe.exe")))
cmd /c "rmdir `"$data\wyniki\podstawione`""
Remove-Item $victim -Recurse -Force

# 4. Odinstalowanie: najpierw bez danych (wyniki zostaja), potem z danymi
Set-Content (Join-Path $data "wyniki\probny.json") "{}"
powershell -ExecutionPolicy Bypass -File (Join-Path $inst "uninstall.ps1") -Quiet *> $null; $rc = $LASTEXITCODE
Check "odinstalowanie: program, PATH, rejestr i skrot usuniete, wyniki zostaja" ($rc -eq 0 -and -not (Test-Path $inst) -and -not (Test-Path $key) -and
    -not ((([Environment]::GetEnvironmentVariable("Path", "Machine")) -split ";") -contains $inst) -and
    -not (Test-Path (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Nanshe")) -and (Test-Path (Join-Path $data "wyniki\probny.json")))
Remove-Item $data -Recurse -Force
Check "host posprzatany" (-not (Test-Path $inst) -and -not (Test-Path $data) -and -not (Test-Path $key))
Remove-Item $bad -Recurse -Force -ErrorAction SilentlyContinue
"paczka: " + $zip.FullName
exit $fail
