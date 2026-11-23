# Test instalatora MSI na hoscie testowym: budowanie, instalacja cicha, sprawdzenie plikow, uprawnien i wpisow,
# ponowna instalacja, odinstalowanie. Zmienia host (Program Files, PATH, rejestr, menu Start) i sprzata po sobie.
# Uruchamiac jako administrator:
#   powershell -ExecutionPolicy Bypass -File scripts\test-msi.ps1 -Bin <katalog z nanshe.exe> -Wix <katalog WiX> -Work <katalog roboczy>
param([string]$Bin, [string]$Wix, [string]$Work)
$ErrorActionPreference = "Continue"
$fail = 0
function Check($name, $ok) { if ($ok) { "{0}: OK" -f $name } else { $script:fail = 1; "{0}: FAIL" -f $name } }
$repo = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$dist = Join-Path $Work "msi"
$inst = Join-Path $env:ProgramFiles "Nanshe"
$results = Join-Path $inst "wyniki"
$menu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Nanshe"
function Arp { Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -eq "Nanshe" } }
function MachinePath { ([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";") | ForEach-Object { $_.TrimEnd("\") } }
function Msi($argline) { $p = Start-Process msiexec.exe -ArgumentList $argline -Wait -PassThru; $p.ExitCode }
if ((Test-Path $inst) -or (Arp)) { "host ma juz instalacje Nanshe; test przerwany, niczego nie zmieniam"; exit 2 }

if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
$out = powershell -ExecutionPolicy Bypass -File (Join-Path $repo "scripts\package-msi.ps1") -Bin $Bin -Wix $Wix -Out $dist
$built = $LASTEXITCODE
$out | Where-Object { $_ -match "BLAD|error|warning|sprawdzenie ICE" } | ForEach-Object { "  $_" }
Check "budowanie bez bledow" ($built -eq 0)
$msi = Get-ChildItem $dist -Filter *.msi -ErrorAction SilentlyContinue | Select-Object -First 1
Check "plik msi zbudowany" ($null -ne $msi)
if (-not $msi) { exit 1 }
$log = Join-Path $dist "install.log"

Check "instalacja cicha kod 0" ((Msi "/i `"$($msi.FullName)`" /qn /norestart /l*v `"$log`"") -eq 0)
$ver = & (Join-Path $inst "nanshe.exe") --version 2>$null
Check "program dziala z katalogu instalacji ($ver)" ($ver -match "nanshe \d+\.\d+\.\d+")
Check "baza wiedzy (pl i en), licencje i plik konsoli zainstalowane" ((Test-Path (Join-Path $inst "kb\windows.json")) -and (Test-Path (Join-Path $inst "kb\en\windows.json")) -and (Test-Path (Join-Path $inst "LICENSE")) -and (Test-Path (Join-Path $inst "NOTICE")) -and (Test-Path (Join-Path $inst "LICENSE-DejaVu.txt")) -and (Test-Path (Join-Path $inst "nanshe-console.cmd")))
# raport z zainstalowanej wersji korzysta z wbudowanej bazy: krotki test, ze program nie potrzebuje niczego spoza katalogu
# same bity zapisu: maski zlozone (Modify, FullControl) zawieraja tez odczyt i pasowalyby do wpisu "tylko odczyt"
$writeRights = [Security.AccessControl.FileSystemRights]"WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership"
$lowSids = @("S-1-5-32-545", "S-1-5-11", "S-1-1-0", "S-1-5-4")
function LowWrite($path) { (Get-Acl $path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq "Allow" -and $lowSids -contains $_.IdentityReference.Value -and ($_.FileSystemRights -band $writeRights) } }
# kontrola samego sprawdzenia: katalog z prawem zapisu dla uzytkownikow musi zostac wykryty
$probe = Join-Path $Work "acl-probe"; New-Item -ItemType Directory -Force $probe | Out-Null
cmd /c "icacls `"$probe`" /grant *S-1-5-32-545:(OI)(CI)M /Q >nul 2>&1"
Check "kontrola: sprawdzenie uprawnien wykrywa katalog zapisywalny" ([bool](LowWrite $probe))
Remove-Item $probe -Recurse -Force
Check "katalog programu i nanshe.exe: zwykli uzytkownicy bez prawa zapisu" (-not (LowWrite $inst) -and -not (LowWrite (Join-Path $inst "nanshe.exe")) -and -not (LowWrite (Join-Path $inst "nanshe-console.cmd")))
$racl = Get-Acl $results
$rules = $racl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
$others = $rules | Where-Object { @("S-1-5-32-544", "S-1-5-18") -notcontains $_.IdentityReference.Value }
Check "katalog wynikow: tylko administratorzy i SYSTEM" ((Test-Path $results) -and (@($rules).Count -ge 2) -and -not $others)
Check "katalog wynikow: dziedziczenie wylaczone, wlasciciel Administratorzy" ($racl.AreAccessRulesProtected -and $racl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq "S-1-5-32-544")
Check "PATH systemowy" ((MachinePath) -contains $inst)
$arp = Arp
Check "wpis w Programy i funkcje (Instalator Windows)" ($arp -and $arp.Publisher -eq "HoneyLens" -and $arp.WindowsInstaller -eq 1 -and $arp.DisplayVersion -match "^\d+\.\d+\.\d+$")
Check "skrot w menu Start" (Test-Path (Join-Path $menu "Nanshe (administrator console).lnk"))
Check "ponowna instalacja tej samej wersji kod 0" ((Msi "/i `"$($msi.FullName)`" /qn /norestart") -eq 0)
Check "po ponownej instalacji jeden wpis i dzialajacy program" ((@(Arp).Count -eq 1) -and ((& (Join-Path $inst "nanshe.exe") --version 2>$null) -match "nanshe"))

# odinstalowanie: plik z wynikami ma zostac, reszta zniknac
$keep = Join-Path $results "wynik-testowy.json"
Set-Content -Path $keep -Value "{}"
Check "odinstalowanie kod 0" ((Msi "/x `"$($msi.FullName)`" /qn /norestart") -eq 0)
Check "odinstalowanie: program, baza, PATH, wpis i skrot usuniete" (-not (Test-Path (Join-Path $inst "nanshe.exe")) -and -not (Test-Path (Join-Path $inst "kb")) -and -not ((MachinePath) -contains $inst) -and -not (Arp) -and -not (Test-Path $menu))
Check "odinstalowanie: wyniki zostaja" (Test-Path $keep)

# sprzatanie po tescie
Remove-Item $inst -Recurse -Force -ErrorAction SilentlyContinue
Check "host posprzatany" (-not (Test-Path $inst) -and -not (Arp) -and -not (Test-Path "HKCU:\SOFTWARE\HoneyLens\Nanshe"))
"msi: $($msi.FullName)"
"sha256: " + (Get-FileHash $msi.FullName -Algorithm SHA256).Hash.ToLower()
exit $fail
