# Usuwa Nanshe: pliki programu, wpis PATH, skrot i wpis w "Programy i funkcje".
# Katalog wynikow (%ProgramData%\Nanshe) zostaje, chyba ze podano -RemoveData.
param([switch]$RemoveData, [switch]$Quiet)
$ErrorActionPreference = "Stop"
function Say($t) { if (-not $Quiet) { Write-Host $t } }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "BLAD: wymagane uprawnienia administratora" -ForegroundColor Red; exit 1 }

# Usuwanie rekurencyjne dziala z uprawnieniami administratora, wiec katalog musi byc zwyklym katalogiem
# nalezacym do konta systemowego i bez dowiazan w srodku: inaczej podstawione dowiazanie skierowaloby
# usuwanie w inne miejsce.
$trusted = @("S-1-5-32-544", "S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
function Assert-DirSafe($path) {
    $it = Get-Item $path -Force
    if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { Write-Host "BLAD: $path jest dowiazaniem; niczego nie usuwam" -ForegroundColor Red; exit 1 }
    $owner = (Get-Acl $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) { Write-Host "BLAD: katalog $path nalezy do konta $owner; niczego nie usuwam" -ForegroundColor Red; exit 1 }
    $link = Get-ChildItem $path -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($link) { Write-Host "BLAD: katalog $path zawiera dowiazanie ($($link.FullName)); usun je recznie i uruchom ponownie" -ForegroundColor Red; exit 1 }
}

$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nanshe"
$dir = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).InstallLocation
if (-not $dir) { $dir = Join-Path $env:ProgramFiles "Nanshe" }
# zabezpieczenie: usuwamy tylko katalog, w ktorym faktycznie lezy nanshe.exe
if (-not (Test-Path (Join-Path $dir "nanshe.exe"))) { Write-Host "BLAD: w $dir nie ma nanshe.exe; niczego nie usuwam" -ForegroundColor Red; exit 1 }
# oba katalogi sprawdzamy, zanim cokolwiek zostanie usuniete
Assert-DirSafe $dir
$data = Join-Path $env:ProgramData "Nanshe"
if ($RemoveData -and (Test-Path $data)) { Assert-DirSafe $data }

$path = [Environment]::GetEnvironmentVariable("Path", "Machine")
$kept = ($path -split ";") | Where-Object { $_ -and $_ -ne $dir }
[Environment]::SetEnvironmentVariable("Path", ($kept -join ";"), "Machine")

$menu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Nanshe"
if (Test-Path $menu) { Remove-Item $menu -Recurse -Force }
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue

# skrypt moze byc uruchomiony z katalogu instalacji: wychodzimy z niego przed usunieciem
Set-Location $env:SystemRoot
Remove-Item $dir -Recurse -Force
if ($RemoveData) {
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
    Say "Usunieto Nanshe razem z katalogiem wynikow"
} else {
    Say "Usunieto Nanshe; wyniki zostaly w $(Join-Path $env:ProgramData 'Nanshe') (usun z -RemoveData)"
}
exit 0
