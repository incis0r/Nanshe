# Test end-to-end na Windows: próbki -> skan żywego procesu -> oczekiwane tagi i kody wyjścia.
# Użycie: powershell -ExecutionPolicy Bypass -File e2e.ps1 -Bin <katalog z nanshe.exe i nanshe-sample.exe> -Out <katalog wyników>
# Porównywane są tagi tylko z regionów o wadze co najmniej "podejrzane", żeby tło procesu nie maskowało wyniku.
param([string]$Bin = ".\target\release", [string]$Out = "$env:TEMP\nanshe-e2e")
# PowerShell 5 zamienia stderr programu natywnego na błąd; programy uruchamiane są przez cmd /c.
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force $Out | Out-Null
$N = Join-Path $Bin "nanshe.exe"; $S = Join-Path $Bin "nanshe-sample.exe"
$fail = 0

function Flagged($json) {
    $r = Get-Content $json -Raw -Encoding UTF8 | ConvertFrom-Json
    $tags = @(); $scores = @()
    foreach ($p in $r.processes) { foreach ($x in $p.regions) {
        if ($x.severity -in @("suspicious", "high")) { $tags += $x.findings.tag; $scores += $x.score }
    } }
    return @{ tags = (($tags | Sort-Object -Unique) -join ","); scores = (($scores | Sort-Object -Descending) -join ",") }
}

function Findings($json) {
    $r = Get-Content $json -Raw -Encoding UTF8 | ConvertFrom-Json
    return (@($r.partial) + @($r.processes | ForEach-Object { $_.max_severity; $_.regions }) | ConvertTo-Json -Depth 20 -Compress)
}

function Check($mode, $wantRc, $wantTags) {
    $ready = Join-Path $Out "$mode.pid"
    $proc = Start-Process -FilePath $S -ArgumentList $mode, "120" -RedirectStandardOutput $ready -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1500
    $j1 = Join-Path $Out "$mode.json"; $j2 = Join-Path $Out "$mode.2.json"
    cmd /c "`"$N`" scan --pid $($proc.Id) --json `"$j1`" 2> `"$(Join-Path $Out "$mode.txt")`""; $rc = $LASTEXITCODE
    cmd /c "`"$N`" scan --pid $($proc.Id) --json `"$j2`" 2> nul"
    $f = Flagged $j1
    # Żywy proces Windows zmienia liczbę regionów między skanami (wątki puli startują i kończą się),
    # więc porównywane są regiony ze znaleziskami, a nie liczniki, pełna mapa regionów ani kontekst systemowy.
    $a = Findings $j1
    $b = Findings $j2
    $det = if ($a -eq $b) { "ok" } else { "ROZNE" }
    $res = if ($rc -eq $wantRc -and $f.tags -eq $wantTags -and $det -eq "ok") { "OK" } else { $script:fail = 1; "FAIL" }
    "{0,-9} {1,-4} kod={2} (oczek. {3}) tagi=[{4}] (oczek. [{5}]) punkty=[{6}] powtarzalnosc-znalezisk={7}" -f $mode, $res, $rc, $wantRc, $f.tags, $wantTags, $f.scores, $det
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}

Check "clean"    0 ""
Check "rwx"      1 "ENT-X,RWX,X-PRIV"
Check "pe"       1 "HDR,X-PRIV"
Check "xmap"     1 "RWX,X-MAP"
Check "rx-stage" 1 "X-PRIV"
Check "shc" 1 "SHC,X-PRIV"
Check "thread"   1 "THR-PRIV,X-PRIV"   # watek (wstrzymany) z adresem startu w pamieci bez pliku
Check "inject"   1 "ENT-X,RWX,X-PRIV"
# red team: kontrola i ewazja
Check "data-noise" 0 ""              # wysoka entropia w danych RW to nie znalezisko
Check "rwx-lowent" 1 "RWX,X-PRIV"    # jak rwx, ale bez ENT-X na ladunku (asercja wyniku nizej)
Check "pe-corrupt" 1 "X-PRIV"        # zla sygnatura PE i brak tablicy sekcji: HDR gluchy (kontrola)
Check "pe-wiped" 1 "HDR,X-PRIV"      # sygnatury MZ i PE wyzerowane, tablica sekcji zostala: HDR po tablicy
Check "pe-offset"  1 "HDR,X-PRIV"    # naglowek PE w srodku strony: HDR szuka pod dowolnym przesunieciem
Check "ximage"     0 ""              # SLEPY PUNKT: MEM_IMAGE z %TEMP% niewidoczny (X-MAP tylko dla MEM_MAPPED)
Check "guard"      1 "GUARD-X,RWX,X-PRIV"  # strony straznika nie czytamy (Z1), ale metadane alarmuja
Check "guard-hide" 1 "GUARD-X,X-PRIV"  # jak pe, ale za PAGE_GUARD: HDR slepy, GUARD-X mowi, ze tresci nie sprawdzono
# red team: wstrzykniecie do warstwy LLM przez metadane
Check "inject-map" 1 "X-MAP"         # instrukcja w nazwie mapowanego pliku

# Probkи dynamiczne (pod przyszly --watch): skan w kazdej zgloszonej fazie; fazy czytane na biezaco
# z wyjscia probki, a skan wykonuje sie w stabilnym oknie miedzy wpisami.
function Check-Phases($mode, $interval, $total, $want) {
    # Uwaga na nazwy: PowerShell nie rozroznia wielkosci liter, wiec lokalne $out NADPISALOBY parametr $Out.
    $sampleOut = Join-Path $Out "$mode.out"
    $proc = Start-Process -FilePath $S -ArgumentList @($mode, "$interval", "$total") -RedirectStandardOutput $sampleOut -PassThru -WindowStyle Hidden
    $sr = $null
    foreach ($i in 1..50) {
        if (Test-Path $sampleOut) { try { $fs = [IO.File]::Open($sampleOut, "Open", "Read", "ReadWrite"); $sr = New-Object IO.StreamReader($fs); break } catch {} }
        Start-Sleep -Milliseconds 100
    }
    if ($null -eq $sr) { $script:fail = 1; "$mode fazy: FAIL (brak pliku wyjscia)"; return }
    $res = "OK"; $got = @()
    $deadline = (Get-Date).AddSeconds($total + 20)
    while ((-not $proc.HasExited -or $sr.Peek() -ge 0) -and (Get-Date) -lt $deadline) {
        $line = $sr.ReadLine()
        if ($null -eq $line) { Start-Sleep -Milliseconds 200; continue }
        if ($line -match ("^" + $mode + " \d+ (\S+)$")) {
            $phase = $Matches[1]
            $j = Join-Path $Out "$mode.last.json"
            cmd /c "`"$N`" scan --pid $($proc.Id) --no-hashes --no-context --json `"$j`" 2> nul" | Out-Null
            $tags = (Flagged $j).tags
            $w = $want[$phase]
            if ($tags -ne $w) { $script:fail = 1; $res = "FAIL" }
            $got += ("{0}:{1}" -f $phase, $(if ($tags -eq $w) { "ok" } else { "FAIL[$tags!=$w]" }))
        }
    }
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    $sr.Close()
    foreach ($ph in $want.Keys) { if (-not ($got | Where-Object { $_ -like "$ph`:*" })) { $script:fail = 1; $res = "FAIL" } }
    "{0} fazy: {1} [{2}]" -f $mode, $res, ($got -join " ")
}
$churnWant = @{ quiet = ""; "stage-rw" = ""; "stage-rx" = "X-PRIV"; hdr = "HDR,X-PRIV"; "armed-rwx" = "ENT-X,HDR,RWX,X-PRIV"; cleanup = "" }
Check-Phases "churn" 3 40 $churnWant
Check-Phases "sleepmask" 3 20 @{ armed = "X-PRIV"; masked = "" }

cmd /c "`"$N`" scan --pid 3999996 > nul 2>&1"
if ($LASTEXITCODE -eq 2) { "nieistniejacy pid: OK kod=2" } else { $fail = 1; "nieistniejacy pid: FAIL kod=$LASTEXITCODE (oczek. 2)" }

# Wstrzykniecie: tekst instrukcji nie moze trafic do ladunku dla modelu, znacznik musi byc podniesiony.
$dry = Join-Path $Out "inject.dry.json"
cmd /c "`"$N`" explain `"$(Join-Path $Out "inject.json")`" --dry-run > `"$dry`" 2> nul"
$txt = Get-Content $dry -Raw
$a = if ($txt -match "(?i)ignore previous") { $fail = 1; "FAIL" } else { "OK" }
$b = if ($txt -match 'instruction_like_text_detected": true') { "OK" } else { $fail = 1; "FAIL" }
"inject dry-run: instrukcja-odcieta=$a znacznik=$b"

# Asercje red team poza zestawem tagow.
# 1. rwx-lowent: region ladunku ma wynik 60 (RWX+X-PRIV), a nie 90 jak przy rwx - ENT-X nie odpalil.
if (((Flagged (Join-Path $Out "rwx.json")).scores -split ",") -contains "90") { "rwx kontrola wyniku 90: OK" } else { $fail = 1; "rwx kontrola wyniku 90: FAIL" }
$low = (Flagged (Join-Path $Out "rwx-lowent.json")).scores -split ","
if (($low -contains "90") -or -not ($low -contains "60")) { $fail = 1; "rwx-lowent wynik 60 bez ENT-X: FAIL" } else { "rwx-lowent wynik 60 bez ENT-X: OK" }
# 2. Wstrzykniecie przez nazwe mapowanego pliku: tekst instrukcji nie moze trafic do ladunku,
#    znacznik musi byc podniesiony.
$dry2 = Join-Path $Out "inject-map.dry.json"
cmd /c "`"$N`" explain `"$(Join-Path $Out "inject-map.json")`" --dry-run > `"$dry2`" 2> nul"
$txt2 = Get-Content $dry2 -Raw
$a = if ($txt2 -match "(?i)ignore previous") { $fail = 1; "FAIL" } else { "OK" }
$b = if ($txt2 -match 'instruction_like_text_detected": true') { "OK" } else { $fail = 1; "FAIL" }
"inject-map dry-run: instrukcja-odcieta=$a znacznik=$b"
# 3. Region wykonywalny za straznikiem: policzony jako nieczytelny, wynik czesciowy; kontrola: pe bez straznika.
$g = Get-Content (Join-Path $Out "guard-hide.json") -Raw -Encoding UTF8 | ConvertFrom-Json
$c = Get-Content (Join-Path $Out "pe.json") -Raw -Encoding UTF8 | ConvertFrom-Json
if ($g.partial -eq $true -and $g.processes[0].regions_unreadable -eq 1 -and $c.partial -eq $false -and $c.processes[0].regions_unreadable -eq 0) { "guard-hide nieczytelny=1 czesciowy, pe nieczytelny=0: OK" } else { $fail = 1; "guard-hide nieczytelny/czesciowy: FAIL" }
# 4. Raport: Markdown i PDF z wyniku skanu; kontrola: wynik bez znalezisk nie ma sekcji procesu.
cmd /c "`"$N`" report `"$(Join-Path $Out "rwx.json")`" --no-llm --md `"$(Join-Path $Out "rwx.report.md")`" --pdf `"$(Join-Path $Out "rwx.report.pdf")`" 2> nul"
cmd /c "`"$N`" report `"$(Join-Path $Out "clean.json")`" --no-llm --md `"$(Join-Path $Out "clean.report.md")`" --pdf `"$(Join-Path $Out "clean.report.pdf")`" 2> nul"
$md = Get-Content (Join-Path $Out "rwx.report.md") -Raw -Encoding UTF8
$mdc = Get-Content (Join-Path $Out "clean.report.md") -Raw -Encoding UTF8
$pdfHead = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes((Join-Path $Out "rwx.report.pdf")), 0, 5)
if ($pdfHead -eq "%PDF-" -and $md -match "RWX, X-PRIV, ENT-X" -and $md -match "(?m)^## \d+\. Proces " -and $mdc -notmatch "(?m)^## \d+\. Proces " -and $mdc -match "Brak znalezisk od poziomu") { "raport md+pdf: OK" } else { $fail = 1; "raport md+pdf: FAIL" }
# 5. Kontekst systemowy: probka ctx zostawia slady poza pamiecia (gniazda, proces potomny); skan ma je zebrac,
#    a raport pokazac. Kontrole: proces bez znalezisk (clean) i skan z --no-context nie maja kontekstu ani mapy.
$ready = Join-Path $Out "ctx.pid"
$proc = Start-Process -FilePath $S -ArgumentList "ctx", "120" -RedirectStandardOutput $ready -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 2000
$cj = Join-Path $Out "ctx.json"; $cn = Join-Path $Out "ctx.noctx.json"
cmd /c "`"$N`" scan --pid $($proc.Id) --json `"$cj`" 2> nul"
cmd /c "`"$N`" scan --pid $($proc.Id) --no-context --json `"$cn`" 2> nul"
cmd /c "`"$N`" report `"$cj`" --no-llm --md `"$(Join-Path $Out "ctx.report.md")`" --pdf `"$(Join-Path $Out "ctx.report.pdf")`" 2> nul"
# wersja angielska: skan i raport z --lang en; raport polski z angielskiego skanu ma o tym uprzedzic
$ce = Join-Path $Out "ctx.en.json"
cmd /c "`"$N`" --lang en scan --pid $($proc.Id) --json `"$ce`" 2> nul"
cmd /c "`"$N`" report `"$ce`" --no-llm --md `"$(Join-Path $Out "ctx.en.report.md")`" --pdf `"$(Join-Path $Out "ctx.en.report.pdf")`" 2> nul"
cmd /c "`"$N`" --lang pl report `"$ce`" --no-llm --md `"$(Join-Path $Out "ctx.mixed.report.md")`" --pdf `"$(Join-Path $Out "ctx.mixed.report.pdf")`" 2> nul"
Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.Id)" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
$p = (Get-Content $cj -Raw -Encoding UTF8 | ConvertFrom-Json).processes[0]
$x = $p.context
$miss = @()
if (-not ($x.cmdline -match "ctx 120")) { $miss += "wiersz polecen" }
if (-not $x.user) { $miss += "uzytkownik" }
if (-not $x.started) { $miss += "czas startu" }
if (-not ($x.exe_file.sha256 -match "^[0-9a-f]{64}$")) { $miss += "sha256 pliku programu" }
if (@($x.ancestors).Count -lt 1) { $miss += "przodkowie" }
if (-not (@($x.children) | Where-Object { $_.cmdline -match "clean 150" })) { $miss += "proces potomny" }
if (-not (@($x.sockets) | Where-Object { $_.state -eq "LISTEN" -and $_.local -match "^127\.0\.0\.1:" })) { $miss += "gniazdo LISTEN" }
if (@(@($x.sockets) | Where-Object { $_.state -eq "ESTABLISHED" -and $_.remote -match "^127\.0\.0\.1:" }).Count -lt 2) { $miss += "polaczenie ESTABLISHED" }
if (-not (@($x.flags) | Where-Object { $_[0] -match "^poziom integral" })) { $miss += "poziom integralnosci" }
if (@($p.layout).Count -lt 10) { $miss += "mapa regionow" }
# otwarte uchwyty: plik probki z nazwa, uchwyt do procesu potomnego z prawami, a liczba wszystkich wieksza niz zapisanych
if (-not (@($x.files) | Where-Object { $_.kind -eq "file" -and $_.target -match "ns-ctx-$($proc.Id)\.dat$" })) { $miss += "uchwyt pliku probki" }
if (-not (@($x.files) | Where-Object { $_.kind -eq "process" -and $_.target -match "nanshe-sample" -and $_.target -match "prawa:" })) { $miss += "uchwyt do procesu potomnego" }
if (-not (@($x.files) | Where-Object { $_.kind -eq "key" })) { $miss += "uchwyt klucza rejestru" }
if ($x.files_total -le @($x.files).Count) { $miss += "liczba wszystkich uchwytow" }
$md = Get-Content (Join-Path $Out "ctx.report.md") -Raw -Encoding UTF8
foreach ($want in @("Podsumowanie dla decydenta", "Priorytet weryfikacji", "Podstawa techniczna", "MITRE ATT", "Jak czyta", "(?m)^### Co to za program", "Program testowy narz", "(?m)^#### Jak sprawdzi", "procdump -ma $($proc.Id)", "(?m)^### Drzewo proces", "\(badany proces\)", "clean 150", "(?m)^### Sie", "LISTEN", "ESTABLISHED", "(?m)^### Otwarte pliki i uchwyty", "uchwyt do innego procesu", "(?m)^### Pliki zmapowane", "(?m)^### Mapa przestrzeni adresowej", "ZNALEZISKO \(wysokie\)", "(?m)^#### Profil entropii regionu", "(?m)^#### Podgl", "LoadLibraryA", "Format \| PE", "SHA-256")) {
    if ($md -notmatch $want) { $miss += "raport: $want" }
}
$noctx = (Get-Content $cn -Raw -Encoding UTF8 | ConvertFrom-Json).processes[0]
if ($noctx.context -or $noctx.layout) { $miss += "--no-context: kontekst mimo flagi" }
$cl = (Get-Content (Join-Path $Out "clean.json") -Raw -Encoding UTF8 | ConvertFrom-Json).processes[0]
if ($cl.context -or $cl.layout) { $miss += "clean: kontekst dla procesu bez znalezisk" }
if ($miss.Count -eq 0) { "kontekst systemowy i diagramy: OK" } else { $fail = 1; "kontekst systemowy i diagramy: FAIL (" + ($miss -join "; ") + ")" }
# 6. Wersja angielska: te same czesci raportu po angielsku i zadnego polskiego tekstu w wyniku ani w raporcie.
$miss = @()
$polish = "[\u0104-\u0107\u0118\u0119\u0141-\u0144\u00d3\u00f3\u015a\u015b\u0179-\u017c\u201e]"
$je = Get-Content $ce -Raw -Encoding UTF8
$mdEn = Get-Content (Join-Path $Out "ctx.en.report.md") -Raw -Encoding UTF8
$mdMix = Get-Content (Join-Path $Out "ctx.mixed.report.md") -Raw -Encoding UTF8
if ($je -notmatch '"lang": "en"') { $miss += "brak pola lang w wyniku" }
if (-not (@(($je | ConvertFrom-Json).processes[0].context.flags) | Where-Object { $_[0] -match "^integrity level" })) { $miss += "cecha integrity level" }
foreach ($want in @("Executive summary", "Verification priority", "Technical basis", "MITRE ATT", "How to read this report", "(?m)^### What this program is", "(?m)^#### How to verify this region", "procdump -ma $($proc.Id)",
    "(?m)^### Process tree", "\(examined process\)", "(?m)^### Network", "(?m)^### Open files and handles", "handle to another process with rights to interfere", "(?m)^### Files mapped into memory", "(?m)^### Address space map",
    "(?m)^#### What the process attributes mean", "integrity level = ", "(?m)^### From memory to network", "What this report does not cover", "Scanner privileges")) {
    if ($mdEn -notmatch $want) { $miss += "raport angielski: $want" }
}
foreach ($pair in @(@("wynik", $je), @("raport", $mdEn))) {
    $m = [regex]::Match($pair[1], ".{0,40}$polish.{0,40}")
    if ($m.Success) { $miss += "polski tekst ($($pair[0])): " + ($m.Value -replace "[^\x20-\x7e]", "?") }
}
if ($mdEn -match "different language") { $miss += "uwaga o jezykach w raporcie jednojezycznym" }
if ($mdMix -notmatch "Skan wykonano w innym") { $miss += "brak uwagi o jezykach w raporcie mieszanym" }
if ($mdMix -notmatch "Podsumowanie dla decydenta") { $miss += "raport z --lang pl nie jest po polsku" }
if ($miss.Count -eq 0) { "wersja angielska: OK" } else { $fail = 1; "wersja angielska: FAIL (" + ($miss -join "; ") + ")" }
# 7. Raport roznicowy: wynik tej samej probki dwa razy nie daje nowych regionow (kontrola), a porownanie wynikow
#    dwoch roznych probek pokazuje proces, ktory zniknal, i nowy proces ze znaleziskami.
$miss = @()
$d1 = Join-Path $Out "same.diff.md"; $d2 = Join-Path $Out "two.diff.md"; $d3 = Join-Path $Out "two.en.diff.md"
cmd /c "`"$N`" diff `"$(Join-Path $Out "rwx.json")`" `"$(Join-Path $Out "rwx.json")`" --md `"$d1`" --pdf `"$(Join-Path $Out "same.diff.pdf")`" 2> nul"
cmd /c "`"$N`" diff `"$(Join-Path $Out "rwx.json")`" `"$(Join-Path $Out "pe.json")`" --md `"$d2`" --pdf `"$(Join-Path $Out "two.diff.pdf")`" 2> nul"
cmd /c "`"$N`" --lang en diff `"$(Join-Path $Out "rwx.json")`" `"$(Join-Path $Out "pe.json")`" --md `"$d3`" --pdf `"$(Join-Path $Out "two.en.diff.pdf")`" 2> nul"
if (-not ((Test-Path $d1) -and (Test-Path $d2) -and (Test-Path $d3))) { $miss += "brak plikow raportu" } else {
    # uwaga: nazwy zmiennych PowerShell nie rozrozniaja wielkosci liter ($s nadpisaloby $S, sciezke do probki)
    $diffSame = Get-Content $d1 -Raw -Encoding UTF8; $diffTwo = Get-Content $d2 -Raw -Encoding UTF8; $diffEn = Get-Content $d3 -Raw -Encoding UTF8
    if ($diffSame -notmatch "\| Nowe regiony w dzia.* \| 0 \|") { $miss += "ten sam wynik: nowe regiony" }
    if ($diffSame -cmatch "NOWY") { $miss += "ten sam wynik: wiersz NOWY" }
    if ($diffTwo -notmatch "\| Nowe procesy ze znaleziskami \| 1 ") { $miss += "rozne procesy: brak nowego procesu" }
    if ($diffTwo -notmatch "znikn.* \| 1 ") { $miss += "rozne procesy: brak procesu, ktory zniknal" }
    if ($diffTwo -notmatch "HDR") { $miss += "rozne procesy: brak tagow nowego procesu" }
    if ($diffEn -notmatch "(?m)^# Nanshe: differential report") { $miss += "brak wersji angielskiej" }
    $pdfHead = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes((Join-Path $Out "two.diff.pdf")), 0, 5)
    if ($pdfHead -ne "%PDF-") { $miss += "pdf" }
}
if ($miss.Count -eq 0) { "raport roznicowy: OK" } else { $fail = 1; "raport roznicowy: FAIL (" + ($miss -join "; ") + ")" }
# 8. Zrzut pamieci procesu: pelny minidump probki (MiniDumpWriteDump z dbghelp.dll, skladnik systemu) daje te same
#    tagi co skan na zywo; zrzut probki bez znalezisk nie daje zadnych (kontrola); raport mowi, ze zrodlem jest zrzut.
Add-Type @"
using System; using System.IO; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class NansheDump {
    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr process, uint pid, SafeFileHandle file, uint type, IntPtr e, IntPtr u, IntPtr c);
    public static bool Write(int pid, string path) {
        var p = System.Diagnostics.Process.GetProcessById(pid);
        using (var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None)) {
            // MiniDumpWithFullMemory (0x2) | MiniDumpWithFullMemoryInfo (0x800) | MiniDumpWithThreadInfo (0x1000)
            return MiniDumpWriteDump(p.Handle, (uint)pid, fs.SafeFileHandle, 0x2 | 0x800 | 0x1000, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        }
    }
}
"@
$miss = @()
foreach ($case in @(@("rwx", 1, "ENT-X,RWX,X-PRIV"), @("pe", 1, "HDR,X-PRIV"), @("thread", 1, "THR-PRIV,X-PRIV"), @("guard", 1, "GUARD-X,RWX,X-PRIV"), @("clean", 0, ""))) {
    $mode = $case[0]
    $proc = Start-Process -FilePath $S -ArgumentList $mode, "120" -RedirectStandardOutput (Join-Path $Out "dump-$mode.pid") -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1500
    $dmp = Join-Path $Out "dump-$mode.dmp"; $dj = Join-Path $Out "dump-$mode.json"
    $ok = [NansheDump]::Write($proc.Id, $dmp)
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    if (-not $ok) { $miss += "${mode}: zrzut nie powstal"; continue }
    cmd /c "`"$N`" scan `"$dmp`" --json `"$dj`" > nul 2> nul"; $rc = $LASTEXITCODE
    $f = Flagged $dj
    if ($rc -ne $case[1] -or $f.tags -ne $case[2]) { $miss += "${mode}: kod=$rc (oczek. $($case[1])) tagi=[$($f.tags)] (oczek. [$($case[2])])" }
    $pj = (Get-Content $dj -Raw -Encoding UTF8 | ConvertFrom-Json).processes[0]
    if ($pj.info.source_type -ne "dump" -or $pj.info.pid -ne $proc.Id -or $pj.info.name -ne "nanshe-sample.exe") { $miss += "${mode}: metadane zrzutu ($($pj.info.source_type), $($pj.info.pid), $($pj.info.name))" }
    if ($mode -eq "rwx") {
        cmd /c "`"$N`" report `"$dj`" --no-llm --md `"$(Join-Path $Out "dump.report.md")`" --pdf `"$(Join-Path $Out "dump.report.pdf")`" 2> nul"
        $dm = Get-Content (Join-Path $Out "dump.report.md") -Raw -Encoding UTF8
        if ($dm -notmatch "zrzut pami") { $miss += "raport nie mowi o zrzucie" }
        if ($dm -match "(?m)^### Sie") { $miss += "raport ze zrzutu ma sekcje sieci" }
    }
    Remove-Item $dmp -Force -ErrorAction SilentlyContinue
}
Set-Content -Path (Join-Path $Out "not-a-dump") -Value "to nie jest zrzut"
cmd /c "`"$N`" scan `"$(Join-Path $Out "not-a-dump")`" > nul 2> nul"
if ($LASTEXITCODE -ne 2) { $miss += "plik niebedacy zrzutem: kod $LASTEXITCODE zamiast 2" }
# 9. Zmiana kodu biblioteki: jeden bajt funkcji z version.dll zmieniony w pamieci daje IMG-MOD z porownania z plikiem
#    (dokladnie 1 bajt, 10 punktow); kontrola: ta sama strona zapisana ta sama trescia nie zglasza roznicy.
$pm = @()
foreach ($mode in @("patch", "touch")) {
    $proc = Start-Process -FilePath $S -ArgumentList $mode, "120" -RedirectStandardOutput (Join-Path $Out "$mode.pid") -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 1500
    $pj = Join-Path $Out "$mode.json"
    cmd /c "`"$N`" scan --pid $($proc.Id) --json `"$pj`" > nul 2> nul"
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    $found = @((Get-Content $pj -Raw -Encoding UTF8 | ConvertFrom-Json).processes[0].regions | ForEach-Object { $_.findings } | Where-Object { $_.tag -eq "IMG-MOD" -and $_.reason -match "version\.dll" })
    if ($mode -eq "patch") {
        if ($found.Count -ne 1) { $pm += "patch: znalezisk IMG-MOD w version.dll: $($found.Count)" }
        elseif ($found[0].weight -ne 10 -or $found[0].reason -notmatch ": 1 bajt") { $pm += "patch: waga $($found[0].weight), opis: " + ($found[0].reason -replace "[^\x20-\x7e]", "?") }
    } else {
        # kontrola: tresc bez zmian. Tozsamosci pliku na Windows nie da sie potwierdzic, wiec zostaje jedno znalezisko
        # informacyjne (10 punktow) mowiace o zgodnosci z plikiem, bez liczby roznych bajtow.
        if ($found.Count -ne 1) { $pm += "touch: znalezisk IMG-MOD w version.dll: $($found.Count)" }
        elseif ($found[0].weight -ne 10 -or $found[0].reason -notmatch "zgodna z plikiem" -or $found[0].reason -match "bajt") { $pm += "touch: waga $($found[0].weight), opis: " + ($found[0].reason -replace "[^\x20-\x7e]", "?") }
    }
}
if ($pm.Count -eq 0) { "zmiana kodu biblioteki (porownanie z plikiem): OK" } else { $fail = 1; "zmiana kodu biblioteki (porownanie z plikiem): FAIL (" + ($pm -join "; ") + ")" }
if ($miss.Count -eq 0) { "zrzut pamieci procesu (minidump): OK" } else { $fail = 1; "zrzut pamieci procesu (minidump): FAIL (" + ($miss -join "; ") + ")" }
# Pliki probek w TEMP zostaja po zabitych procesach (rx-file nie ma tu odpowiednika, ale ximage/inject-map tak)
Start-Sleep -Milliseconds 500
Remove-Item (Join-Path $env:TEMP "ns-*") -Force -ErrorAction SilentlyContinue
exit $fail
