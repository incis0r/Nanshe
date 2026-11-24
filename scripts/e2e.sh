#!/bin/sh
# Test end-to-end w kontenerze Linux: próbki -> skan żywego procesu -> oczekiwane tagi i kody wyjścia.
# Uruchamiać przez: scripts/dev.sh sh scripts/e2e.sh [katalog wyników]
set -u
OUT="${1:-/tmp/nanshe-e2e}"; mkdir -p "$OUT"
cargo build -q --workspace --features nanshe-cli/llm || exit 2
N=/target/debug/nanshe; S=/target/debug/nanshe-sample
fail=0
# Tło platformy: tagi, które ma na tej architekturze nawet próbka "clean" (w kontenerze arm64 jest to ENT-X
# poniżej progu "podejrzane" w kodzie biblioteki libc, na x86_64 nic). Własny ENT-X wnoszą tylko próbki
# z ładunkiem o wysokiej entropii: rwx, memfd, inject, inject-memfd i ctx (ustalone z wyników, 2026-11-24). Oczekiwania poniżej podają tylko to, co wnosi sama próbka;
# tło jest do nich doliczane. Bez tego test przechodził tylko na architekturze, na której go strojono.
BASE=""
union() { printf '%s\n%s\n' "$1" "$2" | tr ',' '\n' | grep -v '^$' | sort -u | paste -sd, -; }
check() { # nazwa, oczekiwany kod, tagi wnoszone przez próbkę (posortowane, po przecinku)
  mode=$1; want_rc=$2; want_tags=$(union "$3" "$BASE")
  $S "$mode" 60 > "$OUT/$mode.pid" & sleep 0.5
  pid=$(awk '{print $2}' "$OUT/$mode.pid")
  $N scan --pid "$pid" --json "$OUT/$mode.json" 2> "$OUT/$mode.txt"; rc=$?
  $N scan --pid "$pid" --json "$OUT/$mode.2.json" 2>/dev/null
  tags=$(grep -o '"tag": "[A-Z-]*"' "$OUT/$mode.json" | cut -d'"' -f4 | sort -u | paste -sd, -)
  a=$(grep -v '"timestamp"' "$OUT/$mode.json" | sha256sum); b=$(grep -v '"timestamp"' "$OUT/$mode.2.json" | sha256sum)
  det=ok; [ "$a" = "$b" ] || det=ROZNE
  res=OK; { [ "$rc" = "$want_rc" ] && [ "$tags" = "$want_tags" ] && [ $det = ok ]; } || { res=FAIL; fail=1; }
  printf '%-7s %-4s kod=%s (oczek. %s) tagi=[%s] (oczek. [%s]) powtarzalność=%s\n' "$mode" "$res" "$rc" "$want_rc" "$tags" "$want_tags" "$det"
  # przy niezgodności: regiony ze znaleziskami (adres, rozmiar, uprawnienia, tagi, źródło), żeby log wskazywał przyczynę
  [ $res = OK ] || regions "$OUT/$mode.txt" "$mode"
  kill "$pid" 2>/dev/null
}
# Wypisuje regiony ze znaleziskami od wagi "podejrzane" z wydruku skanu (adres, rozmiar, uprawnienia,
# waga, tagi, źródło): po jednym wierszu "FAIL-REGION ..." na region.
regions() {
  grep -E '^  0x' "$1" | sed "s/^ */FAIL-REGION $2: /" | cut -c1-220
}
# próbka "clean" wyznacza tło: nie może mieć nic poza ENT-X i nie może przekraczać progu (kod 0)
$S clean 60 > "$OUT/base.pid" & sleep 0.5
$N scan --pid "$(awk '{print $2}' "$OUT/base.pid")" --json "$OUT/base.json" 2>/dev/null
BASE=$(grep -o '"tag": "[A-Z-]*"' "$OUT/base.json" | cut -d'"' -f4 | sort -u | paste -sd, -)
kill "$(awk '{print $2}' "$OUT/base.pid")" 2>/dev/null
case "$BASE" in ""|"ENT-X") echo "tło platformy: [$BASE]";; *) echo "tło platformy FAIL: próbka clean ma tagi [$BASE]"; fail=1;; esac
check clean  0 ""
check rwx    1 "ENT-X,RWX,X-PRIV"
check elf    1 "HDR,X-PRIV"
check memfd  1 "ENT-X,MEMFD"
check inject 1 "ENT-X,RWX,X-PRIV"
# red team: kontrola i ewazja
check data-noise   0 ""                  # wysoka entropia w danych RW to nie znalezisko
check rx-file      1 "X-TMP"             # R-X z pliku w /tmp: łapie X-TMP (katalog zapisywalny dla wszystkich)
check rwx-lowent   1 "RWX,X-PRIV"        # jak rwx, ale bez ENT-X na ładunku (asercja wyniku niżej)
check rx-stage     1 "X-PRIV"            # staging RW->R-X: RWX ominięty, X-PRIV łapie
check hdr-corrupt  1 "X-PRIV"            # e_type spoza zakresu i brak tablicy segmentów: HDR głuchy (kontrola)
check hdr-wiped    1 "HDR,X-PRIV"        # sygnatura wyzerowana, tablica segmentów została: HDR po tablicy
check hdr-offset   1 "HDR,X-PRIV"        # nagłówek w środku strony: HDR szuka pod dowolnym przesunięciem
# red team: pokrycie detektorów
check delexec      1 "DEL-EXEC"
# zmiana kodu biblioteki: jeden bajt zmieniony w pamięci daje IMG-MOD po porównaniu z plikiem;
# kontrola: ta sama strona zapisana tą samą treścią (prywatna kopia bez zmiany) nie daje znaleziska
check patch        1 "IMG-MOD"
check touch        0 ""
check execstack    1 "RWX,X-PRIV"
# red team: wstrzyknięcie do warstwy LLM przez metadane
check inject-memfd 1 "ENT-X,MEMFD"
check inject-path  1 "DEL-EXEC"

# Próbki dynamiczne (pod przyszły --watch): skan w każdej zgłoszonej fazie; fazy czytane na bieżąco
# z wyjścia próbki, a skan wykonuje się w stabilnym oknie między wpisami.
phase_want() { case "$1:$2" in
  churn:quiet|churn:stage-rw|churn:cleanup|sleepmask:masked) echo "";;
  churn:stage-rx|sleepmask:armed) echo "X-PRIV";;
  churn:hdr) echo "HDR,X-PRIV";;
  churn:armed-rwx) echo "HDR,RWX,X-PRIV";;
  *) echo "?";;
esac }
check_phases() { # tryb, interwał s, czas s, wymagane fazy (rozdzielone spacją)
  mode=$1; interval=$2; total=$3; need=$4
  $S "$mode" "$interval" "$total" > "$OUT/$mode.out" 2> "$OUT/$mode.err" &
  spid=$!
  i=0; while [ $i -lt 50 ] && ! grep -q '^ready ' "$OUT/$mode.out" 2>/dev/null; do sleep 0.1; i=$((i+1)); done
  pid=$(awk '/^ready/{print $2; exit}' "$OUT/$mode.out")
  res=OK; seen=""; got=""; detail=""; drained=""
  deadline=$(( $(date +%s) + total + 15 ))
  while { kill -0 "$spid" 2>/dev/null || [ -z "$drained" ]; } && [ "$(date +%s)" -lt "$deadline" ]; do
    line=$(grep "^$mode " "$OUT/$mode.out" 2>/dev/null | tail -n 1)
    if [ -n "$line" ] && [ "$line" != "$seen" ]; then
      seen=$line; phase=${line##* }
      # fazy sprawdzają tylko tagi; bez skrótów i kontekstu skan mieści się w oknie między fazami
      $N scan --pid "$pid" --no-hashes --no-context --json "$OUT/$mode.last.json" 2>/dev/null
      tags=$(grep -o '"tag": "[A-Z-]*"' "$OUT/$mode.last.json" | cut -d'"' -f4 | sort -u | paste -sd, -)
      want=$(phase_want "$mode" "$phase")
      [ "$want" = "?" ] || want=$(union "$want" "$BASE")
      one=ok; [ "$tags" = "$want" ] || { one="FAIL[$tags]"; res=FAIL; fail=1; }
      got="$got $phase"; detail="$detail $phase:$one"
    fi
    kill -0 "$spid" 2>/dev/null || drained=1
    sleep 0.2
  done
  kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  for ph in $need; do case " $got " in *" $ph "*) ;; *) res=FAIL; fail=1;; esac; done
  echo "$mode: $res (fazy:$detail)"
}
check_phases churn     1 14 "quiet stage-rw stage-rx hdr armed-rwx cleanup"
check_phases sleepmask 1 8  "armed masked"
$S all 60 > "$OUT/all.pid" & sleep 0.5
$N scan --all --json "$OUT/all.json" > /dev/null 2> "$OUT/all.txt"; rc=$?; cat "$OUT/all.txt"
if [ "$rc" = 1 ]; then echo "scan --all: OK kod=1"; else echo "scan --all: FAIL kod=$rc (oczek. 1)"; fail=1; fi
$N scan --pid 999999 >/dev/null 2>&1; rc=$?
if [ "$rc" = 2 ]; then echo "nieistniejący pid: OK kod=2"; else echo "nieistniejący pid: FAIL kod=$rc (oczek. 2)"; fail=1; fi

# Asercje red team poza zestawem tagów.
# 1. rwx-lowent: region ładunku ma wynik 60 (RWX+X-PRIV), a nie 90 jak przy rwx: ENT-X nie odpalił.
grep -q '"score": 90' "$OUT/rwx.json" && res=OK || { res=FAIL; fail=1; }
grep -q 'różni się od pliku na dysku: 1 bajtów' "$OUT/patch.json" && r2=OK || { r2=FAIL; fail=1; }
echo "patch: dokładnie jeden bajt różny od pliku: $r2"
echo "rwx kontrola wyniku 90: $res"
if grep -q '"score": 90' "$OUT/rwx-lowent.json" || ! grep -q '"score": 60' "$OUT/rwx-lowent.json"; then
  res=FAIL; fail=1; else res=OK; fi
echo "rwx-lowent wynik 60 bez ENT-X: $res"
# 2. Wstrzyknięcia (pamięć, nazwa memfd, nazwa usuniętego pliku): tekst instrukcji nie może
#    trafić do ładunku dla modelu, a znacznik instruction_like_text_detected musi być podniesiony.
for m in inject inject-memfd inject-path; do
  $N explain "$OUT/$m.json" --dry-run > "$OUT/$m.dry.json" 2> "$OUT/$m.dry.txt"
  a=OK; grep -qi 'ignore previous' "$OUT/$m.dry.json" && { a=FAIL; fail=1; }
  b=OK; grep -q 'instruction_like_text_detected": true' "$OUT/$m.dry.json" || { b=FAIL; fail=1; }
  echo "$m dry-run: instrukcja-odcięta=$a znacznik=$b"
done
# 3. Raport: Markdown i PDF z wyniku skanu; kontrola: wynik bez znalezisk nie ma sekcji procesu.
$N report "$OUT/rwx.json" --no-llm --md "$OUT/rwx.report.md" --pdf "$OUT/rwx.report.pdf" 2>/dev/null
$N report "$OUT/data-noise.json" --no-llm --md "$OUT/clean.report.md" --pdf "$OUT/clean.report.pdf" 2>/dev/null
res=OK
[ "$(head -c 5 "$OUT/rwx.report.pdf")" = "%PDF-" ] || res=FAIL
grep -q 'RWX, X-PRIV, ENT-X' "$OUT/rwx.report.md" || res=FAIL
grep -Eq '^## [0-9]+\. Proces ' "$OUT/rwx.report.md" || res=FAIL
grep -Eq '^## [0-9]+\. Proces ' "$OUT/clean.report.md" && res=FAIL
grep -q 'Brak znalezisk od poziomu' "$OUT/clean.report.md" || res=FAIL
[ $res = OK ] || fail=1
echo "raport md+pdf: $res"
# 4. Kontekst systemowy: próbka ctx zostawia ślady poza pamięcią; skan ma je zebrać, a raport pokazać.
#    Kontrole: proces bez znalezisk (clean) i skan z --no-context nie mają kontekstu ani mapy.
check ctx 1 "ENT-X,HDR,MEMFD,RWX,X-PRIV"
$S ctx 60 > "$OUT/ctx.pid" & sleep 0.7
pid=$(awk '{print $2}' "$OUT/ctx.pid")
$N scan --pid "$pid" --json "$OUT/ctx.json" 2>/dev/null
$N scan --pid "$pid" --no-context --json "$OUT/ctx.noctx.json" 2>/dev/null
$N report "$OUT/ctx.json" --no-llm --md "$OUT/ctx.report.md" --pdf "$OUT/ctx.report.pdf" 2>/dev/null
# wersja angielska: skan i raport z --lang en; raport polski z angielskiego skanu ma o tym uprzedzić
$N --lang en scan --pid "$pid" --json "$OUT/ctx.en.json" 2>/dev/null
$N report "$OUT/ctx.en.json" --no-llm --md "$OUT/ctx.en.report.md" --pdf "$OUT/ctx.en.report.pdf" 2>/dev/null
$N --lang pl report "$OUT/ctx.en.json" --no-llm --md "$OUT/ctx.mixed.report.md" --pdf "$OUT/ctx.mixed.report.pdf" 2>/dev/null
kill "$pid" 2>/dev/null
res=OK
for want in '"state": "LISTEN"' '"state": "ESTABLISHED"' "ns-ctx-$pid.dat" "ns-ctx-$pid.gone" '"deleted": true' '"ancestors"' '"sha256"' '"layout"' "\"cmdline\": \"$S ctx 60\"" "\"cmdline\": \"$S clean 600\""; do
  grep -q -- "$want" "$OUT/ctx.json" || { res=FAIL; echo "  brak w wyniku: $want"; }
done
for want in 'Podsumowanie dla decydenta' 'Priorytet weryfikacji' 'Podstawa techniczna' 'MITRE ATT' 'Jak czytać ten raport' '^### Co to za program' 'Program testowy narzędzia Nanshe' '^### Co oznaczają znaleziska w tym procesie' 'Łagodne wyjaśnienie' '^#### Jak sprawdzić ten region' "gdb -p $pid -batch" 'Słowniczek' '^### Drzewo procesów' '(badany proces)' 'clean 600' '^### Sieć' 'LISTEN' 'ESTABLISHED' '127.0.0.1' '^### Otwarte pliki i uchwyty' 'usunięty z dysku' 'katalog tymczasowy' \
    '^### Pliki zmapowane do pamięci' 'memfd:payload' '^### Mapa przestrzeni adresowej' 'ZNALEZISKO (wysokie)' 'Sąsiad poniżej' '^#### Profil entropii regionu' '^#### Podgląd bajtów od 0x' 'LoadLibraryA' 'SHA-256'; do
  grep -q -- "$want" "$OUT/ctx.report.md" || { res=FAIL; echo "  brak w raporcie: $want"; }
done
grep -q '"context"\|"layout"' "$OUT/ctx.noctx.json" && { res=FAIL; echo "  --no-context: kontekst mimo flagi"; }
grep -q '"context"\|"layout"' "$OUT/clean.json" && { res=FAIL; echo "  clean: kontekst dla procesu bez znalezisk"; }
[ "$(head -c 5 "$OUT/ctx.report.pdf")" = "%PDF-" ] || res=FAIL
[ $res = OK ] || fail=1
echo "kontekst systemowy i diagramy: $res"
# 5. Wersja angielska: te same części raportu po angielsku i żadnego polskiego tekstu w wyniku ani w raporcie.
res=OK
grep -q '"lang": "en"' "$OUT/ctx.en.json" || { res=FAIL; echo "  brak pola lang w wyniku"; }
for want in 'Executive summary' 'Verification priority' 'Technical basis' 'MITRE ATT' 'How to read this report' '^### What this program is' '^### What the findings mean in this process' 'Benign explanation' \
    '^#### How to verify this region' "gdb -p $pid -batch" 'Glossary' '^### Process tree' '(examined process)' '^### Network' '^### Open files and handles' '^### Files mapped into memory' '^### Address space map' \
    'FINDING (high)' 'Neighbour below' '^#### Region entropy profile' '^#### Byte preview from 0x' '^#### What the process attributes mean' 'effective capabilities' '^### From memory to network' 'What this report does not cover'; do
  grep -q -- "$want" "$OUT/ctx.en.report.md" || { res=FAIL; echo "  brak w raporcie angielskim: $want"; }
done
for f in ctx.en.json ctx.en.report.md; do
  if grep -n -F -e ą -e ć -e ę -e ł -e ń -e ó -e ś -e ź -e ż -e Ł -e Ś -e Ż -e „ "$OUT/$f" | head -5 | grep .; then res=FAIL; echo "  polski tekst w $f"; fi
done
grep -q 'different language' "$OUT/ctx.en.report.md" && { res=FAIL; echo "  uwaga o językach w raporcie jednojęzycznym"; }
grep -q 'Skan wykonano w innym języku' "$OUT/ctx.mixed.report.md" || { res=FAIL; echo "  brak uwagi o językach w raporcie mieszanym"; }
grep -q 'Podsumowanie dla decydenta' "$OUT/ctx.mixed.report.md" || { res=FAIL; echo "  raport z --lang pl nie jest po polsku"; }
[ "$(head -c 5 "$OUT/ctx.en.report.pdf")" = "%PDF-" ] || res=FAIL
[ $res = OK ] || fail=1
echo "wersja angielska: $res"
# 6. Raport różnicowy: dwa skany tego samego procesu nie dają nowych regionów (kontrola), a porównanie
#    wyniku jednej próbki z wynikiem innej pokazuje proces, który zniknął, i nowy proces ze znaleziskami.
res=OK
$N diff "$OUT/rwx.json" "$OUT/rwx.2.json" --md "$OUT/same.diff.md" --pdf "$OUT/same.diff.pdf" 2>/dev/null || res=FAIL
$N diff "$OUT/rwx.json" "$OUT/elf.json" --md "$OUT/two.diff.md" --pdf "$OUT/two.diff.pdf" 2>/dev/null || res=FAIL
$N --lang en diff "$OUT/rwx.json" "$OUT/elf.json" --md "$OUT/two.en.diff.md" --pdf "$OUT/two.en.diff.pdf" 2>/dev/null || res=FAIL
grep -q '^# Nanshe: raport różnicowy' "$OUT/same.diff.md" || { res=FAIL; echo "  brak tytułu"; }
grep -q '| Nowe regiony w działających procesach | 0 |' "$OUT/same.diff.md" || { res=FAIL; echo "  ten sam proces: nowe regiony"; }
grep -q '| Nowe procesy ze znaleziskami | 0 ' "$OUT/same.diff.md" || { res=FAIL; echo "  ten sam proces: nowy proces"; }
grep -q 'NOWY' "$OUT/same.diff.md" && { res=FAIL; echo "  ten sam proces: wiersz NOWY"; }
grep -q '| Nowe procesy ze znaleziskami | 1 ' "$OUT/two.diff.md" || { res=FAIL; echo "  różne procesy: brak nowego procesu"; }
grep -q '| Procesy ze znaleziskami, które zniknęły | 1 ' "$OUT/two.diff.md" || { res=FAIL; echo "  różne procesy: brak procesu, który zniknął"; }
grep -q 'HDR' "$OUT/two.diff.md" || { res=FAIL; echo "  różne procesy: brak tagów nowego procesu"; }
grep -q '^# Nanshe: differential report' "$OUT/two.en.diff.md" || { res=FAIL; echo "  brak wersji angielskiej"; }
[ "$(head -c 5 "$OUT/two.diff.pdf")" = "%PDF-" ] || res=FAIL
[ $res = OK ] || fail=1
echo "raport różnicowy: $res"
# 7. Zrzut pamięci procesu: plik core próbki (gcore z pakietu gdb) daje te same tagi co skan na żywo,
#    zrzut próbki bez znalezisk nie daje żadnych (kontrola), a raport mówi, że źródłem jest zrzut.
if command -v gcore >/dev/null 2>&1; then
  res=OK
  for pair in "ctx:1:ENT-X,HDR,MEMFD,RWX,X-PRIV" "clean:0:"; do
    mode=${pair%%:*}; rest=${pair#*:}; want_rc=${rest%%:*}; want=$(union "${rest#*:}" "$BASE")
    $S "$mode" 60 > "$OUT/dump-$mode.pid" & sleep 0.7
    pid=$(awk '{print $2}' "$OUT/dump-$mode.pid")
    rm -f "$OUT/core-$mode".*
    gcore -o "$OUT/core-$mode" "$pid" >/dev/null 2>&1
    kill "$pid" 2>/dev/null
    $N scan "$OUT/core-$mode.$pid" --json "$OUT/dump-$mode.json" >/dev/null 2>"$OUT/dump-$mode.txt"; rc=$?
    tags=$(grep -o '"tag": "[A-Z-]*"' "$OUT/dump-$mode.json" | cut -d'"' -f4 | sort -u | paste -sd, -)
    { [ "$rc" = "$want_rc" ] && [ "$tags" = "$want" ]; } || { res=FAIL; echo "  zrzut $mode: kod=$rc (oczek. $want_rc) tagi=[$tags] (oczek. [$want])"; regions "$OUT/dump-$mode.txt" "zrzut-$mode"; }
    grep -q '"source_type": "dump"' "$OUT/dump-$mode.json" || { res=FAIL; echo "  zrzut $mode: brak source_type dump"; }
    rm -f "$OUT/core-$mode.$pid"
  done
  $N report "$OUT/dump-ctx.json" --no-llm --md "$OUT/dump.report.md" --pdf "$OUT/dump.report.pdf" 2>/dev/null
  grep -q 'zrzut pamięci procesu' "$OUT/dump.report.md" || { res=FAIL; echo "  raport nie mówi o zrzucie"; }
  grep -q '^### Sieć' "$OUT/dump.report.md" && { res=FAIL; echo "  raport ze zrzutu ma sekcję sieci"; }
  grep -q 'memfd:payload' "$OUT/dump.report.md" || { res=FAIL; echo "  raport ze zrzutu bez nazwy pliku memfd"; }
  printf 'to nie jest zrzut' > "$OUT/not-a-dump"
  $N scan "$OUT/not-a-dump" >/dev/null 2>&1; [ $? = 2 ] || { res=FAIL; echo "  plik niebędący zrzutem: kod inny niż 2"; }
  [ $res = OK ] || fail=1
  echo "zrzut pamięci procesu (core): $res"
else
  echo "zrzut pamięci procesu (core): POMINIĘTE (brak gcore; zainstaluj pakiet gdb)"
fi
exit $fail
