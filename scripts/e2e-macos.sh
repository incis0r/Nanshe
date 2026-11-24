#!/bin/sh
# Testy end-to-end na macOS: próbki syntetyczne skanowane przez prawdziwy backend.
# Użycie: scripts/e2e-macos.sh [katalog wyników]
# Bez roota: kopia binarium jest podpisywana lokalnie (adhoc) z uprawnieniem debugera, co pozwala czytać
# pamięć procesów tego samego użytkownika, które nie są chronione przez system. Oryginał nie jest zmieniany.
set -u
cd "$(dirname "$0")/.."
OUT="${1:-${TMPDIR:-/tmp}/nanshe-e2e-macos}"
mkdir -p "$OUT"
cargo build -q -p nanshe-cli -p nanshe-samples || exit 1
BIN="${CARGO_TARGET_DIR:-target}/debug"
N="$OUT/nanshe"; S="$BIN/nanshe-sample"
cp "$BIN/nanshe" "$N" && codesign -f -s - --entitlements packaging/macos/debugger.entitlements "$N" 2>/dev/null || { echo "podpis z uprawnieniem debugera nie powiódł się"; exit 1; }
fail=0
check() { # tryb próbki, oczekiwany kod, oczekiwane tagi (posortowane, po przecinku)
  mode=$1; want_rc=$2; want_tags=$3
  "$S" "$mode" 30 > "$OUT/$mode.pid" 2>&1 & spid=$!
  sleep 0.7
  "$N" scan --pid "$spid" --json "$OUT/$mode.json" > /dev/null 2> "$OUT/$mode.txt"; rc=$?
  "$N" scan --pid "$spid" --json "$OUT/$mode.2.json" > /dev/null 2>&1
  tags=$(grep -o '"tag": "[A-Z-]*"' "$OUT/$mode.json" 2>/dev/null | cut -d'"' -f4 | sort -u | paste -sd, -)
  # powtarzalność znalezisk: mapa procesu zmienia się między skanami o pojedyncze regiony (alokator), więc
  # porównujemy identyfikatory znalezisk, a nie cały wynik
  a=$(grep '"id": ' "$OUT/$mode.json" 2>/dev/null | shasum -a 256); b=$(grep '"id": ' "$OUT/$mode.2.json" 2>/dev/null | shasum -a 256)
  det=ok; [ "$a" = "$b" ] || det=ROZNE
  res=OK; { [ "$rc" = "$want_rc" ] && [ "$tags" = "$want_tags" ] && [ $det = ok ]; } || { res=FAIL; fail=1; }
  printf '%-10s %-4s kod=%s (oczek. %s) tagi=[%s] (oczek. [%s]) powtarzalnosc-znalezisk=%s\n' "$mode" "$res" "$rc" "$want_rc" "$tags" "$want_tags" "$det"
  [ $res = OK ] || { grep -E '^  0x' "$OUT/$mode.txt" | sed "s/^ */FAIL-REGION $mode: /" | cut -c1-200; tail -1 "$OUT/$mode.txt" | cut -c1-200; }
  { kill "$spid"; wait "$spid"; } 2>/dev/null
}
check clean      0 ""                 # program bez niczego: biblioteki systemowe nie dają znalezisk
check data-noise 0 ""                 # wysoka entropia w danych to nie znalezisko
check rx-stage   1 "ENT-X,X-PRIV"     # ładunek zapisany, potem przełączony na wykonywalny
check rx-lowent  1 "X-PRIV"           # to samo bez wysokiej entropii
check shc        1 "SHC,X-PRIV"       # kod o niskiej entropii z bezpośrednim wywołaniem jądra
check macho      1 "ENT-X,HDR,X-PRIV" # nagłówek Mach-O w pamięci bez pliku
check jit        1 "RWX,X-PRIV"       # region kompilatora JIT: jedyna pamięć RWX na Apple Silicon
check all        1 "ENT-X,HDR,X-PRIV"

# Program z utwardzonym środowiskiem i uprawnieniem allow-jit (jak przeglądarka): system sam zezwala mu na region
# JIT, więc waga jest obniżona i proces nie przekracza progu. Ta sama próbka bez takiego podpisu (wyżej) go przekracza.
SJ="$OUT/nanshe-sample-jit"
cp "$S" "$SJ" && codesign -f -s - --options runtime --entitlements packaging/macos/sample-jit.entitlements "$SJ" 2>/dev/null
"$SJ" jit 30 > /dev/null 2>&1 & spid=$!; sleep 0.7
"$N" scan --pid "$spid" --min info --json "$OUT/jit-allowed.json" > /dev/null 2> "$OUT/jit-allowed.txt"
"$N" scan --pid "$spid" --json /dev/null > /dev/null 2>&1; rc=$?
{ kill "$spid"; wait "$spid"; } 2>/dev/null
res=OK
[ "$rc" = 0 ] || { res=FAIL; echo "  kod=$rc (oczek. 0)"; }
grep -q '"allowlisted": "jit:macos-allow-jit"' "$OUT/jit-allowed.json" || { res=FAIL; echo "  brak dowodu allow-jit w wyniku"; tail -2 "$OUT/jit-allowed.txt" | cut -c1-200; }
grep -q '"tag": "RWX"' "$OUT/jit-allowed.json" || { res=FAIL; echo "  region RWX nie został odnotowany"; }
[ $res = OK ] || fail=1
echo "region JIT z uprawnieniem systemu (obnizona waga): $res"
# kontekst procesu: rodzic, wiersz poleceń, podpis kodu
res=OK
"$S" rx-stage 30 > /dev/null 2>&1 & spid=$!; sleep 0.7
"$N" scan --pid "$spid" --json "$OUT/ctx.json" > /dev/null 2>&1
{ kill "$spid"; wait "$spid"; } 2>/dev/null
for want in '"ppid"' '"cmdline": ".*nanshe-sample rx-stage 30"' '"started"' '"threads"' 'podpis kodu' 'bez utwardzonego' '"ancestors"' '"host_info"' '"os": "macOS '; do
  grep -q -- "$want" "$OUT/ctx.json" || { res=FAIL; echo "  brak w kontekście: $want"; }
done
[ $res = OK ] || fail=1
echo "kontekst procesu i podpis kodu: $res"

# proces chroniony przez system: odmowa dostępu z czytelnym komunikatem, kod 2
"$N" scan --pid 1 --json "$OUT/launchd.json" > /dev/null 2> "$OUT/launchd.txt"; rc=$?
res=OK; { [ $rc = 2 ] && grep -q "SIP" "$OUT/launchd.txt"; } || { res=FAIL; fail=1; }
echo "proces chroniony (launchd): $res kod=$rc"
# nieistniejący proces
"$N" scan --pid 99999999 > /dev/null 2> "$OUT/none.txt"; rc=$?
res=OK; [ $rc = 2 ] || { res=FAIL; fail=1; }
echo "nieistniejacy pid: $res kod=$rc"
# raport po polsku i po angielsku z wyniku macOS, z krokami sprawdzenia dla tego systemu
res=OK
"$S" macho 30 > /dev/null 2>&1 & spid=$!; sleep 0.7
"$N" scan --pid "$spid" --json "$OUT/rep.json" > /dev/null 2>&1
"$N" --lang en scan --pid "$spid" --json "$OUT/rep.en.json" > /dev/null 2>&1
{ kill "$spid"; wait "$spid"; } 2>/dev/null
"$N" report "$OUT/rep.json" --no-llm --md "$OUT/rep.md" --pdf "$OUT/rep.pdf" 2>/dev/null || res=FAIL
"$N" --lang en report "$OUT/rep.en.json" --no-llm --md "$OUT/rep.en.md" --pdf "$OUT/rep.en.pdf" 2>/dev/null || res=FAIL
for want in "vmmap $spid" 'codesign -dv' 'Mach-O' 'Jak sprawdzić ten region'; do grep -q -- "$want" "$OUT/rep.md" || { res=FAIL; echo "  brak w raporcie: $want"; }; done
for want in "vmmap $spid" 'How to verify this region' 'Executive summary'; do grep -q -- "$want" "$OUT/rep.en.md" || { res=FAIL; echo "  brak w raporcie angielskim: $want"; }; done
if grep -n -F -e ą -e ć -e ę -e ł -e ń -e ó -e ś -e ź -e ż "$OUT/rep.en.md" | head -3 | grep .; then res=FAIL; echo "  polski tekst w raporcie angielskim"; fi
[ "$(head -c 5 "$OUT/rep.pdf")" = "%PDF-" ] || res=FAIL
[ $res = OK ] || fail=1
echo "raport md+pdf (pl, en): $res"
# skan wszystkich procesów: kończy się, a procesy niedostępne są policzone, nie pominięte
"$N" scan --all --no-hashes --json "$OUT/all.json" > /dev/null 2> "$OUT/all.txt"; rc=$?
res=OK; { [ $rc = 0 ] || [ $rc = 1 ] || [ $rc = 3 ]; } && grep -q '"processes"' "$OUT/all.json" || { res=FAIL; fail=1; }
echo "skan wszystkich procesow: $res kod=$rc"
exit $fail
