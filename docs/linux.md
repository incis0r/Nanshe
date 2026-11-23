# Nanshe na Linuksie

Stan: obsługiwany. Sprawdzony na aarch64 w kontenerze Debian 12 (`rust:1-slim-bookworm`). Linux x86_64: jeszcze niesprawdzony.

## Build

Na stacji bez Rusta build idzie w kontenerze (podman):

```sh
scripts/dev.sh cargo build --release -p nanshe-cli                 # bez kodu sieciowego
scripts/dev.sh cargo build --release -p nanshe-cli --features llm  # z warstwą LLM
```

Na hoście z Rustem (stabilny, edycja 2021) te same polecenia `cargo` bez `scripts/dev.sh`. Binarium: `target/release/nanshe`. Nie ma zależności od bibliotek systemowych poza libc; czcionka raportu PDF jest wbudowana.

## Uprawnienia

Skan czyta `/proc/<pid>/maps` i `/proc/<pid>/mem`. Wystarcza jedno z:

- root,
- `CAP_SYS_PTRACE`,
- ten sam użytkownik co cel i `kernel.yama.ptrace_scope=0`.

Wynik i raport podają uprawnienia skanera (root, `CAP_SYS_PTRACE`); skan bez pełnych uprawnień jest w raporcie oznaczony ostrzeżeniem na pierwszej stronie.

Bez uprawnień proces jest raportowany jako niedostępny, a wynik jako częściowy (kod wyjścia 3 przy `--all`, 2 przy `--pid`). W kontenerze potrzebne `--cap-add SYS_PTRACE` (robi to `scripts/dev.sh`).

Skaner niczego nie zatrzymuje i niczego nie zapisuje w celu: nie używa `ptrace(PTRACE_ATTACH)`.

## Użycie

```sh
nanshe ps
nanshe scan --pid 1234 --json wynik.json      # skrót na stderr, wynik w pliku
nanshe scan --all --min high                  # cały host, tylko waga "wysokie"
nanshe report wynik.json                      # wynik.report.md i wynik.report.pdf
nanshe explain wynik.json --url http://127.0.0.1:11434   # interpretacja LLM + raport
```

Kody wyjścia `scan`: 0 brak znalezisk od progu `--min`, 1 są znaleziska, 2 błąd, 3 wynik częściowy bez znalezisk.

## Detektory działające na Linuksie

| Tag | Punkty | Warunek |
|---|---|---|
| `RWX` | 30 | region zapisywalny i wykonywalny |
| `X-PRIV` | 30 | wykonywalna pamięć anonimowa (bez pliku), poza regionami jądra (`[vdso]` itp.) |
| `MEMFD` | 40 | wykonywalne mapowanie `memfd:` |
| `DEL-EXEC` | 30 | wykonywalne mapowanie pliku usuniętego z dysku |
| `X-TMP` | 30 | wykonywalne mapowanie istniejącego pliku z `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/`, `/run/user/`, `/var/lock/`, `/run/lock/` albo `/dev/mqueue/` |
| `ENT-X` | 20/30 | wysoka entropia w regionie wykonywalnym; 10, gdy to pojedyncze strony w zwykłym kodzie z pliku |
| `HDR` | 40 | nagłówek ELF/PE/Mach-O w regionie bez pliku: na początku strony w każdym regionie, a w regionach wykonywalnych także pod dowolnym przesunięciem (ELF, PE) |

| `THR-PRIV` | 40 | wątek czekający w wywołaniu systemowym, którego instrukcja wywołania leży w pamięci bez pliku (poza regionami jądra) |
| `IMG-MOD` | 40 | wykonywalne, niezapisywalne mapowanie pliku ma strony zmienione w pamięci (pole `Anonymous` w `smaps` większe od zera) |

`X-MAP` i `GUARD-X` dotyczą tylko Windows.

`THR-PRIV` i `IMG-MOD` nie podlegają obniżce dla środowisk JIT. `THR-PRIV` czyta `/proc/<pid>/task/<tid>/syscall`: wątek, który w chwili skanu coś liczył (nie czekał w jądrze), nie jest oceniany. `IMG-MOD` mówi, że kod zmieniono, ale nie pokazuje różnic ani dokładnej strony.

## Skróty SHA-256

Skan liczy skróty plików i zapisuje je w polu `files` wyniku (`--no-hashes` wyłącza):

- plik programu każdego procesu, czytany przez `/proc/<pid>/exe` (także usunięty z dysku),
- pliki zmapowane w procesach ze znaleziskami od wagi „podejrzane", czytane przez `/proc/<pid>/map_files/`, czyli faktycznie zmapowany plik, także usunięty albo `memfd`.

Odczyt `map_files` wymaga pełnych uprawnień roota. Bez nich (np. kontener z samym `CAP_SYS_PTRACE`) skaner otwiera plik po ścieżce i zapisuje w wyniku adnotację, że dla procesu w kontenerze może to być inny plik; plików `memfd` i usuniętych nie da się wtedy policzyć. Każdy region ze znaleziskiem ma dodatkowo skrót swojej zawartości (`sha256` w regionie). Limit pliku: 512 MiB.

## Kontekst systemowy

Dla procesu ze znaleziskiem od wagi „podejrzane" skan zbiera dodatkowo, wyłącznie odczytem `/proc`:

| Co | Skąd |
|---|---|
| rodzic, liczba wątków, czas startu | `/proc/<pid>/stat`, `btime` z `/proc/stat` |
| wiersz poleceń, katalog roboczy | `cmdline`, `cwd` |
| użytkownik | `Uid` ze `status`; nazwa wg `/etc/passwd` skanera |
| plik programu: rozmiar, czas zmiany, właściciel, tryb, SHA-256 | `/proc/<pid>/exe`, czyli faktycznie uruchomiony plik, także usunięty z dysku |
| cechy bezpieczeństwa | `TracerPid`, `CapEff`, `Seccomp`, `NoNewPrivs`, katalog główny inny niż `/`, zmienne `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` |
| przodkowie (do 16) i dzieci (do 50) | obraz `/proc` zrobiony raz na skan |
| otwarte deskryptory (do 200) | `/proc/<pid>/fd` |
| gniazda TCP/UDP (IPv4, IPv6) i uniksowe | `/proc/<pid>/net/*` dopasowane po i-węźle gniazda; tabele z przestrzeni nazw badanego procesu |
| pełna mapa regionów | `/proc/<pid>/maps` (ta sama, na której pracowały detektory) |

Reszta środowiska procesu nie jest zbierana. `nanshe scan --no-context` wyłącza cały kontekst i mapę.

Ograniczenia: to stan z chwili skanu (zamkniętych połączeń i zakończonych procesów nie widać); nazwa użytkownika procesu w kontenerze może pochodzić z innej bazy niż `/etc/passwd` skanera; czas startu zakłada 100 tyknięć zegara na sekundę; adresy IPv6 zakładają architekturę little-endian. Wiersz poleceń i ścieżki trafiają do wyniku bez filtrowania sekretów.

## Lista dozwolonych JIT

Obniża (dzieli przez 3) wagę `RWX`, `X-PRIV` i `ENT-X` dla znanych środowisk JIT. Działa tylko, gdy plik programu wskazany przez jądro (`/proc/<pid>/exe`):

- nie jest usunięty,
- leży w `/usr/`, `/opt/`, `/bin/`, `/sbin/` albo `/snap/`,
- należy do roota i nie jest zapisywalny dla grupy ani innych,
- jest tym samym plikiem (urządzenie i i-węzeł), który widzi skaner.

Sama nazwa procesu niczego nie obniża.

## Znane ograniczenia i ślepe punkty

Każdy poniższy punkt ma próbkę w `tests/samples` i oczekiwanie w `scripts/e2e.sh`:

- **R-X z pliku poza katalogami tymczasowymi**: `X-TMP` obejmuje tylko listę katalogów zapisywalnych dla wszystkich (próbka `rx-file` w `/tmp` jest wykrywana). Ten sam ładunek z katalogu domowego albo `/run/user/` pozostaje niewidoczny.
- **Fałszywe alarmy `X-TMP`**: programy rozpakowujące biblioteki natywne do `/tmp` (np. JNI w Javie, PyInstaller, AppImage) dadzą wagę „podejrzane". Skali nie zmierzono; detektor nie jest objęty listą dozwolonych.
- **Nagłówek ELF z uszkodzonym polem** (`hdr-corrupt`): `HDR` nie reaguje, zostaje `X-PRIV`. Wymazane sygnatury (stomping) to planowany detektor `HDR-STRIP`.
- **Nagłówek poza granicą strony w danych niewykonywalnych** (np. ładunek w buforze RW na stercie przed zmianą uprawnień): niewidoczny. To świadome ograniczenie: program ładujący trzyma na stosie kopię nagłówka każdej ładowanej biblioteki, więc szukanie pod dowolnym przesunięciem w danych dawało `HDR` w każdym procesie (sprawdzone na próbce `clean`). W regionach wykonywalnych nagłówek pod przesunięciem jest wykrywany (`hdr-offset`).
- **RWX o niskiej entropii** (`rwx-lowent`): 60 punktów zamiast 90, bez `ENT-X`.
- Proces z ponad 1 048 576 regionami: skanowane są pierwsze regiony do limitu, znaleziska zostają, a wynik procesu jest oznaczony jako niekompletny (wynik częściowy).
- Region większy niż `--max-region-mib` (domyślnie 64) jest czytany częściowo i tak oznaczony.
- Procesy w innej przestrzeni nazw montowania: lista dozwolonych ich nie obejmuje (plik programu nie jest tym samym plikiem dla skanera).
- Brak analizy zrzutów (etap M2).

## Warstwa LLM i raport

Wspólne dla wszystkich systemów: [README](../README.pl.md) i [dokumentacja wersji](dokumentacja-0.1.0.md). Testy: [testy.md](testy.md).
