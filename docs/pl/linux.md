# Nanshe na Linuksie

Wersja angielska: [../linux.md](../linux.md).

Stan: obsługiwany. Testy jednostkowe i end-to-end sprawdzone na aarch64 w kontenerze Debian 12 (`rust:1-slim-bookworm`). Pełne skany na żywo (`nanshe scan --all` jako root, binarium statyczne) wykonano 2026-11-23 na 20 hostach jednego labu (19 x86_64, 1 arm64); przebiegu zestawu testów end-to-end na x86_64 ta dokumentacja nie odnotowuje.

Działającego gościa Windows na hoście KVM/QEMU można przeskanować z tego hosta Linux: patrz [hiperwizor.md](hiperwizor.md).

## Build

Na stacji bez Rusta build idzie w kontenerze (podman):

```sh
scripts/dev.sh cargo build --release -p nanshe-cli                 # bez kodu sieciowego
scripts/dev.sh cargo build --release -p nanshe-cli --features llm  # z warstwą LLM
```

Na hoście z Rustem (stabilny, edycja 2021) te same polecenia `cargo` bez `scripts/dev.sh`. Binarium: `target/release/nanshe`. Nie ma zależności od bibliotek systemowych poza libc; czcionka raportu PDF jest wbudowana.

Dwa dodatkowe skrypty budujące:

```sh
scripts/dev.sh sh scripts/build-linux-static.sh   # statyczne binaria musl dla x86_64 i aarch64 (cechy domyślne), w dist/linux
scripts/build-linux-vm.sh                         # binarium x86_64 z cechą vm (glibc 2.31 lub nowsza), patrz hiperwizor.md
```

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

Wątki jądra są pomijane na liście procesów `scan --all`: nie mają pamięci użytkownika. Są rozpoznawane po fladze `PF_KTHREAD` w `/proc/<pid>/stat`, a nie po nazwie, więc proces, który tylko nazywa się jak wątek jądra, jest skanowany normalnie.

## Detektory działające na Linuksie

| Tag | Punkty | Warunek |
|---|---|---|
| `RWX` | 30 | region zapisywalny i wykonywalny |
| `X-PRIV` | 30 | wykonywalna pamięć anonimowa (bez pliku), poza regionami jądra (`[vdso]` itp.) |
| `MEMFD` | 40/10 | wykonywalne mapowanie `memfd:`; 10 dla `memfd:libffi` w procesie, który ma zmapowaną systemową bibliotekę `libffi` (patrz „Obniżone wagi") |
| `DEL-EXEC` | 30/10 | wykonywalne mapowanie pliku usuniętego z dysku; 10 dla pliku usuniętego z katalogu pakietów (patrz „Obniżone wagi") |
| `X-TMP` | 30 | wykonywalne mapowanie istniejącego pliku z `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/`, `/run/user/`, `/var/lock/`, `/run/lock/` albo `/dev/mqueue/` |
| `ENT-X` | 20/30 | wysoka entropia w regionie wykonywalnym; 10, gdy to pojedyncze strony w zwykłym kodzie z pliku |
| `HDR` | 40/10 | nagłówek ELF/PE/Mach-O w regionie bez pliku: na początku strony w każdym regionie, a w regionach wykonywalnych także pod dowolnym przesunięciem (ELF, PE); w regionach wykonywalnych także nagłówek z wymazaną sygnaturą, rozpoznawany po tablicy nagłówków programu ELF albo tablicy sekcji PE; 10 w pamięci gościa procesu QEMU (patrz „Obniżone wagi") |
| `THR-PRIV` | 40 | wątek czekający w wywołaniu systemowym, którego instrukcja wywołania leży w pamięci bez pliku (poza regionami jądra) |
| `IMG-MOD` | 40 | wykonywalne, niezapisywalne mapowanie pliku ma strony zmienione w pamięci (pole `Anonymous` w `smaps` większe od zera), których treść różni się od pliku albo nie dała się z nim porównać |
| `SHC` | 40/20/10 | wzorce kodu typowe dla shellcode'u w pamięci wykonywalnej, która nie pochodzi z pliku na dysku (pamięć anonimowa, `memfd`): ustalanie własnego adresu, bezpośrednie wywołanie jądra, prolog znanych etapów ładujących, na Windows także odczyt PEB, pętla skrótów nazw funkcji i kopia wejścia do jądra poza `ntdll`. 40 za dwie klasy albo jedną mocną, 20 za pojedynczą słabszą (sama nie przekracza progu), 10 za samą kopię wejścia do jądra w przeglądarce opartej na Chromium (robi to jej piaskownica). Bez obniżki dla środowisk JIT |

`X-MAP` i `GUARD-X` dotyczą tylko Windows.

`THR-PRIV` i `IMG-MOD` nie podlegają obniżce dla środowisk JIT. `THR-PRIV` czyta `/proc/<pid>/task/<tid>/syscall`: wątek, który w chwili skanu coś liczył (nie czekał w jądrze), nie jest oceniany. `IMG-MOD` porównuje zmienione strony ze zmapowanym plikiem (otwieranym przez `/proc/<pid>/map_files`) i podaje liczbę różniących się bajtów oraz adres pierwszego; prywatna kopia o niezmienionej treści nie jest zgłaszana. Gdy treści nie dało się porównać, znalezisko to mówi.

### Obniżone wagi

Wprowadzone po pełnych skanach 20 hostów Linux jednego labu (2026-11-23). Każda reguła obniża jedną zmierzoną łagodną klasę do 10 punktów („info"), zostawia znalezisko widoczne z opisem, który podaje powód, i ma test jednostkowy z kontrolami, w których pełna waga zostaje. Znalezisko obniżone w ten sposób samo nie daje procesowi priorytetu P1.

| Tag | Obniżone do 10, gdy | Pełna waga zostaje, gdy |
|---|---|---|
| `DEL-EXEC` | usunięty plik leżał w `/usr/`, `/lib/`, `/lib64/`, `/opt/`, `/bin/`, `/sbin/` albo `/snap/`, a plik programu procesu jest potwierdzony (należy do roota, nie jest zapisywalny dla grupy ani innych, jest tym samym plikiem, który widzi skaner) i nie jest usunięty. Opis: zwykle biblioteka zaktualizowana na dysku, proces używa starej wersji do restartu | plik leżał gdzie indziej (na przykład `/tmp`, katalog domowy, `/var/lib`), ścieżka zawiera `/../` albo plik programu nie jest potwierdzony (na przykład proces w kontenerze, który ma własne `/usr`) lub sam jest usunięty |
| `HDR` | nagłówek leży w niewykonywalnym regionie o rozmiarze co najmniej 16 MiB w procesie, którego potwierdzony plik programu w katalogu systemowym to `qemu-system-*` albo `qemu-kvm`. Opis: najpewniej pamięć maszyny wirtualnej. Jeden wpis na region | region wykonywalny, mniejszy region, inne programy, w tym inne narzędzia QEMU (`qemu-img`) |
| `MEMFD` | mapowanie nazywa się `memfd:libffi`, a proces ma potwierdzony plik programu w katalogu systemowym i zmapowaną `libffi.so*` z `/usr/lib/`, `/usr/lib64/`, `/lib/` albo `/lib64/`, a region wygląda jak tablica skoków libffi: najwyżej 64 KiB, niezapisywalny, o niskiej entropii | każda inna nazwa, proces bez systemowej `libffi`, niepotwierdzony plik programu, region większy, zapisywalny albo gęsty |

Nazwę mapowania i ścieżki wybiera sam proces, dlatego każda reguła wymaga dodatkowo potwierdzonego pliku programu. Plik programu jest potwierdzony tylko dla procesu w tej samej przestrzeni nazw użytkowników co skaner: proces we własnej przestrzeni nazw może bez uprawnień zamontować swój katalog w miejscu ścieżki systemowej. Znane ryzyko, takie samo jak przy liście dozwolonych JIT: kod wstrzyknięty do procesu spełniającego warunki dziedziczy obniżkę.

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

Obniża (dzieli przez 3) wagę `RWX`, `X-PRIV` i `ENT-X` dla znanych środowisk JIT: `node`, `java`, `dotnet`, `firefox`, `firefox-esr`, `chrome`, `chromium`, `msedge`, `brave`, `electron`, `code`, `pwsh`, `powershell`, `qemu-system-x86_64`, `luajit`, a od skanów 20 hostów Linux także `apache2`, `httpd`, `php`, `php-fpm`, `gjs`, `gjs-console`, `gnome-shell`, `gnome-terminal-server`, `python`, `uwsgi`. Nazwa pliku jest porównywana dokładnie oraz bez końcowego numeru wersji (`python3.14`, `php-fpm8.2`). Działa tylko, gdy plik programu wskazany przez jądro (`/proc/<pid>/exe`):

- nie jest usunięty,
- leży w `/usr/`, `/opt/`, `/bin/`, `/sbin/` albo `/snap/`,
- należy do roota i nie jest zapisywalny dla grupy ani innych,
- jest tym samym plikiem (urządzenie i i-węzeł), który widzi skaner.

Sama nazwa procesu niczego nie obniża.

## Znane ograniczenia i ślepe punkty

Każdy poniższy punkt ma próbkę w `tests/samples` i oczekiwanie w `scripts/e2e.sh`:

- **R-X z pliku poza katalogami tymczasowymi**: `X-TMP` obejmuje tylko listę katalogów zapisywalnych dla wszystkich (próbka `rx-file` w `/tmp` jest wykrywana). Ten sam ładunek z katalogu domowego albo `/run/user/` pozostaje niewidoczny.
- **Fałszywe alarmy `X-TMP`**: programy rozpakowujące biblioteki natywne do `/tmp` (np. JNI w Javie, PyInstaller, AppImage) dadzą wagę „podejrzane". Skali nie zmierzono; detektor nie jest objęty listą dozwolonych.
- **Nagłówek ELF z uszkodzonym polem i bez tablicy nagłówków programu** (`hdr-corrupt`): `HDR` nie reaguje, zostaje `X-PRIV`. Nagłówek z wymazaną sygnaturą, po którym została tablica nagłówków programu, jest wykrywany przez `HDR` w regionach wykonywalnych (`hdr-wiped`).
- **Nagłówek poza granicą strony w danych niewykonywalnych** (np. ładunek w buforze RW na stercie przed zmianą uprawnień): niewidoczny. To świadome ograniczenie: program ładujący trzyma na stosie kopię nagłówka każdej ładowanej biblioteki, więc szukanie pod dowolnym przesunięciem w danych dawało `HDR` w każdym procesie (sprawdzone na próbce `clean`). W regionach wykonywalnych nagłówek pod przesunięciem jest wykrywany (`hdr-offset`).
- **RWX o niskiej entropii** (`rwx-lowent`): 60 punktów zamiast 90, bez `ENT-X`.
- Proces z ponad 1 048 576 regionami: skanowane są pierwsze regiony do limitu, znaleziska zostają, a wynik procesu jest oznaczony jako niekompletny (wynik częściowy).
- Region większy niż `--max-region-mib` (domyślnie 64) jest czytany częściowo i tak oznaczony.
- Procesy w innej przestrzeni nazw montowania (kontenery): lista dozwolonych i obniżone wagi ich nie obejmują (plik programu nie jest tym samym plikiem dla skanera). To samo dotyczy procesu, którego plik programu został na dysku zastąpiony przez aktualizację.
- Zrzuty: zrzuty pojedynczych procesów (pliki core) analizuje `nanshe scan <plik-zrzutu>`, patrz [dokumentacja wersji](dokumentacja-0.1.0.md), rozdział 4; zrzutów pamięci fizycznej narzędzie nie analizuje.

## Warstwa LLM i raport

Wspólne dla wszystkich systemów: [README](../../README.pl.md) i [dokumentacja wersji](dokumentacja-0.1.0.md). Testy: [testy.md](testy.md).
