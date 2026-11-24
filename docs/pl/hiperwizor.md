# Odczyt gościa Windows z hosta KVM

Wersja angielska: [../hypervisor.md](../hypervisor.md).

`nanshe vm` skanuje procesy działającej maszyny wirtualnej Windows z hosta Linux, który uruchamia ją pod KVM/QEMU. W gościu nic nie jest instalowane ani uruchamiane. Skaner czyta pamięć procesu QEMU na hoście, znajduje w niej jądro Windows i przechodzi tablice stron każdego procesu gościa. Detektory i raport są te same co przy skanie na żywo.

Stan: pierwsza wersja (zapowiedź 0.4). Zmierzona na razie na jednym gościu; patrz „Co zmierzono".

## Po co

- Skan z wnętrza Windows nie otworzy procesów chronionych (LSASS, procesy antywirusa, podstawowe procesy systemu), nawet jako SYSTEM. Z hosta to zwykła pamięć.
- W gościu nic nie działa, więc kod w gościu nie ma czego wykryć, zablokować ani podmienić w chwili skanu.
- Gość nie jest zatrzymywany i nic nie jest do niego zapisywane.

## Wymagania

- Host Linux z KVM/QEMU (libvirt albo samo QEMU), gość x86_64 z 64-bitowym Windows.
- Uprawnienia root na hoście (skaner czyta pamięć innego procesu).
- Build z cechą `vm`: `cargo build --release -p nanshe-cli --features vm`. Domyślne buildy nie zawierają tego kodu, a polecenie kończy się wtedy błędem, który to mówi. `scripts/build-linux-vm.sh` buduje takie binarium x86_64 w kontenerze (linkowane z glibc 2.31, wynik w `dist/linux/nanshe-vm-x86_64`).
- Plik symboli jądra (PDB) dla wersji Windows gościa; patrz „Symbole jądra".

## Użycie

```sh
# lista procesów gościa
sudo nanshe vm dc01 --ps --symbols ./symbols

# skan wszystkich procesów gościa i zapis wyniku
sudo nanshe vm dc01 --all --symbols ./symbols --json dc01.json
nanshe report dc01.json

# jeden proces
sudo nanshe vm dc01 --pid 812 --symbols ./symbols --json lsass.json
```

Celem jest nazwa gościa (wartość `guest=` argumentu `-name` QEMU, czyli nazwa domeny libvirt) albo PID procesu QEMU. Rozpoznawane są procesy `qemu-system-*` i `qemu-kvm` (rodzina RHEL). Gdy celem jest nazwa, proces jest przyjmowany tylko wtedy, gdy jego plik programu wskazany przez jądro (`/proc/<pid>/exe`, a nie nazwa, którą proces nadaje sobie sam) jest takim programem w `/usr/`, `/opt/`, `/bin/` albo `/sbin/`; gdy nie pasuje żaden proces albo pasuje więcej niż jeden, skan kończy się błędem.

| Opcja | Znaczenie |
|---|---|
| `--ps` | lista procesów gościa i koniec |
| `--pid N` | skan jednego procesu gościa (PID wewnątrz gościa) |
| `--all` | skan wszystkich procesów gościa |
| `--symbols <katalog>` | katalog z plikami symboli jądra |
| `--fetch-symbols` | zgoda na pobranie brakującego pliku symboli (jedyne użycie sieci) |
| `--json <plik>` | pełny wynik do pliku (`-` oznacza standardowe wyjście) |
| `--min info\|suspicious\|high` | próg wypisywania i kodu wyjścia (domyślnie `suspicious`) |
| `--no-bytes` | bez podglądu bajtów w wyniku |
| `--max-region-mib N` | limit odczytu jednego regionu (domyślnie 64) |

Wynik ma ten sam format co skan na żywo; pole `source_type` każdego procesu ma wartość `vm`.

## Symbole jądra

Skaner potrzebuje układu struktur jądra dla dokładnej wersji Windows gościa. Bierze go z pliku symboli jądra, szukanego w lokalnym katalogu o układzie `<plik.pdb>/<identyfikator>`, na przykład `symbols/ntkrnlmp.pdb/953A8DE880B0818C32DA2DEC1D79C2D91`.

- Domyślnie skaner **nie nawiązuje żadnego połączenia sieciowego**. Gdy pliku brakuje, kończy pracę z błędem, który to mówi. Bez `--fetch-symbols` adres serwera symboli jest zastępowany takim, którego klient HTTP nie potrafi użyć, więc nie ma nawet próby połączenia; sprawdza to test jednostkowy.
- `--fetch-symbols` pozwala pobrać brakujący plik z serwera symboli Microsoftu do katalogu symboli. To jedyny kod sieciowy tej funkcji; wysyłany jest wyłącznie identyfikator wersji jądra. Wystarczy uruchomić raz na maszynie z dostępem do sieci i skopiować katalog na host.
- Bez `--symbols` katalogiem jest katalog pamięci podręcznej użytkownika (`~/.cache/memflow`).
- Nazwa pliku symboli i identyfikator wersji są czytane z pamięci gościa i stają się częścią ścieżki pliku oraz adresu pobierania. Skaner przyjmuje tylko zwykłą nazwę `*.pdb` i identyfikator szesnastkowy; w przeciwnym razie się zatrzymuje.
- Gość wybierany po nazwie musi być procesem QEMU uruchomionym z konta systemowego (root albo konto usługi, np. `qemu`). Nazwę gościa ustawia ten, kto uruchamia QEMU, więc maszynę zwykłego użytkownika wskazuje się tylko numerem PID.

Po otwarciu gościa skaner sprawdza, czy lista procesów zawiera proces `System` o numerze 4. Jeśli nie, symbole nie pasują do jądra i skan się zatrzymuje, zamiast zwrócić pusty albo błędny wynik.

## Co wynik zawiera, a czego nie

| | Skan na żywo w Windows | Skan z hosta |
|---|---|---|
| Procesy chronione (LSASS, antywirus) | niedostępne | skanowane |
| Lista regionów | z menedżera pamięci (wszystkie regiony zarezerwowane i przydzielone) | z tablic stron: tylko strony obecne w pamięci fizycznej |
| Ochrona regionu | ustawiona przez proces | faktyczna, z tablic stron, łączona między poziomami tak jak w procesorze |
| Rodzaj regionu | prywatny, mapowany, obraz | obraz, jeśli leży w module procesu, w przeciwnym razie prywatny; nieznany, gdy listy modułów nie da się przeczytać |
| Pliki mapowane jako dane | znane, ze ścieżką | nieodróżnialne od pamięci prywatnej |
| Porównanie kodu z plikiem na dysku (`IMG-MOD`) | tak | nie (host nie widzi plików gościa) |
| Wątki, sieć, otwarte pliki, drzewo procesów | tak | nie |
| Obniżka wagi dla środowisk tworzących kod w locie | tak | nie (pliku programu nie da się sprawdzić z hosta) |

Skutki, o których warto wiedzieć przed lekturą raportu:

- **Stron wyrzuconych do pliku wymiany nie widać.** Region może być krótszy niż w skanie na żywo albo może go nie być.
- **Gość działa w trakcie skanu,** więc wynik nie jest spójną migawką.
- **`HDR` jest zgłaszany tylko w regionach wykonywalnych.** Pliki mapowane jako dane zaczynają się nagłówkiem obrazu i nie da się ich odróżnić od pamięci prywatnej; na zmierzonym gościu dawało to 466 takich regionów, zanim dodano tę regułę. Nagłówek w niewykonywalnej pamięci prywatnej nie jest więc w tym trybie zgłaszany.
- **Jedna strona za każdym modułem jest liczona jako jego część.** Windows Server 2025 mapuje tuż za każdym obrazem dodatkową stronę kodu. Zasięg modułu to rozmiar obrazu plus jedna strona, zaokrąglony w górę do granicy alokacji 64 KiB. Gdy obraz kończy się dokładnie na granicy 64 KiB, osobna jednostronicowa alokacja umieszczona tuż za nim nie zostanie odróżniona.
- **Procesy bez listy modułów** (`System`, `Secure System`, `Registry` oraz procesy, których dane programu ładującego są poza pamięcią) mają regiony o nieznanym rodzaju: kod bez pliku nie jest w nich wykrywany, a raport to mówi.
- Środowiska tworzące kod w locie (.NET, silniki antywirusowe) mają pełną wagę, jak w zrzucie.

## Co zmierzono

Jeden gość, 2026-11-23: kontroler domeny Windows Server 2025 (4 GiB RAM) na hoście Rocky Linux 9.8, QEMU uruchomione przez libvirt.

- 96 procesów gościa wylistowanych i przeskanowanych w 9 sekund, przeczytane 1,8 GiB, gość działał przez cały czas.
- Wszystkie procesy były czytelne, w tym `lsass.exe`, `MsMpEng.exe`, `csrss.exe` i `LsaIso.exe`.
- 3 procesy o wadze od „podejrzane": `Microsoft.ActiveDirectory.WebServices.exe` (.NET, `RWX` i `X-PRIV`), `MsMpEng.exe` (`RWX` i `X-PRIV`) oraz `LogonUI.exe` (dwie strony `X-PRIV`). Ocena: środowiska tworzące kod; żadnego nie weryfikowano ręcznie.
- Nie zmierzono: innych wersji Windows, procesów 32-bitowych, gości z balonem pamięci albo dużymi stronami, gości z włączonym VBS, obciążenia zajętego hosta.

## Uwagi o implementacji

- Moduł `nanshe-vm`. Pamięć fizyczną gościa i jądro Windows odnajduje biblioteka [memflow](https://github.com/memflow/memflow) (MIT); z niej pochodzi lista procesów i listy modułów.
- Tablice stron przechodzi sam Nanshe (`walk_page_tables`). memflow 0.2.4 łączy bit zapisu poziomów tablic stron przez „lub" zamiast „i", przez co każda strona wygląda na zapisywalną, a każda strona kodu na `RWX`.
- Gość jest daną niezaufaną. Przejście tablic ma limit liczby czytanych tablic (`MAX_TABLES`) i limit liczby zakresów stron na proces (`MAX_RANGES`); po osiągnięciu limitu wynik procesu jest oznaczany jako niepełny. Oba limity są testowane, razem z tablicami nieczytelnymi i wskazującymi na siebie.

## Plan dla tej funkcji

- Lista regionów z drzewa VAD jądra (prawdziwe rodzaje regionów, nazwy plików mapowanych, regiony zarezerwowane).
- Strony przejściowe i prototypowe (obecne w pamięci fizycznej, ale nieoznaczone jako obecne w tablicach stron).
- Inne hiperwizory (Proxmox używa QEMU i powinien działać; Hyper-V i VMware wymagają innej drogi do pamięci gościa) oraz goście Linux.
