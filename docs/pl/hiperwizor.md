# Odczyt gościa Windows z hosta KVM

Wersja angielska: [../hypervisor.md](../hypervisor.md).

`nanshe vm` skanuje procesy działającej maszyny wirtualnej Windows z hosta Linux, który uruchamia ją pod KVM/QEMU. W gościu nic nie jest instalowane ani uruchamiane. Skaner czyta pamięć procesu QEMU na hoście, znajduje w niej jądro Windows i przechodzi tablice stron każdego procesu gościa. Detektory i raport są te same co przy skanie na żywo.

Stan: pierwsza wersja (zapowiedź 0.4). Zmierzona na razie na dwóch gościach, w tym na jednym w porównaniu ze skanem na żywo tego samego systemu; patrz „Co zmierzono". Wyniki z tego trybu wymagają większej ostrożności niż wyniki skanu na żywo.

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
| Lista regionów | z menedżera pamięci (wszystkie regiony zarezerwowane i przydzielone) | granice regionów z drzewa VAD jądra; badane są tylko części obecne w pamięci fizycznej (strony w zestawie roboczym i strony przejściowe) |
| Ochrona regionu | ustawiona przez proces | faktyczna, z tablic stron, łączona między poziomami tak jak w procesorze |
| Rodzaj regionu | prywatny, mapowany, obraz | prywatny, mapowany albo obraz z drzewa VAD jądra; z listy modułów procesu tylko wtedy, gdy układ VAD jądra nie jest znany (starsze pliki symboli) |
| Pliki mapowane jako dane | znane, ze ścieżką | znane, ze ścieżką z obiektu pliku jądra (bez litery dysku) |
| Porównanie kodu z plikiem na dysku (`IMG-MOD`) | tak | nie (host nie widzi plików gościa) |
| Wątki, sieć, otwarte pliki, drzewo procesów | tak | nie |
| Obniżka wagi dla środowisk tworzących kod w locie | tak | nie (pliku programu nie da się sprawdzić z hosta) |

Skutki, o których warto wiedzieć przed lekturą raportu:

- **Rodzaj regionów pochodzi z jądra, nie z procesu.** Drzewo VAD i obiekty plików to struktury jądra, więc proces nie ukryje biblioteki, edytując własną listę modułów, a niepełna lista modułów nie daje już fałszywych znalezisk `X-PRIV` (zmierzone: jeden proces spadł z 430 takich znalezisk do 2, cztery inne z setek do zera). Jeśli plik symboli jądra nie zawiera struktur VAD, skaner wraca do listy modułów i mówi o tym w wyniku; wtedy dawna słabość obowiązuje.
- **Kod, którego jądro nie potrafi przypisać, jest badany, a nie usprawiedliwiany.** Strona wykonywalna, której nie opisuje żaden wpis VAD, jest traktowana jak pamięć prywatna (etykieta `[no VAD]`): odpięcie regionu z drzewa to znany sposób jego ukrycia. Obraz, którego pliku nie da się nazwać, jest traktowany jak mapowanie bez pliku (etykieta `[image without file name]`, cecha `X-MAP`): tak wygląda proces uruchomiony z pliku usuniętego albo podmienionego. Na drugim gościu 13 regionów obrazów nie miało czytelnej nazwy i dwa procesy zostały przez to wskazane; na żadnym gościu nie było strony poza drzewem VAD. Przyczyny nieczytelnych nazw nie ustalono, więc takie znalezisko wymaga ręcznego sprawdzenia, a nie wniosku.
- **Stron zapisanych do pliku wymiany nie widać.** Region może być krótszy niż w skanie na żywo albo może go nie być. Strony przejściowe (zdjęte z zestawu roboczego, ale nadal w pamięci fizycznej) są czytane. Na drugim gościu dwa procesy wskazane przez skan na żywo osiem godzin wcześniej (`dwm.exe`, `ShellExperienceHost.exe`) nie miały w chwili późniejszego skanu z hosta żadnej prywatnej strony wykonywalnej w pamięci fizycznej; nie ustalono, czy te strony trafiły do pliku wymiany, czy zostały zwolnione.
- **Gość działa w trakcie skanu,** więc wynik nie jest spójną migawką.
- **`HDR` w pamięci niewykonywalnej jest zgłaszany tylko dla regionów, które jądro oznacza jako prywatne.** Sekcje bez pliku i regiony o nieznanym rodzaju są pomijane, bo pliki mapowane jako dane zaczynają się nagłówkiem obrazu. Silniki antywirusowe trzymają w pamięci prywatnej wiele obrazów programów i mają wiele znalezisk `HDR` (228 w `MsMpEng.exe` na pierwszym gościu).
- Środowiska tworzące kod w locie (.NET, silniki antywirusowe) mają pełną wagę, jak w zrzucie.

## Co zmierzono

Jeden gość, 2026-11-23: kontroler domeny Windows Server 2025 (4 GiB RAM) na hoście Rocky Linux 9.8, QEMU uruchomione przez libvirt.

- 96 procesów gościa wylistowanych i przeskanowanych w 9 sekund, przeczytane 1,8 GiB, gość działał przez cały czas.
- Wszystkie procesy były czytelne, w tym `lsass.exe`, `MsMpEng.exe`, `csrss.exe` i `LsaIso.exe`.
- 3 procesy o wadze od „podejrzane": `Microsoft.ActiveDirectory.WebServices.exe` (.NET, `RWX` i `X-PRIV`), `MsMpEng.exe` (`RWX` i `X-PRIV`) oraz `LogonUI.exe` (dwie strony `X-PRIV`). Ocena: środowiska tworzące kod; żadnego nie weryfikowano ręcznie.
- Nie zmierzono: innych wersji Windows, procesów 32-bitowych, gości z balonem pamięci albo dużymi stronami, gości z włączonym VBS, obciążenia zajętego hosta.

Drugi gość, 2026-11-24: Windows 11 Enterprise LTSC (build 26100.9974, 4 GiB RAM) na tym samym hoście, porównany ze skanem na żywo wykonanym w tym samym gościu około 90 minut wcześniej.

- 137 do 162 procesów gościa na przebieg, 18 do 34 sekund, bez błędów odczytu. Skan na żywo nie otworzył 17 procesów (między innymi `lsass.exe`, `MsMpEng.exe`, `csrss.exe`, `services.exe`); skan z hosta przeczytał wszystkie.
- Pierwsze przebiegi na tym gościu były błędne w obie strony: w żadnym procesie zwykłego użytkownika nie było widać ani jednej strony wykonywalnej. Przyczyna: izolacja tablic stron jądra. Taki proces ma dwa zestawy tablic stron, a w zestawie jądrowym cała połowa użytkownika jest oznaczona jako niewykonywalna. Skaner czyta teraz zestaw użytkownika (`UserDirectoryTableBase`), gdy proces go ma. Na pierwszym gościu wszystkie wskazane procesy były systemowe i miały jeden zestaw, więc błąd się nie ujawnił.
- Po poprawce z 14 procesów wskazanych przez skan na żywo 12 zostało wskazanych także z hosta. Dla `TrueConf.exe` odnalazło się 87 ze 101 adresów regionów wskazanych przez skan na żywo; dla `QtWebEngineProcess.exe` znaleziska były te same poza `IMG-MOD`. `dwm.exe` (57 regionów `X-PRIV` w skanie na żywo) i `ShellExperienceHost.exe` nie zostały wskazane z hosta; przyczyny nie ustalono.
- Przy regionach z drzewa VAD (później tego samego dnia) fałszywe alarmy z wcześniejszych przebiegów zniknęły: z 14 procesów wskazanych przez skan na żywo 12 zostało wskazanych z hosta z tymi samymi cechami poza `IMG-MOD` (na przykład `QtWebEngineProcess.exe`: `X-PRIV` 6 i `ENT-X` 3 w obu), żaden proces zbadany i niewskazany przez skan na żywo nie został wskazany z hosta, a `MsMpEng.exe`, którego skan na żywo nie otwiera, został przeczytany. Liczby regionów w procesach z intensywnym JIT różnią się między skanami wykonanymi w odstępie ośmiu godzin.
- Liczb nie da się porównywać jeden do jednego: skan na żywo liczy regiony, skan z hosta liczy ciągi obecnych stron, więc jeden region może dać wiele znalezisk.

## Uwagi o implementacji

- Moduł `nanshe-vm`. Pamięć fizyczną gościa i jądro Windows odnajduje biblioteka [memflow](https://github.com/memflow/memflow) (MIT); z niej pochodzi lista procesów i listy modułów.
- Tablice stron przechodzi i pamięć gościa czyta sam Nanshe (`walk_page_tables`, `leaf_entry`), razem ze stronami przejściowymi i wpisami, w których Windows odwraca bity adresu na procesorach podatnych na L1TF. memflow 0.2.4 łączy bit zapisu poziomów tablic stron przez „lub" zamiast „i", przez co każda strona wygląda na zapisywalną, a każda strona kodu na `RWX`, i nie tłumaczy stron przejściowych.
- Proces objęty izolacją tablic stron jądra ma drugi zestaw tablic dla trybu użytkownika; jego adres jest czytany z `_KPROCESS.UserDirectoryTableBase` (przesunięcie z tego samego pliku symboli) i używany, gdy istnieje.
- Gość jest daną niezaufaną. Przejście tablic ma limit liczby czytanych tablic (`MAX_TABLES`) i limit liczby zakresów stron na proces (`MAX_RANGES`); po osiągnięciu limitu wynik procesu jest oznaczany jako niepełny. Oba limity są testowane, razem z tablicami nieczytelnymi i wskazującymi na siebie.

## Plan dla tej funkcji

- Strony prototypowe (wspólne, jeszcze nietknięte przez proces) i strony w pliku wymiany.
- Inne hiperwizory (Proxmox używa QEMU i powinien działać; Hyper-V i VMware wymagają innej drogi do pamięci gościa) oraz goście Linux.
