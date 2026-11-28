# Nanshe na Windows

Wersja angielska: [../windows.md](../windows.md).

Stan: obsługiwany. Sprawdzony na Windows 11 Pro x64 (jedna stacja testowa), build natywny MSVC.

## Build

Wymagane: Rust (toolchain `stable-x86_64-pc-windows-msvc`) i Visual Studio Build Tools z obciążeniem C++.

```powershell
cargo build --release -p nanshe-cli --features llm
# target\release\nanshe.exe
```

Testy end-to-end (`scripts\e2e.ps1`) i testy instalatorów uruchamiaj tylko na dedykowanej stacji testowej: startują próbki, instalują i usuwają program.

## Instalacja z paczki

Paczkę buduje na hoście z toolchainem MSVC skrypt `scripts\package-windows.ps1`; powstaje `dist\nanshe-<wersja>-windows-x64.zip` z programem, bazą wiedzy, instalatorem i listą skrótów `SHA256SUMS`. Po rozpakowaniu, w konsoli administratora:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1      # opcje: -InstallDir, -NoPath, -NoShortcut, -Quiet
```

Instalator:

- sprawdza skróty SHA-256 wszystkich plików paczki i odmawia, gdy którykolwiek się nie zgadza,
- instaluje do `C:\Program Files\Nanshe`; katalog należy do Administratorów, zwykli użytkownicy mają tylko odczyt, dziedziczenie uprawnień jest wyłączone,
- tworzy `C:\ProgramData\Nanshe\wyniki` dostępny tylko dla Administratorów i SYSTEM (wyniki i raporty zawierają dane z pamięci),
- odmawia, gdy któryś z tych katalogów już istnieje i jest dowiązaniem, zawiera dowiązanie albo należy do zwykłego konta (w `ProgramData` katalog może założyć każdy użytkownik); sprawdza oba katalogi, zanim cokolwiek zmieni,
- dopisuje katalog programu do systemowego `PATH`, tworzy skrót w menu Start uruchamiany jako administrator i wpis w „Programy i funkcje".

Usuwanie: „Programy i funkcje" albo `uninstall.ps1` z katalogu programu; wyniki zostają, chyba że podano `-RemoveData`. Skrypt usuwania stosuje te same kontrole co instalator: odmawia, gdy katalog jest dowiązaniem, zawiera dowiązanie albo należy do zwykłego konta.exe` nie jest podpisany cyfrowo, więc system może ostrzegać przy uruchomieniu.

### Instalator MSI

Drugą, zalecaną postacią jest pakiet Instalatora Windows: `nanshe-<wersja>-windows-x64.msi`. Buduje go `scripts\package-msi.ps1` narzędziem WiX Toolset 3.14 (licencja MS-RL; służy tylko do budowania i nie trafia do pakietu):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-msi.ps1 -Bin <katalog z nanshe.exe> -Wix <katalog z candle.exe> -Out dist
msiexec /i nanshe-0.2.0-windows-x64.msi            # z oknami; cicho: /qn /norestart
msiexec /x nanshe-0.2.0-windows-x64.msi /qn        # usunięcie (albo "Programy i funkcje")
```

Pakiet:

- instaluje dla wszystkich użytkowników do `C:\Program Files\Nanshe` (program, baza wiedzy po polsku i angielsku, licencje, `README.md`),
- tworzy katalog `C:\Program Files\Nanshe\wyniki` dostępny tylko dla Administratorów i konta SYSTEM, bez dziedziczenia uprawnień,
- dopisuje katalog programu do systemowej zmiennej PATH i usuwa wpis przy odinstalowaniu,
- dodaje w menu Start skrót „Nanshe (administrator console)", który otwiera konsolę z podniesionymi uprawnieniami w katalogu wyników,
- pokazuje licencję Apache 2.0 przed instalacją,
- zastępuje poprzednią wersję zainstalowaną z MSI (stały identyfikator rodziny produktu),
- odmawia instalacji, gdy wykryje wersję zainstalowaną skryptem `install.ps1` (oba sposoby używają tego samego katalogu).

Różnice wobec instalatora skryptowego: katalog wyników leży w `Program Files`, a nie w `ProgramData`. W `ProgramData` zwykły użytkownik może przygotować katalog przed instalacją; skrypt to sprawdza, a pakiet MSI unika problemu, wybierając miejsce, w którym zwykły użytkownik niczego nie utworzy. Przy odinstalowaniu pliki wyników zostają.

Pakiet i program nie są podpisane cyfrowo: Windows pokaże ostrzeżenie o nieznanym wydawcy. Pliki WiX także nie mają podpisu, dlatego skrypt budujący sprawdza skrót SHA-256 archiwum WiX zapisany w skrypcie (skrót pochodzi z jednego pobrania z oficjalnego wydania; nie był porównany z niezależnym źródłem).

## Uprawnienia

- Uruchamiać jako administrator (podniesiony). Narzędzie włącza `SeDebugPrivilege`; bez niej widać tylko procesy własnego użytkownika, a narzędzie wypisuje ostrzeżenie.
- Procesy chronione (PPL, np. LSASS z `RunAsPPL`, usługi antywirusa) są niedostępne także dla administratora: trafiają do wyniku jako niedostępne, a wynik jest częściowy.
- Wynik i raport podają, z jakimi uprawnieniami działał skaner (konto, poziom integralności, `SeDebugPrivilege`). Skan bez podniesionych uprawnień albo bez `SeDebugPrivilege` jest w raporcie oznaczony ostrzeżeniem na pierwszej stronie.
- Konto SYSTEM nie daje więcej niż administrator z podniesionymi uprawnieniami: w dwóch pomiarach na stacji testowej (2026-11-22) oba skany miały tyle samo procesów niedostępnych (18, potem 20) i te same procesy ze znaleziskami. Procesy chronione wymagają innej drogi: zrzutu pamięci (`nanshe scan <plik-zrzutu>`) albo, dla gościa działającego pod KVM/QEMU, odczytu z hiperwizora poleceniem `nanshe vm` (pierwsza wersja, patrz [hiperwizor.md](hiperwizor.md)).

Skaner używa `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)`, `VirtualQueryEx` i `ReadProcessMemory`. Niczego nie zapisuje w celu i nie wstrzykuje kodu.

## Strony ze strażnikiem (PAGE_GUARD)

Odczyt strony ze strażnikiem zdejmuje flagę, czyli zmienia stan badanego procesu. Dlatego takich stron skaner nie czyta.

- Wykonywalny region ze strażnikiem dostaje tag `GUARD-X` (30 punktów), liczy się jako nieodczytany, a wynik jest częściowy. Detektory treści (`ENT-X`, `HDR`) go nie sprawdziły i raport mówi to wprost.
- Zwykłe strony strażnika stosu (RW) nie są liczone: ma je każdy wątek.

## Kontekst systemowy

Dla procesu ze znaleziskiem od wagi „podejrzane" skan zbiera dodatkowo, wyłącznie zapytaniami o metadane (`PROCESS_QUERY_LIMITED_INFORMATION`):

| Co | Skąd |
|---|---|
| rodzic, liczba wątków, dzieci | migawka `CreateToolhelp32Snapshot` |
| wiersz poleceń | `NtQueryInformationProcess(ProcessCommandLineInformation)`; jądro kopiuje go do bufora skanera |
| użytkownik, poziom integralności, podniesienie uprawnień | token procesu (`TokenUser`, `TokenIntegrityLevel`, `TokenElevation`) |
| czas startu, sesja | `GetProcessTimes`, `ProcessIdToSessionId` |
| plik programu: rozmiar, czas zmiany, SHA-256 | ścieżka z `QueryFullProcessImageNameW`, plik czytany z dysku |
| gniazda TCP/UDP (IPv4, IPv6) z właścicielem | `GetExtendedTcpTable`, `GetExtendedUdpTable` |
| otwarte uchwyty: liczba wszystkich oraz nazwane pliki dyskowe, klucze rejestru, sekcje, muteksy i uchwyty do innych procesów (do 300) | `NtQuerySystemInformation(SystemExtendedHandleInformation)`, potem typ i nazwa przez kopię uchwytu |
| pełna mapa regionów | `VirtualQueryEx` (ta sama, na której pracowały detektory) |

Uchwyty: żeby poznać typ i nazwę obiektu, skaner otwiera proces z prawem `PROCESS_DUP_HANDLE` i kopiuje uchwyt do siebie bez żadnych praw (`DuplicateHandle` z dostępem 0; dla uchwytów do procesów z prawem zapytania o metadane), po czym kopię zamyka. Stan badanego procesu się nie zmienia, ale obiekt ma przez chwilę o jedno odwołanie więcej. To jedyne miejsce, w którym skaner prosi o prawo inne niż odczyt. Nazwy są pytane tylko dla plików dyskowych i obiektów innych niż pliki: zapytanie o nazwę potoku potrafi zawiesić wątek, więc potoki i gniazda są zapisywane bez nazwy. Każde zapytanie o nazwę idzie przez wątek roboczy z limitem 500 ms; po trzech przekroczeniach limitu lista uchwytów procesu jest przerywana z adnotacją w raporcie. Uchwyt do innego procesu jest opisany numerem PID, nazwą i prawami pozwalającymi ingerować w ten proces (zapis pamięci, operacje na pamięci, tworzenie wątków, kopiowanie uchwytów).

Numer PID rodzica bywa użyty ponownie po jego zakończeniu, dlatego rodzic jest uznawany tylko, gdy powstał przed dzieckiem; inaczej łańcuch przodków jest urywany z adnotacją w raporcie.

Nie są zbierane: katalog roboczy, właściciel pliku programu, podpis cyfrowy pliku, nazwy potoków, uchwyty obiektów bez nazwy (poza ich liczbą). Uchwyty działają tylko w wersji 64-bitowej narzędzia. Procesy chronione, dla których system odmawia `PROCESS_DUP_HANDLE`, mają podaną samą liczbę uchwytów. `nanshe scan --no-context` wyłącza cały kontekst i mapę.

## Użycie

```powershell
nanshe ps
nanshe scan --pid 1234 --json wynik.json
nanshe scan --all --min high --json host.json
nanshe report wynik.json
```

Wydruk skanu podaje procesy od najwyższej wagi, regiony o tych samych znacznikach, uprawnieniach, punktacji i źródle w jednym wierszu (liczba, zakres rozmiarów, pierwsze adresy), procesy niedostępne zebrane według przyczyny, a opis każdego znacznika raz na końcu. `--regions` wypisuje każdy region osobno, z entropią i opisami znalezisk. Kolory (dobrane do ciemnego tła) są używane tylko na terminalu; `--color always|never` zmienia to, a zmienna `NO_COLOR` je wyłącza.

## Detektory działające na Windows

| Tag | Punkty | Warunek |
|---|---|---|
| `RWX` | 30 | strona `PAGE_EXECUTE_READWRITE` / `PAGE_EXECUTE_WRITECOPY` |
| `X-PRIV` | 30 | wykonywalna pamięć prywatna (`MEM_PRIVATE`) |
| `X-MAP` | 30 | wykonywalne mapowanie `MEM_MAPPED`, czyli sekcja niebędąca obrazem modułu |
| `X-TMP` | 30 | kod obrazu modułu (`MEM_IMAGE`) załadowanego z `\AppData\Local\Temp`, `\AppData\LocalLow\Temp`, `\Windows\Temp`, `\Users\Public` albo `\$Recycle.Bin` |
| `GUARD-X` | 30 | wykonywalny region z `PAGE_GUARD`, treść nieodczytana |
| `ENT-X` | 20/30 | wysoka entropia w regionie wykonywalnym |
| `HDR` | 40 | nagłówek PE (`MZ` + `PE\0\0`, niezerowe pole Machine, 1-96 sekcji) w regionie bez pliku: na początku strony w każdym regionie, a w regionach wykonywalnych także pod dowolnym przesunięciem |
| `THR-PRIV` | 40 | adres startu wątku leży w pamięci bez pliku; albo (x64) wątek czeka w jądrze, a jego stos wywołań wraca do pamięci bez pliku (zob. „Stos wywołań wątków") |
| `IMG-MOD` | 10/40 | strony wykonywalnego, niezapisywalnego obrazu modułu nie są już współdzielone z plikiem (kopia przy zapisie); 40 dla `amsi.dll` i `wldp.dll`, 10 dla pozostałych |
| `SHC` | 40/20/10 | wzorce kodu typowe dla shellcode'u w pamięci wykonywalnej, która nie pochodzi z pliku na dysku (pamięć anonimowa, `memfd`): ustalanie własnego adresu, bezpośrednie wywołanie jądra, prolog znanych etapów ładujących, na Windows także odczyt PEB, pętla skrótów nazw funkcji i kopia wejścia do jądra poza `ntdll`. 40 za dwie klasy albo jedną mocną, 20 za pojedynczą słabszą (sama nie przekracza progu), 10 za samą kopię wejścia do jądra w przeglądarce opartej na Chromium (robi to jej piaskownica). Bez obniżki dla środowisk JIT |

`MEMFD` i `DEL-EXEC` dotyczą tylko Linuksa.

`THR-PRIV` i `IMG-MOD` nie podlegają obniżce dla środowisk JIT. Adres startu pochodzi z `NtQueryInformationThread`, a stan stron z `QueryWorkingSetEx` (oba tylko do odczytu). `IMG-MOD` ocenia wyłącznie strony obecne w zestawie roboczym procesu. Porównuje je z plikiem PE na dysku (z relokacjami dla faktycznego adresu załadowania) i podaje liczbę różniących się bajtów oraz adres pierwszego; gdy treść jest zgodna z plikiem, zostaje znalezisko informacyjne (10 punktów), bo tożsamości pliku nie da się potwierdzić; gdy treści nie dało się porównać, znalezisko to mówi.

Pomiar na stacji testowej (2026-11-22, 240 procesów): `IMG-MOD` wystąpił w 28 regionach 19 procesów, w tym `user32.dll` w 10 procesach, `clr.dll` w 9, `ntdll.dll` w 3 (procesy WebView2) i biblioteki agenta monitoringu. Przyczyn nie badałem pojedynczo; znane łagodne źródła to relokacja bibliotek bez ASLR, podpięcia piaskownicy Chromium i samo środowisko .NET. Dlatego zwykła biblioteka dostaje 10 punktów („info", także razem z `ENT-X` w tym samym kodzie; przy 20 punktach dziesięć zwykłych procesów stawało się „podejrzane"), a pełną wagę mają tylko moduły zabezpieczeń skryptów (`amsi.dll`, `wldp.dll`), których zmiana w pamięci jest typowa dla obejść. `THR-PRIV` nie wystąpił w tym pomiarze ani razu.

### Stos wywołań wątków

Adres startu wątku nie wystarcza, gdy kod przejmuje istniejący wątek albo chowa się na czas uśpienia (zdejmuje prawo wykonania i szyfruje własną pamięć). Dlatego na Windows x64 skaner odwija stosy wątków, które czekają w wywołaniu jądra, i sprawdza pierwszy adres powrotu leżący poza obrazami modułów:

| Dokąd wraca stos | Wynik |
|---|---|
| obraz modułu (cały stos) | nic |
| pamięć wykonywalna bez pliku | `THR-PRIV` 40; w procesie z rozpoznanym środowiskiem JIT nic, bo tak wygląda zwykły wątek kodu zarządzanego |
| pamięć niewykonywalna bez pliku | `THR-PRIV` 40, także w procesie z JIT: tak wygląda kod ukryty na czas uśpienia |

Jak to działa i czego nie robi:

- Rejestry pochodzą z `GetThreadContext` bez wstrzymywania wątku; proces nie jest zatrzymywany ani zmieniany. Liczą się tylko wątki stojące tuż za instrukcją `syscall` w obrazie modułu, których adres instrukcji i wskaźnik stosu są takie same przed odwijaniem i po nim.
- Odwijanie korzysta z tablic wyjątków (`.pdata`) czytanych z pamięci procesu i kończy się na pierwszej ramce poza obrazami. Dalszych ramek nie ocenia.
- Wynik wątpliwy jest porzucany: brak tablicy, nieznana wersja informacji o odwijaniu, nieudany odczyt, adres w regionie własnego stosu wątku.
- Ta sama kontrola działa na zrzucie procesu (rejestry ze strumienia `ThreadList` minidumpa) i przy odczycie gościa z hiperwizora (rejestry z jądra, zob. `docs/pl/hiperwizor.md`).

**Pokrycie.** Brak znalezisk znaczy coś tylko wtedy, gdy stosy faktycznie przejrzano, dlatego wynik podaje to dla każdego procesu (pole `stacks`), a raport pokazuje w metryce i w opisie procesu („Stosy wątków"):

| Licznik | Znaczenie |
|---|---|
| `threads` | wątki, których rejestry odczytano |
| `unread` | żyjące wątki, których rejestrów nie dało się odczytać; ich stosy nie zostały zbadane. Wątki już zakończone, które zostają na liście, dopóki ktoś trzyma ich uchwyt, nie są liczone |
| `waiting` | wątki czekające w wywołaniu jądra (tylko one są odwijane) |
| `complete` | stosy odwinięte do dna (zerowy adres powrotu pierwszej funkcji wątku), każda ramka w obrazie modułu |
| `foreign` | stosy z adresem powrotu poza obrazami modułów |
| `abandoned` | stosy porzucone, z powodem: `no-table`, `table-read`, `unwind-info-read`, `unwind-info`, `stack-read`, `stack-bounds`, `frame-limit`, `register-unknown`, `moved`, `own-stack`, `outside-map`, `thread-limit` |

Pomiar na stacji testowej (2026-11-25, skan na żywo, 229 procesów, 35 s): odczytano rejestry 1817 wątków, 408 nie odczytano; 1815 wątków czekało, 1773 stosy odwinięto do dna, 42 wracały poza moduły (wszystkie do pamięci wykonywalnej procesów z rozpoznanym środowiskiem JIT, więc bez zgłoszenia), żadnego nie porzucono. Żadnego zgłoszenia poza próbkami. To jeden pomiar na jednej stacji.

Przyczyna 408 nieodczytanych wątków (ustalona 2026-11-27 osobnym odczytem na dwóch stacjach): były to wątki już zakończone, których obiekty istnieją, dopóki jakiś program trzyma ich uchwyt (na pierwszej stacji 430 z 431 wątków z błędem odczytu, na drugiej 193 ze 193; najwięcej w procesach usług). Taki wątek nie ma stosu do zbadania, więc licznik go już nie obejmuje. Ten sam skan po zmianie (228 procesów, 39 s): 1857 wątków odczytanych, 1 nieodczytany (`LsaIso.exe`, proces izolowany przez system), 1855 czekających, 1813 stosów odwiniętych do dna, 42 wracające poza moduły, żadnego porzuconego.

Ograniczenia: sfałszowany stos (podstawione ramki wracające do obrazów modułów) omija tę kontrolę; kod wstrzyknięty do procesu z JIT, wracający do pamięci wykonywalnej, nie różni się od kodu środowiska; wątki działające w chwili skanu, procesy 32-bitowe, Linux i macOS nie są objęte.

### Rezerwacja regionu ze znaleziskiem

Każdy region ze znaleziskiem niesie opis rezerwacji, do której należy (pole `allocation`: adres bazowy, rozmiar, liczba regionów mapy w jej zakresie), gdy źródło ją zna: `AllocationBase` w skanie na żywo, wpis VAD przy odczycie z hiperwizora. Jest zapisywany dla analityka i do pomiarów; punktacja z niego nie korzysta.

Pomiar, który miał uzasadnić jego użycie (2026-11-25, regiony z `X-PRIV`, `RWX` albo `X-MAP`), nie daje prostej reguły:

| Gdzie | Regiony | Rezerwacja do 64 KiB | do 1 MiB | do 16 MiB | większa | Jedyny region w rezerwacji |
|---|---|---|---|---|---|---|
| stacja testowa, procesy ze środowiskiem .NET (10) | 376 | 271 | 91 | 14 | 0 | 102 |
| stacja testowa, WebView2 (1) | 7 | 5 | 0 | 0 | 2 | 5 |
| drugi gość, procesy bez rozpoznanego środowiska, głównie Electron i Qt WebEngine (7) | 429 | 13 | 8 | 22 | 386 | 15 |

Kod generowany przez V8 leży w dużych rezerwacjach, ale środowisko .NET przydziela swój kod w wielu małych, z których jedna czwarta to pojedyncze regiony. „Samotny region wykonywalny w małej rezerwacji" opisuje więc zwykły kod .NET tak samo jak pojedynczy wstrzyknięty przydział, dlatego wagi zostały bez zmian.

## Skróty SHA-256

Skan liczy skróty plików i zapisuje je w polu `files` wyniku (`--no-hashes` wyłącza): plik programu każdego procesu oraz pliki zmapowane w procesach ze znaleziskami od wagi „podejrzane" (otwierane po ścieżce urządzenia). Każdy region ze znaleziskiem ma dodatkowo skrót swojej zawartości. Limit pliku: 512 MiB. Podpis cyfrowy plików nie jest sprawdzany.

## Linia bazowa i szum

Pomiar `scan --all` na stacji testowej (2026-11-21): 246 procesów, 22 GB, 45 s; 18 procesów niedostępnych, 25 z regionami „podejrzane" lub „wysokie". Prawie cały szum to środowiska JIT:

- .NET Framework: prywatne sterty RWX w każdym procesie z załadowanym `clr.dll`, jedna strona RWX w obrazie `clr.dll`, wykonywalne sekcje bez pliku (`X-MAP`),
- V8 w aplikacjach Electron/WebView2.

### Obniżka wagi dla środowisk JIT

Pomiar na stacji testowej (2026-11-22, `scan --all`, 244 procesy): przed zmianą 20 procesów miało regiony „podejrzane" lub „wysokie", po zmianie 5. Zostało narzędzie własne uruchamiane spoza katalogów systemowych i cztery procesy `Teams.exe` z profilu użytkownika, czyli programy spoza katalogów systemowych; 14 procesów ma znaleziska z adnotacją obniżki, a 213 z 222 plików programów spełnia warunek katalogu i właściciela. Wynik po zaostrzeniu warunków (właściciel, katalogi środowisk) jest taki sam. To jedna stacja.

Na Windows środowisko JIT jest rozpoznawane po załadowanym module, bo .NET i WebView2 działają wewnątrz dowolnych programów. Waga `RWX`, `X-PRIV`, `X-MAP` i `ENT-X` jest dzielona przez 3 (znaleziska zostają widoczne, z adnotacją `jit:dotnet` albo `jit:webview2`), gdy spełnione są oba warunki:

- plik programu leży w `%SystemRoot%`, `%ProgramFiles%` albo `%ProgramFiles(x86)%` (wartości ze środowiska skanera), poza podkatalogami, w których zwykły użytkownik może tworzyć pliki (`Temp`, `Tasks`, `Tracing`, `spool`, `debug` i kilka innych), a jego właścicielem jest SYSTEM, grupa Administratorzy albo TrustedInstaller,
- w procesie jest obraz modułu (`MEM_IMAGE`) środowiska załadowany z jego katalogu instalacyjnego w korzeniu wolumenu: `clr.dll` z `\Windows\Microsoft.NET\Framework*`, `coreclr.dll` z `\Program Files\dotnet\shared` albo `\Program Files\WindowsApps`, `msedge.dll` z katalogów EdgeWebView albo Edge.

Pierwszy warunek jest po to, żeby nie wystarczyło załadować `clr.dll` do własnego programu z `%TEMP%` albo z `C:\Windows\Temp`. `HDR` i `GUARD-X` nie są obniżane, a `X-MAP` tylko dla sekcji bez pliku (tak .NET mapuje wygenerowany kod); wykonywalne mapowanie pliku nigdy nie dostaje obniżki.

Ograniczenia tej obniżki:

- Kod wstrzyknięty do legalnego procesu .NET dziedziczy obniżkę. Prywatny region RWX o niskiej entropii spada wtedy z 60 do 20 punktów („info") i znika z domyślnego widoku; z wysoką entropią (30 punktów) albo z nagłówkiem obrazu (60) zostaje widoczny. `--min info` pokazuje wszystko.
- Sprawdzany jest właściciel pliku programu, nie cała lista DACL: plik należący do Administratorów, ale zapisywalny dla wszystkich, przejdzie warunek. Podpis cyfrowy nie jest weryfikowany.
- Programy spoza katalogów systemowych (np. Electron w profilu użytkownika) nie dostają obniżki, więc nadal są w wyniku.

## Znane ograniczenia i ślepe punkty

Każdy punkt ma próbkę w `tests/samples` i oczekiwanie w `scripts/e2e.ps1`:

- **Sekcja `SEC_IMAGE` z pliku spoza katalogów systemowych**: `X-TMP` obejmuje tylko listę katalogów tymczasowych i publicznych (próbka `ximage` w `%TEMP%`). Obraz załadowany z innego katalogu zapisywalnego dla użytkownika (profil, `ProgramData`, własny katalog) nadal nie jest punktowany, bo stamtąd działają zwykłe programy.
- **Fałszywe alarmy `X-TMP`**: instalatory i programy aktualizujące, które rozpakowują się do `%TEMP%` i stamtąd działają, oraz aplikacje Electron rozpakowujące tam biblioteki natywne (`*.tmp.node`; jedna taka obserwacja na maszynie testowej) dostaną wagę „podejrzane".
- **Nagłówek PE z uszkodzoną sygnaturą i bez tablicy sekcji** (`pe-corrupt`): `HDR` nie reaguje, zostaje `X-PRIV`. Nagłówek z wymazanymi sygnaturami `MZ` i `PE`, po którym została tablica sekcji, jest wykrywany przez `HDR` w regionach wykonywalnych (`pe-wiped`).
- **Nagłówek poza granicą strony w danych niewykonywalnych**: niewidoczny (świadomie, bo kopie nagłówków w zwykłych danych są codziennością). W regionach wykonywalnych nagłówek pod przesunięciem jest wykrywany (`pe-offset`).
- Proces z ponad 1 048 576 regionami: skanowane są pierwsze regiony do limitu, znaleziska zostają, a wynik procesu jest oznaczony jako niekompletny.
- **Ładunek za strażnikiem** (`guard-hide`): treść niewidoczna, ale region dostaje `GUARD-X` i `X-PRIV`.
- Procesy 32-bitowe (WOW64) nie są odróżniane od 64-bitowych.
- Między dwoma skanami żywego procesu zmienia się liczba regionów (wątki puli), więc powtarzalne są znaleziska, a nie liczniki.
- Windows Defender nie zareagował na binaria ani próbki (jedna obserwacja, stacja testowa, 2026-11).

## Warstwa LLM i raport

Działają tak samo jak na Linuksie. Z hosta Windows do Ollamy w sieci lokalnej: `nanshe explain wynik.json --url http://<host>:11434 --insecure-llm` (czyste HTTP tylko w zaufanej sieci). Testy: [testy.md](testy.md).
