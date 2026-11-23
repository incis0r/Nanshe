# Nanshe: raport triage pamięci

host 1a3b4982fe9e \| skan 2026-11-23T12:08:46Z

| Pole | Wartość |
|---|---|
| Host | 1a3b4982fe9e |
| Czas skanu | 2026-11-23T12:08:46Z |
| Narzędzie | nanshe 0.1.0 |
| Procesy | 1 przeskanowanych, 1 ze znaleziskami od poziomu „podejrzane" |
| Znaleziska | 8 |
| Kompletność | pełny |
| System hosta | Debian GNU/Linux 12 (bookworm), jądro/wersja 7.1.10-200.fc44.aarch64 |
| Start systemu | 2026-11-13T15:36:49Z |
| Skan wykonał | root (uid 0) |
| Uprawnienia skanera | root; CAP\_SYS\_PTRACE: tak |
| Klasyfikacja | Poufne: dokument zawiera dane z badanej stacji; udostępniać wyłącznie osobom prowadzącym analizę |
| Plik wyniku | wynik-skanu.json |
| SHA-256 wyniku | 5a40750257126f1b84bbd35071ec685db372f65c95494c9bea7f30d9f757a699 |

> To wynik triage, nie werdykt. Znaleziska wskazują miejsca warte ręcznej analizy; ich brak nie dowodzi, że proces jest czysty. Nazwy procesów, ścieżki i opisy pochodzą z badanego systemu i mogą być kontrolowane przez atakującego.

> Raport zawiera dane z badanej stacji bez filtrowania: wiersze poleceń, ścieżki, adresy sieciowe, bajty i ciągi tekstowe z pamięci. Mogą wśród nich być hasła i klucze. Traktuj ten dokument jak materiał dowodowy.

**Spis treści**

- 1. Podsumowanie dla decydenta
- 2. Jak czytać ten raport
- 3. Przegląd procesów
- 4. Proces 2050: nanshe-sample
- 5. Czego ten raport nie obejmuje
- 6. Słowniczek
- 7. Legenda

## 1. Podsumowanie dla decydenta

Ocena ogólna. Co najmniej jeden proces ma cechy, których nie tłumaczy znane środowisko uruchomieniowe. Wymaga weryfikacji w pierwszej kolejności, zanim na stacji zostaną wprowadzone zmiany.

| Pole | Wartość |
|---|---|
| Zakres | 1 procesów na hoście 1a3b4982fe9e, stan z 2026-11-23T12:08:46Z |
| Kompletność | pełna dla procesów dostępnych skanerowi |
| Procesy do weryfikacji | 1 (P1: 1, P2: 0, P3: 0) od wagi „podejrzane" |

#### Najważniejsze procesy

| Priorytet | Proces | Dlaczego |
|---|---|---|
| P1 | 2050 nanshe-sample | Występuje cecha, której nie tłumaczy środowisko kompilujące kod w locie: HDR (cały program schowany w pamięci), MEMFD (kod z pliku istniejącego tylko w pamięci). |

#### Zalecane działania

- Dla procesów P1: zabezpieczyć zrzut pamięci procesu i nie restartować stacji przed zakończeniem weryfikacji; pamięć jest jedynym nośnikiem tych śladów.

Ograniczenia oceny: przegląd dotyczy stanu pamięci z jednej chwili, nie obejmuje procesów chronionych przez system ani pamięci jądra i opiera się na cechach, które mają też przyczyny łagodne. Szczegóły są w rozdziale „Czego ten raport nie obejmuje".

## 2. Jak czytać ten raport

Raport przedstawia wynik przeglądu pamięci działających procesów. Wskazuje obszary pamięci o cechach nietypowych dla zwykłego oprogramowania. Nie rozstrzyga, czy stacja została przejęta: każde znalezisko jest hipotezą do zweryfikowania.

Proces przechowuje kod i dane w wydzielonych obszarach pamięci, zwanych regionami. W typowym programie kod pochodzi z pliku na dysku i nie jest modyfikowany w trakcie pracy. Narzędzie wyszukuje odstępstwa od tej reguły: kod bez pliku źródłowego, kod modyfikowalny, kod o cechach danych zaszyfrowanych, obraz programu załadowany z pominięciem systemu, wątek działający z pamięci bez pliku oraz zmieniony kod biblioteki.

Takie odstępstwa występują w złośliwym oprogramowaniu, ale także w legalnym: w przeglądarkach, środowiskach .NET i Java oraz w programach zabezpieczających. Dlatego każde znalezisko ma w raporcie wyjaśnienie łagodne i niepokojące, ocenę w kontekście danego procesu oraz sposób weryfikacji.

Zalecana kolejność czytania: podsumowanie dla decydenta, tabela procesów z priorytetami, a następnie dla procesów o priorytecie P1 i P2 części "Ocena", "Co to za program" i "Co oznaczają znaleziska". Szczegóły regionów służą weryfikacji. Słowniczek pojęć znajduje się na końcu.

| Waga | Co oznacza |
|---|---|
| wysokie | kilka cech w jednym regionie; do weryfikacji w pierwszej kolejności |
| podejrzane | cecha wymagająca wyjaśnienia; często ma przyczynę łagodną |
| info | pojedyncza słaba cecha; bez dodatkowych przesłanek nie wymaga działania |

| Część raportu | Co pokazuje i na co patrzeć |
|---|---|
| Podsumowanie dla decydenta | najważniejsze ustalenia, ocena ogólna i zalecane działania na jednej stronie. |
| Ocena | priorytet weryfikacji procesu, uzasadnienie i pierwszy krok. |
| Procesy i cechy | tabela pokazuje, które cechy wystąpiły w których procesach i ile razy. Kolor komórki to najwyższa waga. Proces, który ma cechę nieobecną u podobnych procesów, warto obejrzeć pierwszy. |
| Drzewo procesów ze znaleziskami | wszystkie procesy ze znaleziskami na wspólnym drzewie: widać, czy mają wspólnego rodzica. |
| Co to za program | czym zwykle jest program o tej nazwie i czy leży tam, gdzie powinien. Nazwę proces może sobie nadać sam, więc liczy się ścieżka pliku i jego skrót SHA-256. |
| Drzewo procesów | kto uruchomił badany program (wyżej) i co on sam uruchomił (niżej). Nietypowy rodzic, na przykład edytor tekstu uruchamiający wiersz poleceń, to ważna wskazówka. |
| Sieć | połączenia i porty otwarte przez program w chwili skanu. Adres zdalny mówi, z kim program rozmawia; stan LISTEN oznacza, że czeka na połączenia przychodzące. |
| Otwarte pliki i uchwyty | pliki i inne zasoby, z których program właśnie korzysta. Na górze są pozycje nietypowe: pliki usunięte z dysku, pliki z katalogów tymczasowych i dostęp do innych procesów. |
| Pliki zmapowane do pamięci | biblioteki i pliki załadowane do pamięci programu. Na górze są pliki spoza katalogów systemowych, usunięte albo istniejące tylko w pamięci. |
| Mapa przestrzeni adresowej | cała pamięć programu od najniższego adresu. Kolor mówi, co leży w danym miejscu; czerwone i pomarańczowe bloki to znaleziska. Warto patrzeć, co sąsiaduje ze znaleziskiem. |
| Profil entropii regionu | pasek pokazuje, jak bardzo losowe są dane w kolejnych częściach regionu. Kolor turkusowy to zwykły kod i dane, pomarańczowy i czerwony to dane wyglądające na zaszyfrowane albo spakowane. |
| Podgląd bajtów | pierwsze bajty znaleziska zapisane szesnastkowo, a po prawej jako znaki. Pozwala na pierwszy rzut oka odróżnić tekst, kod i dane losowe. |
| Ciągi tekstowe w regionie | czytelne napisy znalezione w regionie: nazwy funkcji, ścieżki, adresy. Często zdradzają, do czego kod służy. |
| Interpretacja LLM | hipotezy modelu językowego na podstawie danych regionu. To pomoc w myśleniu, nie dowód; model może się mylić i nie zmienia punktacji. |
| Rozmiar i entropia regionów | każdy punkt to jeden region ze znaleziskiem: w poziomie rozmiar, w pionie losowość danych. Zwykłe sterty kodu tworzonego w locie leżą nisko i blisko siebie; punkt wysoko albo daleko od reszty to region odstający. |
| Skróty SHA-256 | odciski plików i zawartości regionów. Ten sam skrót oznacza identyczną zawartość, więc można go wyszukać w bazach znanych plików albo porównać między stacjami. |
| Od pamięci do sieci | po lewej regiony ze znaleziskami, w środku proces, po prawej jego połączenia sieciowe z chwili skanu. Diagram pokazuje, że podejrzany kod i połączenie są w tym samym procesie; nie dowodzi, że to ten kod otworzył połączenie. |

## 3. Przegląd procesów

| Priorytet | PID | Proces | Waga | Regiony | Maks. pkt | Tagi |
|---|---|---|---|---|---|---|
| P1 | 2050 | nanshe-sample | wysokie | 3 | 90 | ENT-X, HDR, MEMFD, RWX, X-PRIV |

Priorytet to kolejność weryfikacji (P1 w pierwszej kolejności), wyznaczona z rodzaju znalezisk i kontekstu procesu. Nie jest oceną szkodliwości; uzasadnienie znajduje się w części „Ocena" każdego procesu.

#### Znaleziska według tagu

| Tag | Liczba | Udział |
|---|---|---|
| ENT-X | 2 | ████████████████████████ |
| X-PRIV | 2 | ████████████████████████ |
| HDR | 1 | ████████████ |
| MEMFD | 1 | ████████████ |
| RWX | 1 | ████████████ |

#### Procesy i cechy

Liczba regionów z daną cechą w każdym procesie; kolor komórki to najwyższa waga takiego regionu. Proces z cechą, której nie mają podobne procesy, warto obejrzeć pierwszy.

| Proces | ENT-X | X-PRIV | HDR | MEMFD | RWX |
|---|---|---|---|---|---|
| 2050 nanshe-sample | 2 (wysokie) | 2 (wysokie) | 1 (wysokie) | 1 (wysokie) | 1 (wysokie) |

## 4. Proces 2050: nanshe-sample

| Pole | Wartość |
|---|---|
| System | linux/aarch64 |
| Plik programu | /target/debug/nanshe-sample |
| Regiony | 26 łącznie, 0 nieodczytanych, przeskanowano 2.7 MiB |
| Wiersz poleceń | /target/debug/nanshe-sample ctx 60 |
| Użytkownik | root (uid 0) |
| Uruchomiony | 2026-11-23T12:08:45Z |
| Proces nadrzędny | 1356 (sh) |
| Katalog roboczy | /src |
| Wątki | 1 |
| Plik programu: metadane | 5.1 MiB, zmieniony 2026-11-22T15:30:04Z, właściciel root (uid 0), tryb 0755 |
| Plik programu: SHA-256 | b30029f0ef4af73cfdac3069fc66c732cf4ea1f2b8f453c7c29b75f33100ef67 |
| uprawnienia efektywne (CapEff) | 00000000800c05fb |
| seccomp | filtr |
| no\_new\_privs | 0 |

### Ocena

| Pole | Wartość |
|---|---|
| Priorytet weryfikacji | P1: w pierwszej kolejności |
| Uzasadnienie | Występuje cecha, której nie tłumaczy środowisko kompilujące kod w locie: HDR (cały program schowany w pamięci), MEMFD (kod z pliku istniejącego tylko w pamięci). Plik programu leży poza katalogami systemowymi. Proces działa z wysokimi uprawnieniami, więc przejęcie go oznaczałoby kontrolę nad stacją. Proces ma w chwili skanu połączenia z adresami zdalnymi. |
| Pierwszy krok | Zabezpieczyć pełny zrzut pamięci procesu 2050 przed jakąkolwiek zmianą na stacji, a następnie wykonać kroki z części „Jak sprawdzić ten region" dla regionów o najwyższym wyniku. |

### Co to za program

Program o nazwie nanshe-sample to zwykle: Program testowy narzędzia Nanshe. Celowo tworzy w pamięci układy, których szukają detektory; niczego z nich nie uruchamia.

- Nazwę procesu program może ustawić sam, więc powyższe opiera się na nazwie tylko jako na wskazówce.

#### Co oznaczają cechy procesu

- uprawnienia efektywne (CapEff) = 00000000800c05fb: 0000000000000000 oznacza brak dodatkowych uprawnień; same jedynki szesnastkowe (np. 000001ffffffffff) to pełne uprawnienia administratora
- seccomp = filtr: "filtr" oznacza program w piaskownicy, co ogranicza skutki ewentualnego przejęcia
- no\_new\_privs = 0: 1 oznacza, że program i jego potomkowie nie mogą zdobyć wyższych uprawnień

### Drzewo procesów

- 1 sh: sh -c cargo test --workspace --features nanshe-cli/llm 2&gt;&amp;1 \| grep -E "^test result: .\* \[1-9\]\[0-9\]\* passed\|FAI
  - 1356 sh: sh scripts/example.sh /src/docs/przyklady
    - => 2050 nanshe-sample: /target/debug/nanshe-sample ctx 60 (badany proces)
      - 2052 nanshe-sample: /target/debug/nanshe-sample clean 600

### Sieć

| Protokół | Adres lokalny | Adres zdalny | Stan |
|---|---|---|---|
| tcp | 127.0.0.1:42551 | - | LISTEN |
| tcp | 127.0.0.1:56108 | 127.0.0.1:42551 | ESTABLISHED |
| tcp | 127.0.0.1:42551 | 127.0.0.1:56108 | ESTABLISHED |

### Otwarte pliki i uchwyty

Wszystkich deskryptorów lub uchwytów: 9. Zapisane z nazwą: 9 (memfd: 1, plik: 3, gniazdo: 3, potok: 1, urządzenie: 1).

| Nr | Rodzaj | Obiekt | Uwagi |
|---|---|---|---|
| 0x3 | memfd | memfd:payload | tylko w pamięci |
| 0x1 | plik | /src/docs/przyklady/sample.pid | poza katalogami systemowymi |
| 0x7 | plik | /tmp/ns-ctx-2050.dat | katalog tymczasowy |
| 0x8 | plik | /tmp/ns-ctx-2050.gone | usunięty z dysku, katalog tymczasowy |

### Pliki zmapowane do pamięci

| Plik | Rozmiar | Kod | Uwagi i opis |
|---|---|---|---|
| /target/debug/nanshe-sample | 456 KiB | tak | plik programu, poza katalogami systemowymi |
| memfd:payload | 8 KiB | tak | tylko w pamięci; plik istniejący tylko w pamięci RAM; nie ma go na dysku |
| /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 | 172 KiB | tak | program ładujący biblioteki przy starcie; normalny w każdym procesie |
| /usr/lib/aarch64-linux-gnu/libc.so.6 | 1.6 MiB | tak | podstawowa biblioteka systemowa; ma ją prawie każdy program |
| /usr/lib/aarch64-linux-gnu/libgcc\_s.so.1 | 196 KiB | tak | biblioteka pomocnicza kompilatora; normalna |

#### Skróty SHA-256 plików

| Plik | SHA-256 |
|---|---|
| nanshe-sample | b30029f0ef4af73cfdac3069fc66c732cf4ea1f2b8f453c7c29b75f33100ef67 |
| memfd:payload | brak: plik niedostępny: Operation not permitted (os error 1) |
| ld-linux-aarch64.so.1 | 17538b8f9889a470c061f69a8fea8124da89627311cd16546c133a89f09056df |
| libc.so.6 | e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0 |
| libgcc\_s.so.1 | 046856f95f4636f1fc7c3a12bf4f3cd5634c2fc5145c3fdf7395d4f349fa69c7 |

### Mapa przestrzeni adresowej

Wszystkie 26 regionów procesu od najniższego adresu. Sąsiednie mapowania tego samego pliku są połączone w jeden wiersz, długie ciągi zwykłych mapowań zwinięte, a duże nieużywane zakresy pokazane jako przerwy. Wysokość bloku rośnie z rozmiarem (skala logarytmiczna).

| Początek | Koniec | Rozmiar | Prawa | Rodzaj | Zawartość | Uwagi |
|---|---|---|---|---|---|---|
| 0xaaaac1000000 | 0xaaaac1081000 | 456 KiB | r-x r-- rw- | kod z pliku | /target/debug/nanshe-sample | mapowań: 3 |
| 0xaaaac1081000 | 0xaaaaf1a5a000 | 777.8 MiB | - | przerwa | nieużywany zakres adresów |  |
| 0xaaaaf1a5a000 | 0xaaaaf1a7b000 | 132 KiB | rw- | sterta | \[heap\] |  |
| 0xaaaaf1a7b000 | 0xffff80350000 | 85.3 TiB | - | przerwa | nieużywany zakres adresów |  |
| 0xffff80350000 | 0xffff80360000 | 64 KiB | rwx | ZNALEZISKO (wysokie) | pamięć anonimowa | &lt;&lt;&lt; RWX, X-PRIV, ENT-X (90 pkt) |
| 0xffff80360000 | 0xffff80502000 | 1.6 MiB | r-x --- r-- rw- | kod z pliku | /usr/lib/aarch64-linux-gnu/libc.so.6 | mapowań: 4 |
| 0xffff80502000 | 0xffff8050f000 | 52 KiB | rw- | pamięć anonimowa | pamięć anonimowa |  |
| 0xffff80510000 | 0xffff80541000 | 196 KiB | r-x --- r-- rw- | kod z pliku | /usr/lib/aarch64-linux-gnu/libgcc\_s.so.1 | mapowań: 4 |
| 0xffff8054b000 | 0xffff80572000 | 156 KiB | r-x | kod z pliku | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 |  |
| 0xffff80574000 | 0xffff80578000 | 16 KiB | r-x | ZNALEZISKO (wysokie) | pamięć anonimowa | &lt;&lt;&lt; X-PRIV, HDR (70 pkt) |
| 0xffff80578000 | 0xffff8057f000 | 28 KiB | --- rw- | pamięć anonimowa | pamięć anonimowa | mapowań: 3 |
| 0xffff8057f000 | 0xffff80581000 | 8 KiB | r-x | ZNALEZISKO (wysokie) | memfd:payload | &lt;&lt;&lt; MEMFD, ENT-X (70 pkt) |
| 0xffff80581000 | 0xffff80583000 | 8 KiB | rw- | pamięć anonimowa | pamięć anonimowa |  |
| 0xffff80583000 | 0xffff80587000 | 16 KiB | r-- | region jądra | \[vvar\] |  |
| 0xffff80587000 | 0xffff80589000 | 8 KiB | r-x | region jądra | \[vdso\] |  |
| 0xffff80589000 | 0xffff8058d000 | 16 KiB | r-- rw- | dane z pliku | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 | mapowań: 2 |
| 0xffff8058d000 | 0xffffcf95b000 | 1.2 GiB | - | przerwa | nieużywany zakres adresów |  |
| 0xffffcf95b000 | 0xffffcf97c000 | 132 KiB | rw- | stos | \[stack\] |  |

### Co oznaczają znaleziska w tym procesie

#### ENT-X + RWX + X-PRIV: zaszyfrowany lub spakowany kod tworzony w trakcie pracy

Regionów z tym zestawem cech: 1; najwyższy wynik: 90 pkt.

Region bez pliku, zapisywalny i wykonywalny, wypełniony danymi wyglądającymi na losowe. To najmocniejsze połączenie cech w tym raporcie.

- Łagodne wyjaśnienie: Programy chronione przed kopiowaniem i analizą (pakery, zabezpieczenia gier) rozpakowują swój kod w ten sposób.
- Łagodne wyjaśnienie: Rzadziej: środowisko JIT trzymające skompresowane dane obok kodu.
- Niepokojące wyjaśnienie: Zaszyfrowany ładunek, który zostanie odkodowany i uruchomiony w tym samym miejscu. Tak działają programy ładujące (stagery) i wiele narzędzi zdalnego sterowania.
- W tym procesie: Brak środowiska JIT w procesie zwiększa wagę tego znaleziska.

Podstawa techniczna. ENT-X: Entropia Shannona liczona dla stron 4 KiB w skali 0-8; próg 7,2 (wysoka) i 7,8 (bardzo wysoka). W kodzie z pliku pojedyncze strony powyżej progu mają obniżoną wagę. RWX: Mapowanie z prawami rwx w /proc/&lt;pid&gt;/maps (PROT\_READ, PROT\_WRITE i PROT\_EXEC jednocześnie). X-PRIV: Mapowanie wykonywalne bez ścieżki pliku w /proc/&lt;pid&gt;/maps (pamięć anonimowa), z wyłączeniem regionów jądra (\[vdso\] i podobnych).

Powiązane techniki MITRE ATT&amp;CK (orientacyjnie; znalezisko nie dowodzi użycia techniki): T1027 Obfuscated Files or Information, T1027.002 Software Packing, T1055 Process Injection, T1620 Reflective Code Loading.

#### HDR + X-PRIV: program załadowany do pamięci bez pliku

Regionów z tym zestawem cech: 1; najwyższy wynik: 70 pkt.

W wykonywalnej pamięci bez pliku leży nagłówek programu albo biblioteki. Ktoś załadował plik wykonywalny ręcznie, z pominięciem systemu.

- Łagodne wyjaśnienie: Niektóre programy zabezpieczające, emulatory i narzędzia deweloperskie ładują biblioteki z pamięci.
- Łagodne wyjaśnienie: Kopia własnego pliku trzymana do sprawdzania integralności.
- Niepokojące wyjaśnienie: Ładowanie refleksyjne: biblioteka albo program dostarczony przez sieć i uruchomiony bez zapisu na dysk. To typowa technika narzędzi zdalnego sterowania.

Podstawa techniczna. HDR: Nagłówek ELF (z poprawnym typem pliku), PE (sygnatury MZ i PE, niezerowe pole Machine, 1-96 sekcji) albo Mach-O; na początku strony w każdym regionie bez pliku poza niewykonywalnym stosem, pod dowolnym przesunięciem tylko w regionach wykonywalnych. X-PRIV: Mapowanie wykonywalne bez ścieżki pliku w /proc/&lt;pid&gt;/maps (pamięć anonimowa), z wyłączeniem regionów jądra (\[vdso\] i podobnych).

Powiązane techniki MITRE ATT&amp;CK (orientacyjnie; znalezisko nie dowodzi użycia techniki): T1055 Process Injection, T1620 Reflective Code Loading.

#### ENT-X + MEMFD: zaszyfrowany lub spakowany kod z pliku tylko w pamięci

Regionów z tym zestawem cech: 1; najwyższy wynik: 70 pkt.

Kod jest uruchamiany z pliku istniejącego wyłącznie w pamięci RAM, a jego zawartość wygląda na losową.

- Łagodne wyjaśnienie: Rzadkie. Niektóre środowiska uruchomieniowe i piaskownice używają memfd, ale ich kod nie wygląda na zaszyfrowany.
- Niepokojące wyjaśnienie: Program pobrany z sieci i uruchomiony bez zapisu na dysk, dodatkowo spakowany. To typowy obraz bezplikowego złośliwego oprogramowania na Linuksie.

Podstawa techniczna. ENT-X: Entropia Shannona liczona dla stron 4 KiB w skali 0-8; próg 7,2 (wysoka) i 7,8 (bardzo wysoka). W kodzie z pliku pojedyncze strony powyżej progu mają obniżoną wagę. MEMFD: Wykonywalne mapowanie obiektu utworzonego przez memfd\_create (wpis /memfd:&lt;nazwa&gt; w /proc/&lt;pid&gt;/maps).

Powiązane techniki MITRE ATT&amp;CK (orientacyjnie; znalezisko nie dowodzi użycia techniki): T1027 Obfuscated Files or Information, T1027.002 Software Packing, T1620 Reflective Code Loading.

#### Rozmiar i entropia regionów

Każdy punkt to jeden z 4 regionów ze znaleziskiem w tym procesie (także o wadze „info"). Punkt wysoko (entropia od 7,2) albo daleko od reszty to region odstający.

| Entropia \\ rozmiar | do 16 KiB | do 256 KiB | do 4 MiB | powyżej 4 MiB |
|---|---|---|---|---|
| bardzo wysoka (od 7,8) | 1 | 1 | 1 | - |
| wysoka (7,2-7,8) | - | - | - | - |
| średnia (5-7,2) | - | - | - | - |
| niska (poniżej 5) | 1 | - | - | - |

### Od pamięci do sieci

Regiony ze znaleziskami, proces i jego połączenia sieciowe z chwili skanu. Diagram pokazuje, że podejrzany kod i połączenie współistnieją w jednym procesie; nie dowodzi, że to kod z danego regionu otworzył połączenie.

| Region w pamięci | Proces | Sieć |
|---|---|---|
| 0xffff80350000 RWX, X-PRIV, ENT-X (90 pkt) | =&gt; 2050 nanshe-sample, root (uid 0) =&gt; | tcp 127.0.0.1:56108 -&gt; 127.0.0.1:42551 (ESTABLISHED) |
| 0xffff80574000 X-PRIV, HDR (70 pkt) |  | tcp 127.0.0.1:42551 -&gt; 127.0.0.1:56108 (ESTABLISHED) |
| 0xffff8057f000 MEMFD, ENT-X (70 pkt) |  | nasłuch tcp 127.0.0.1:42551 |

### Regiony ze znaleziskami

| Adres | Rozmiar | Prawa | Waga | Pkt | Entropia | Tagi | Źródło |
|---|---|---|---|---|---|---|---|
| 0xffff80350000 | 64 KiB | rwx | wysokie | 90 | 7.96 | RWX, X-PRIV, ENT-X | brak pliku |
| 0xffff80574000 | 16 KiB | r-x | wysokie | 70 | 4.06 | X-PRIV, HDR | brak pliku |
| 0xffff8057f000 | 8 KiB | r-x | wysokie | 70 | 7.95 | MEMFD, ENT-X | memfd:payload |

### Region 0xffff80350000 (wysokie, 90 pkt)

W skrócie: zaszyfrowany lub spakowany kod tworzony w trakcie pracy. Wyjaśnienie jest wyżej, w części „Co oznaczają znaleziska w tym procesie".

- RWX: region jednocześnie zapisywalny i wykonywalny
- X-PRIV: wykonywalna pamięć prywatna/anonimowa bez pliku źródłowego
- ENT-X: bardzo wysoka entropia w regionie wykonywalnym: max 7.96, stron powyżej progu: 16 z 16

| Pole | Wartość |
|---|---|
| Zakres adresów | 0xffff80350000 - 0xffff80360000 (64 KiB, odczytano 64 KiB) |
| Rodzaj i źródło | pamięć prywatna; bez pliku źródłowego |
| Entropia | maksymalna 7.96, średnia 7.95 (skala 0-8); stron zerowych: 0 |
| SHA-256 zawartości | 2e043edf3a68f7b9549ebdbc0770ec807dd4eaaa83f3aea3eb459103b1c3566e |
| Sąsiad poniżej | 0xaaaaf1a5a000 rw- \[heap\] (odstęp 85.3 TiB) |
| Sąsiad powyżej | 0xffff80360000 r-x /usr/lib/aarch64-linux-gnu/libc.so.6 (przylega) |

#### Profil entropii regionu

```text
0xffff80350000 ████████████████ 0xffff80360000
```

Entropia odcinków (0-8): najniższa 8.0, najwyższa 8.0; 16 odcinków po 4 KiB.

#### Podgląd bajtów od 0xffff80350000

```text
0xffff80350000  00 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41  ....LoadLibraryA
0xffff80350010  00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00  .GetProcAddress.
0xffff80350020  56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 ac a8 07  VirtualAlloc....
0xffff80350030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffff80350040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffff80350050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffff80350060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffff80350070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Ciągi tekstowe w regionie

- LoadLibraryA
- GetProcAddress
- VirtualAlloc
- no}P=NHfQr

#### Jak sprawdzić ten region

- Zobacz, czym jest ten region w mapie pamięci procesu: grep -n ffff80350000 /proc/2050/maps
- Zapisz zawartość regionu do pliku (wymaga gdb, zatrzymuje proces na chwilę): gdb -p 2050 -batch -ex "dump memory /tmp/region\_ffff80350000.bin 0xffff80350000 0xffff80360000"
- Sprawdź, kto uruchomił proces i z jakim poleceniem: ps -o pid,ppid,user,lstart,cmd -p 2050
- Sprawdź, czy program ma środowisko JIT: grep -E "libjvm\|libnode\|libv8\|libmono\|libcoreclr\|libjs" /proc/2050/maps
- Po zapisaniu regionu porównaj jego skrót z bazami znanych plików: sha256sum /tmp/region\_ffff80350000.bin

### Region 0xffff80574000 (wysokie, 70 pkt)

W skrócie: program załadowany do pamięci bez pliku. Wyjaśnienie jest wyżej, w części „Co oznaczają znaleziska w tym procesie".

- X-PRIV: wykonywalna pamięć prywatna/anonimowa bez pliku źródłowego
- HDR: nagłówek ELF w regionie bez pliku źródłowego

| Pole | Wartość |
|---|---|
| Zakres adresów | 0xffff80574000 - 0xffff80578000 (16 KiB, odczytano 16 KiB) |
| Rodzaj i źródło | pamięć prywatna; bez pliku źródłowego |
| Entropia | maksymalna 4.06, średnia 2.85 (skala 0-8); stron zerowych: 0 |
| SHA-256 zawartości | 4063392c86a10c8e77471f136ce93dc116b19f38a46082e4b8b5078cc17fcb1b |
| Sąsiad poniżej | 0xffff8054b000 r-x /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 (odstęp 8 KiB) |
| Sąsiad powyżej | 0xffff80578000 --- pamięć anonimowa (przylega) |

#### Profil entropii regionu

```text
0xffff80574000 ▃▅▃▃ 0xffff80578000
```

Entropia odcinków (0-8): najniższa 2.0, najwyższa 4.1; 4 odcinków po 4 KiB.

#### Nagłówek obrazu odczytany z pamięci

| Pole | Wartość |
|---|---|
| Format | ELF 64-bitowy, AArch64 |
| Typ | biblioteka lub program PIE (DYN) |
| Punkt wejścia | 0xb180 |
| Nagłówki programu / sekcji | 10 / 41 |

#### Podgląd bajtów od 0xffff80574000

```text
0xffff80574000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
0xffff80574010  03 00 b7 00 01 00 00 00 80 b1 00 00 00 00 00 00  ................
0xffff80574020  40 00 00 00 00 00 00 00 a0 f3 50 00 00 00 00 00  @.........P.....
0xffff80574030  00 00 00 00 40 00 38 00 0a 00 40 00 29 00 28 00  ....@.8...@.).(.
0xffff80574040  06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00  ........@.......
0xffff80574050  40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  @.......@.......
0xffff80574060  30 02 00 00 00 00 00 00 30 02 00 00 00 00 00 00  0.......0.......
0xffff80574070  08 00 00 00 00 00 00 00 03 00 00 00 04 00 00 00  ................
```

#### Ciągi tekstowe w regionie

- /lib/ld-linux-aarch64.so.1
- \_ITM\_deregisterTMCloneTable
- \_\_gmon\_start\_\_
- \_ITM\_registerTMCloneTable
- \_Unwind\_Resume
- \_Unwind\_Backtrace
- \_Unwind\_GetLanguageSpecificData
- \_Unwind\_GetIPInfo
- \_Unwind\_GetDataRelBase
- \_Unwind\_GetRegionStart
- \_Unwind\_SetIP
- \_Unwind\_GetIP
- \_Unwind\_DeleteException
- \_Unwind\_RaiseException
- \_Unwind\_SetGR
- ... i 25 kolejnych w pliku wyniku

#### Jak sprawdzić ten region

- Zobacz, czym jest ten region w mapie pamięci procesu: grep -n ffff80574000 /proc/2050/maps
- Zapisz zawartość regionu do pliku (wymaga gdb, zatrzymuje proces na chwilę): gdb -p 2050 -batch -ex "dump memory /tmp/region\_ffff80574000.bin 0xffff80574000 0xffff80578000"
- Sprawdź, kto uruchomił proces i z jakim poleceniem: ps -o pid,ppid,user,lstart,cmd -p 2050
- Po zapisaniu regionu sprawdź, co to za plik wykonywalny: file /tmp/region\_ffff80574000.bin oraz readelf -h /tmp/region\_ffff80574000.bin

### Region 0xffff8057f000 (wysokie, 70 pkt)

W skrócie: zaszyfrowany lub spakowany kod z pliku tylko w pamięci. Wyjaśnienie jest wyżej, w części „Co oznaczają znaleziska w tym procesie".

- MEMFD: wykonywalne mapowanie memfd:payload
- ENT-X: bardzo wysoka entropia w regionie wykonywalnym: max 7.95, stron powyżej progu: 2 z 2

| Pole | Wartość |
|---|---|
| Zakres adresów | 0xffff8057f000 - 0xffff80581000 (8 KiB, odczytano 8 KiB) |
| Rodzaj i źródło | mapowanie; memfd:payload |
| Entropia | maksymalna 7.95, średnia 7.95 (skala 0-8); stron zerowych: 0 |
| SHA-256 zawartości | b511e7d5ceda23c4c9555f760682f3089d78baf592641fdce4ceac79f973cc94 |
| Sąsiad poniżej | 0xffff8057d000 rw- pamięć anonimowa (przylega) |
| Sąsiad powyżej | 0xffff80581000 rw- pamięć anonimowa (przylega) |

#### Profil entropii regionu

```text
0xffff8057f000 ██ 0xffff80581000
```

Entropia odcinków (0-8): najniższa 8.0, najwyższa 8.0; 2 odcinków po 4 KiB.

#### Podgląd bajtów od 0xffff8057f000

```text
0xffff8057f000  ea 1c 58 d8 97 be 9d 50 12 c9 a7 6e 43 b5 af 76  ..X....P...nC..v
0xffff8057f010  c2 a0 72 7d 39 91 3d 65 90 d8 4f a3 7f c7 4f 6f  ..r}9.=e..O...Oo
0xffff8057f020  09 25 49 a6 b7 01 0d a5 40 3e 28 89 cd ac a8 07  .%I.....@>(.....
0xffff8057f030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffff8057f040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffff8057f050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffff8057f060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffff8057f070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Ciągi tekstowe w regionie

- no}P=NHfQr

#### Jak sprawdzić ten region

- Zobacz, czym jest ten region w mapie pamięci procesu: grep -n ffff8057f000 /proc/2050/maps
- Zapisz zawartość regionu do pliku (wymaga gdb, zatrzymuje proces na chwilę): gdb -p 2050 -batch -ex "dump memory /tmp/region\_ffff8057f000.bin 0xffff8057f000 0xffff80581000"
- Sprawdź, kto uruchomił proces i z jakim poleceniem: ps -o pid,ppid,user,lstart,cmd -p 2050
- Znajdź deskryptor pliku memfd i skopiuj cały plik: ls -l /proc/2050/fd \| grep memfd, potem cp /proc/2050/fd/NUMER /tmp/memfd\_2050.bin
- Po zapisaniu regionu porównaj jego skrót z bazami znanych plików: sha256sum /tmp/region\_ffff8057f000.bin

## 5. Czego ten raport nie obejmuje

- 1 regionów ze znaleziskami poniżej poziomu „podejrzane" pominięto; są w pliku wyniku.
- Podgląd bajtów w raporcie to pierwsze 128 bajtów znaleziska; pełne 256 bajtów jest w pliku wyniku (JSON). Pełnego zrzutu regionu narzędzie nie robi.
- Kontekst systemowy to stan z chwili skanu: połączenia zamknięte wcześniej, zakończone procesy potomne i usunięte pliki nie są widoczne. Historii (logów, dziennika audytu) raport nie obejmuje.
- Skan obejmuje pamięć procesów w chwili skanu; nie obejmuje jądra, treści plików na dysku ani zawartości ruchu sieciowego.
- Plik wyniku zawiera skróty SHA-256 5 plików (programy wszystkich procesów i pliki zmapowane w procesach ze znaleziskami); raport pokazuje tylko część. Raport nie sprawdza skrótów w zewnętrznych bazach.
- Znalezisko THR-PRIV opiera się na adresie startu wątku (Windows) albo na miejscu wywołania jądra przez wątki czekające (Linux); wątek, który w chwili skanu coś liczył, nie jest na Linuksie oceniany. IMG-MOD mówi, że kod z pliku zmieniono w pamięci, ale nie pokazuje różnic.
- Brak interpretacji LLM (raport wyłącznie z danych deterministycznych).

## 6. Słowniczek

| Pojęcie | Znaczenie |
|---|---|
| proces | uruchomiony program razem z jego pamięcią; ma numer PID |
| PID | numer nadany procesowi przez system; po zakończeniu procesu numer może zostać użyty ponownie |
| region pamięci | ciągły kawałek pamięci procesu o jednakowych uprawnieniach, np. kod jednej biblioteki albo stos |
| uprawnienia r, w, x | r: wolno czytać, w: wolno zapisywać, x: wolno uruchamiać jako kod; zapis rwx oznacza wszystkie trzy naraz |
| pamięć anonimowa (prywatna) | pamięć, która nie pochodzi z pliku; program dostał ją od systemu pustą i sam ją wypełnił |
| mapowanie pliku | plik z dysku widoczny bezpośrednio w pamięci procesu; tak ładowane są programy i biblioteki |
| entropia | miara losowości danych w skali 0-8; tekst ma około 4-5, zwykły kod 5-6,5, dane zaszyfrowane i spakowane powyżej 7,5 |
| JIT (kompilacja w locie) | tworzenie kodu maszynowego w trakcie pracy programu; robią to .NET, Java i silniki JavaScript |
| shellcode | krótki samodzielny kod maszynowy wstrzykiwany do pamięci, zwykle po to, by pobrać i uruchomić właściwe narzędzie atakującego |
| ładowanie refleksyjne | załadowanie biblioteki albo programu z pamięci, bez pliku na dysku i bez udziału systemu |
| paker | narzędzie, które kompresuje albo szyfruje program i dokleja kod rozpakowujący go przy starcie |
| wstrzyknięcie kodu | umieszczenie i uruchomienie własnego kodu w pamięci cudzego procesu |
| SHA-256 | skrót (odcisk) pliku; ten sam plik ma zawsze ten sam skrót, więc można go porównać z bazami znanych plików |
| stos i sterta | obszary pamięci na dane robocze programu; zwykle nie powinny być wykonywalne |
| wynik częściowy | skan nie przeczytał wszystkiego, np. system odmówił dostępu do części procesów; brak znalezisk w nieprzeczytanej części niczego nie dowodzi |
| lista dozwolonych | znane środowiska JIT, dla których narzędzie obniża wagę typowych dla nich znalezisk; znaleziska pozostają w wyniku |
| wątek | jedna z równoległych nitek wykonywania w procesie; każdy proces ma co najmniej jeden |
| hook (podpięcie) | nadpisanie początku funkcji tak, by najpierw wykonał się cudzy kod; robią to programy zabezpieczające i złośliwe oprogramowanie |
| MITRE ATT&amp;CK | publiczny katalog technik stosowanych przez atakujących; identyfikatory w rodzaju T1055 pozwalają jednoznacznie nazwać technikę |
| priorytet P1, P2, P3 | kolejność weryfikacji procesów w tym raporcie: P1 w pierwszej kolejności, P3 przy okazji; wynika z rodzaju znalezisk i kontekstu procesu, nie jest oceną szkodliwości |
| /proc | katalog, w którym Linux udostępnia informacje o działających procesach; narzędzie tylko z niego czyta |
| memfd | plik utworzony w pamięci RAM wywołaniem memfd\_create; nie ma go na dysku |
| ELF | format plików wykonywalnych i bibliotek na Linuksie; zaczyna się od bajtów 7f 45 4c 46 |
| vdso | mały fragment kodu jądra wstawiany do każdego procesu; jest normalny |
| uprawnienia (capabilities) | części uprawnień administratora nadawane procesowi osobno; pole CapEff pokazuje aktywne |
| seccomp | filtr ograniczający wywołania systemowe procesu; włączony oznacza program uruchomiony w piaskownicy |
| LD\_PRELOAD | zmienna, która każe załadować wskazaną bibliotekę przed wszystkimi innymi; bywa używana do podmiany funkcji |

Objaśnienia w tym raporcie pochodzą z bazy wiedzy narzędzia (wersja 2026-11-22, system linux). Opisują typowe przypadki; nie zastępują sprawdzenia konkretnego procesu.

## 7. Legenda

| Tag | Znaczenie |
|---|---|
| ENT-X | kod wyglądający na zaszyfrowany: Zawartość regionu wykonywalnego ma rozkład bliski losowemu. Kod maszynowy ma wyraźną strukturę i znacznie niższą entropię. |
| HDR | cały program schowany w pamięci: W pamięci bez pliku źródłowego znajduje się nagłówek pliku wykonywalnego albo biblioteki. Oznacza to, że obraz programu został załadowany z pominięciem mechanizmu ładowania systemu. |
| MEMFD | kod z pliku istniejącego tylko w pamięci: Proces wykonuje kod z pliku utworzonego wywołaniem memfd\_create. Taki plik istnieje wyłącznie w pamięci RAM i nie jest zapisywany na dysku. |
| RWX | pamięć zapisywalna i wykonywalna naraz: Region pamięci jest jednocześnie zapisywalny i wykonywalny. W typowym programie kod jest dostępny wyłącznie do odczytu i wykonania. |
| X-PRIV | kod bez pliku na dysku: Proces zawiera wykonywalny kod, który nie pochodzi z żadnego pliku. Kod powstał w pamięci w trakcie pracy procesu. |

Waga regionu wynika z sumy punktów jego znalezisk: poniżej 30 „info", 30-59 „podejrzane", od 60 „wysokie".

---

Triage, nie werdykt.
