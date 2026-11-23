# Nanshe: raport triage pamięci

host 9a65a92d132b \| skan 2026-11-22T09:50:24Z

| Pole | Wartość |
|---|---|
| Host | 9a65a92d132b |
| Czas skanu | 2026-11-22T09:50:24Z |
| Narzędzie | nanshe 0.1.0 |
| Procesy | 1 przeskanowanych, 1 ze znaleziskami od poziomu „podejrzane" |
| Znaleziska | 8 |
| Kompletność | pełny |
| System hosta | Debian GNU/Linux 12 (bookworm), jądro/wersja 7.1.10-200.fc44.aarch64 |
| Start systemu | 2026-11-13T15:10:15Z |
| Skan wykonał | root (uid 0) |
| Klasyfikacja | Poufne: dokument zawiera dane z badanej stacji; udostępniać wyłącznie osobom prowadzącym analizę |
| Plik wyniku | stacja.json |
| SHA-256 wyniku | 2d9e10cdc1015ac1c74f51bc9057de34bf3ed771a56570d4b995e1009960547e |

> To wynik triage, nie werdykt. Znaleziska wskazują miejsca warte ręcznej analizy; ich brak nie dowodzi, że proces jest czysty. Nazwy procesów, ścieżki i opisy pochodzą z badanego systemu i mogą być kontrolowane przez atakującego.

> Raport zawiera dane z badanej stacji bez filtrowania: wiersze poleceń, ścieżki, adresy sieciowe, bajty i ciągi tekstowe z pamięci. Mogą wśród nich być hasła i klucze. Traktuj ten dokument jak materiał dowodowy.

## 1\. Podsumowanie dla decydenta

Ocena ogólna. Co najmniej jeden proces ma cechy, których nie tłumaczy znane środowisko uruchomieniowe. Wymaga weryfikacji w pierwszej kolejności, zanim na stacji zostaną wprowadzone zmiany.

| Pole | Wartość |
|---|---|
| Zakres | 1 procesów na hoście 9a65a92d132b, stan z 2026-11-22T09:50:24Z |
| Kompletność | pełna dla procesów dostępnych skanerowi |
| Procesy do weryfikacji | 1 (P1: 1, P2: 0, P3: 0) od wagi „podejrzane" |

#### Najważniejsze procesy

| Priorytet | Proces | Dlaczego |
|---|---|---|
| P1 | 5 nanshe-sample | Występuje cecha, której nie tłumaczy środowisko kompilujące kod w locie: HDR (cały program schowany w pamięci), MEMFD (kod z pliku istniejącego tylko w pamięci). |

#### Zalecane działania

- Dla procesów P1: zabezpieczyć zrzut pamięci procesu i nie restartować stacji przed zakończeniem weryfikacji; pamięć jest jedynym nośnikiem tych śladów.

Ograniczenia oceny: przegląd dotyczy stanu pamięci z jednej chwili, nie obejmuje procesów chronionych przez system ani pamięci jądra i opiera się na cechach, które mają też przyczyny łagodne. Szczegóły są w rozdziale „Czego ten raport nie obejmuje".

## 2\. Interpretacja LLM: parametry

> Sekcje oznaczone „Interpretacja LLM" są niedeterministyczne i wymagają weryfikacji przez analityka. Model nie zmienia punktacji ani wagi znalezisk; widzi wyłącznie dane opisane poziomem danych poniżej.

| Pole | Wartość |
|---|---|
| Model | anthropic/claude-opus-5.5 (backend: nous) |
| Gdzie przetwarzano | chmura, poza LAB; wysłano same metadane regionów (poziom d0: bez nazwy hosta, ścieżek użytkowników, nazw procesów i ciągów z pamięci), więc nie było wartości do podmiany |
| Poziom danych | d0: same metadane |
| Próbkowanie | domyślne modelu (wynik może się różnić między przebiegami) |
| Wersja promptu | 2026-11-22.3 |
| Zapytania | 4 (z pamięci podręcznej: 0), tokeny: 7985 wejścia, 3404 wyjścia |
| Czas interpretacji | 2026-11-22T09:50:37Z |

## 3\. Jak czytać ten raport

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

## 4\. Przegląd procesów

| Priorytet | PID | Proces | Waga | Regiony | Maks. pkt | Tagi |
|---|---|---|---|---|---|---|
| P1 | 5 | nanshe-sample | wysokie | 3 | 90 | ENT-X, HDR, MEMFD, RWX, X-PRIV |

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
| 5 nanshe-sample | 2 (wysokie) | 2 (wysokie) | 1 (wysokie) | 1 (wysokie) | 1 (wysokie) |

## 5\. Proces 5: nanshe-sample

| Pole | Wartość |
|---|---|
| System | linux/aarch64 |
| Plik programu | /target/release/nanshe-sample |
| Regiony | 26 łącznie, 0 nieodczytanych, przeskanowano 2.6 MiB |
| Wiersz poleceń | /target/release/nanshe-sample ctx 120 |
| Użytkownik | root (uid 0) |
| Uruchomiony | 2026-11-22T09:50:22Z |
| Proces nadrzędny | 1 (sh) |
| Katalog roboczy | /target/demo |
| Wątki | 1 |
| Plik programu: metadane | 388 KiB, zmieniony 2026-11-22T09:49:00Z, właściciel root (uid 0), tryb 0755 |
| Plik programu: SHA-256 | c9cb5e4ccf027cefbbc9f65b50ed5004f7407894263247862d9811b7a891839f |
| uprawnienia efektywne (CapEff) | 00000000800c05fb |
| seccomp | filtr |
| no\_new\_privs | 0 |

### Ocena

| Pole | Wartość |
|---|---|
| Priorytet weryfikacji | P1: w pierwszej kolejności |
| Uzasadnienie | Występuje cecha, której nie tłumaczy środowisko kompilujące kod w locie: HDR (cały program schowany w pamięci), MEMFD (kod z pliku istniejącego tylko w pamięci). Plik programu leży poza katalogami systemowymi. Proces działa z wysokimi uprawnieniami, więc przejęcie go oznaczałoby kontrolę nad stacją. Proces ma w chwili skanu połączenia z adresami zdalnymi. |
| Pierwszy krok | Zabezpieczyć pełny zrzut pamięci procesu 5 przed jakąkolwiek zmianą na stacji, a następnie wykonać kroki z części „Jak sprawdzić ten region" dla regionów o najwyższym wyniku. |

### Co to za program

Program o nazwie nanshe-sample to zwykle: Program testowy narzędzia Nanshe. Celowo tworzy w pamięci układy, których szukają detektory; niczego z nich nie uruchamia.

- Nazwę procesu program może ustawić sam, więc powyższe opiera się na nazwie tylko jako na wskazówce.

#### Co oznaczają cechy procesu

- uprawnienia efektywne (CapEff) = 00000000800c05fb: 0000000000000000 oznacza brak dodatkowych uprawnień; same jedynki szesnastkowe (np. 000001ffffffffff) to pełne uprawnienia administratora
- seccomp = filtr: "filtr" oznacza program w piaskownicy, co ogranicza skutki ewentualnego przejęcia
- no\_new\_privs = 0: 1 oznacza, że program i jego potomkowie nie mogą zdobyć wyższych uprawnień

### Drzewo procesów

- 1 sh: sh -c rm -rf /target/demo &amp;&amp; mkdir -p /target/demo &amp;&amp; cd /target/demo &amp;&amp; (/target/release/nanshe-sample ctx 12
  - => 5 nanshe-sample: /target/release/nanshe-sample ctx 120 (badany proces)
    - 7 nanshe-sample: /target/release/nanshe-sample clean 600

### Sieć

| Protokół | Adres lokalny | Adres zdalny | Stan |
|---|---|---|---|
| tcp | 127.0.0.1:35595 | - | LISTEN |
| tcp | 127.0.0.1:48086 | 127.0.0.1:35595 | ESTABLISHED |
| tcp | 127.0.0.1:35595 | 127.0.0.1:48086 | ESTABLISHED |

### Otwarte pliki i uchwyty

Wszystkich deskryptorów lub uchwytów: 9. Zapisane z nazwą: 9 (memfd: 1, plik: 3, gniazdo: 3, potok: 1, urządzenie: 1).

| Nr | Rodzaj | Obiekt | Uwagi |
|---|---|---|---|
| 0x3 | memfd | memfd:payload | tylko w pamięci |
| 0x1 | plik | /target/demo/s.out | poza katalogami systemowymi |
| 0x7 | plik | /tmp/ns-ctx-5.dat | katalog tymczasowy |
| 0x8 | plik | /tmp/ns-ctx-5.gone | usunięty z dysku, katalog tymczasowy |

### Pliki zmapowane do pamięci

| Plik | Rozmiar | Kod | Uwagi i opis |
|---|---|---|---|
| /target/release/nanshe-sample | 372 KiB | tak | plik programu, poza katalogami systemowymi |
| memfd:payload | 8 KiB | tak | tylko w pamięci; plik istniejący tylko w pamięci RAM; nie ma go na dysku |
| /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 | 172 KiB | tak | program ładujący biblioteki przy starcie; normalny w każdym procesie |
| /usr/lib/aarch64-linux-gnu/libc.so.6 | 1.6 MiB | tak | podstawowa biblioteka systemowa; ma ją prawie każdy program |
| /usr/lib/aarch64-linux-gnu/libgcc\_s.so.1 | 196 KiB | tak | biblioteka pomocnicza kompilatora; normalna |

### Mapa przestrzeni adresowej

Wszystkie 26 regionów procesu od najniższego adresu. Sąsiednie mapowania tego samego pliku są połączone w jeden wiersz, długie ciągi zwykłych mapowań zwinięte, a duże nieużywane zakresy pokazane jako przerwy. Wysokość bloku rośnie z rozmiarem (skala logarytmiczna).

| Początek | Koniec | Rozmiar | Prawa | Rodzaj | Zawartość | Uwagi |
|---|---|---|---|---|---|---|
| 0xaaaae93f0000 | 0xaaaae9461000 | 372 KiB | r-x r-- rw- | kod z pliku | /target/release/nanshe-sample | mapowań: 3 |
| 0xaaaae9461000 | 0xaaab11cbb000 | 648.4 MiB | - | przerwa | nieużywany zakres adresów |  |
| 0xaaab11cbb000 | 0xaaab11cdc000 | 132 KiB | rw- | sterta | \[heap\] |  |
| 0xaaab11cdc000 | 0xffff9c120000 | 85.3 TiB | - | przerwa | nieużywany zakres adresów |  |
| 0xffff9c120000 | 0xffff9c130000 | 64 KiB | rwx | ZNALEZISKO (wysokie) | pamięć anonimowa | &lt;&lt;&lt; RWX, X-PRIV, ENT-X (90 pkt) |
| 0xffff9c130000 | 0xffff9c2d2000 | 1.6 MiB | r-x --- r-- rw- | kod z pliku | /usr/lib/aarch64-linux-gnu/libc.so.6 | mapowań: 4 |
| 0xffff9c2d2000 | 0xffff9c2df000 | 52 KiB | rw- | pamięć anonimowa | pamięć anonimowa |  |
| 0xffff9c2e0000 | 0xffff9c311000 | 196 KiB | r-x --- r-- rw- | kod z pliku | /usr/lib/aarch64-linux-gnu/libgcc\_s.so.1 | mapowań: 4 |
| 0xffff9c31f000 | 0xffff9c346000 | 156 KiB | r-x | kod z pliku | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 |  |
| 0xffff9c348000 | 0xffff9c34c000 | 16 KiB | r-x | ZNALEZISKO (wysokie) | pamięć anonimowa | &lt;&lt;&lt; X-PRIV, HDR (70 pkt) |
| 0xffff9c34c000 | 0xffff9c353000 | 28 KiB | --- rw- | pamięć anonimowa | pamięć anonimowa | mapowań: 3 |
| 0xffff9c353000 | 0xffff9c355000 | 8 KiB | r-x | ZNALEZISKO (wysokie) | memfd:payload | &lt;&lt;&lt; MEMFD, ENT-X (70 pkt) |
| 0xffff9c355000 | 0xffff9c357000 | 8 KiB | rw- | pamięć anonimowa | pamięć anonimowa |  |
| 0xffff9c357000 | 0xffff9c35b000 | 16 KiB | r-- | region jądra | \[vvar\] |  |
| 0xffff9c35b000 | 0xffff9c35d000 | 8 KiB | r-x | region jądra | \[vdso\] |  |
| 0xffff9c35d000 | 0xffff9c361000 | 16 KiB | r-- rw- | dane z pliku | /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 | mapowań: 2 |
| 0xffff9c361000 | 0xffffd84c2000 | 961.4 MiB | - | przerwa | nieużywany zakres adresów |  |
| 0xffffd84c2000 | 0xffffd84e3000 | 132 KiB | rw- | stos | \[stack\] |  |

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
| 0xffff9c120000 RWX, X-PRIV, ENT-X (90 pkt) | =&gt; 5 nanshe-sample, root (uid 0) =&gt; | tcp 127.0.0.1:48086 -&gt; 127.0.0.1:35595 (ESTABLISHED) |
| 0xffff9c348000 X-PRIV, HDR (70 pkt) |  | tcp 127.0.0.1:35595 -&gt; 127.0.0.1:48086 (ESTABLISHED) |
| 0xffff9c353000 MEMFD, ENT-X (70 pkt) |  | nasłuch tcp 127.0.0.1:35595 |

### Regiony ze znaleziskami

| Adres | Rozmiar | Prawa | Waga | Pkt | Entropia | Tagi | Źródło |
|---|---|---|---|---|---|---|---|
| 0xffff9c120000 | 64 KiB | rwx | wysokie | 90 | 7.96 | RWX, X-PRIV, ENT-X | brak pliku |
| 0xffff9c348000 | 16 KiB | r-x | wysokie | 70 | 4.09 | X-PRIV, HDR | brak pliku |
| 0xffff9c353000 | 8 KiB | r-x | wysokie | 70 | 7.95 | MEMFD, ENT-X | memfd:payload |

### Region 0xffff9c120000 (wysokie, 90 pkt)

W skrócie: zaszyfrowany lub spakowany kod tworzony w trakcie pracy. Wyjaśnienie jest wyżej, w części „Co oznaczają znaleziska w tym procesie".

- RWX: region jednocześnie zapisywalny i wykonywalny
- X-PRIV: wykonywalna pamięć prywatna/anonimowa bez pliku źródłowego
- ENT-X: bardzo wysoka entropia w regionie wykonywalnym: max 7.96, stron powyżej progu: 16 z 16

| Pole | Wartość |
|---|---|
| Zakres adresów | 0xffff9c120000 - 0xffff9c130000 (64 KiB, odczytano 64 KiB) |
| Rodzaj i źródło | pamięć prywatna; bez pliku źródłowego |
| Entropia | maksymalna 7.96, średnia 7.95 (skala 0-8); stron zerowych: 0 |
| Sąsiad poniżej | 0xaaab11cbb000 rw- \[heap\] (odstęp 85.3 TiB) |
| Sąsiad powyżej | 0xffff9c130000 r-x /usr/lib/aarch64-linux-gnu/libc.so.6 (przylega) |

#### Profil entropii regionu

```text
0xffff9c120000 ████████████████ 0xffff9c130000
```

Entropia odcinków (0-8): najniższa 8.0, najwyższa 8.0; 16 odcinków po 4 KiB.

#### Podgląd bajtów od 0xffff9c120000

```text
0xffff9c120000  00 00 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 41  ....LoadLibraryA
0xffff9c120010  00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00  .GetProcAddress.
0xffff9c120020  56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 ac a8 07  VirtualAlloc....
0xffff9c120030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffff9c120040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffff9c120050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffff9c120060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffff9c120070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Ciągi tekstowe w regionie

- LoadLibraryA
- GetProcAddress
- VirtualAlloc
- no}P=NHfQr

#### Jak sprawdzić ten region

- Zobacz, czym jest ten region w mapie pamięci procesu: grep -n ffff9c120000 /proc/5/maps
- Zapisz zawartość regionu do pliku (wymaga gdb, zatrzymuje proces na chwilę): gdb -p 5 -batch -ex "dump memory /tmp/region\_ffff9c120000.bin 0xffff9c120000 0xffff9c130000"
- Sprawdź, kto uruchomił proces i z jakim poleceniem: ps -o pid,ppid,user,lstart,cmd -p 5
- Sprawdź, czy program ma środowisko JIT: grep -E "libjvm\|libnode\|libv8\|libmono\|libcoreclr\|libjs" /proc/5/maps
- Po zapisaniu regionu porównaj jego skrót z bazami znanych plików: sha256sum /tmp/region\_ffff9c120000.bin

#### Interpretacja LLM (do weryfikacji)

| Nr | Hipoteza | Pewność | Dowody (tagi) |
|---|---|---|---|
| 1 | packer (kod spakowany lub zaszyfrowany) | ocena | ENT-X, RWX, X-PRIV |
| 2 | shellcode-stager (shellcode lub etap ładujący) | niepotwierdzone | RWX, X-PRIV, ENT-X |
| 3 | jit (kompilacja JIT) | niepotwierdzone | RWX, X-PRIV |

- Hipoteza 1, za: Bardzo wysoka entropia (max 7,96, średnia 7,95) w całym regionie wykonywalnym jest typowa dla spakowanego lub zaszyfrowanego kodu.
- Hipoteza 1, za: Prawa RWX w prywatnej pamięci bez pliku źródłowego pasują do stuba, który rozpakowuje kod w miejscu.
- Hipoteza 1, przeciw: Entropia bliska 8 w całym regionie wskazuje raczej na dane zaszyfrowane lub skompresowane niż na już rozpakowany kod wykonywalny.
- Hipoteza 1, przeciw: Nie znaleziono nagłówka obrazu (HDR), więc nie widać rozpakowanego modułu.

- Hipoteza 2, za: Anonimowy region RWX o rozmiarze 64 KiB bez pliku źródłowego to typowe miejsce na zaszyfrowany ładunek stagera.
- Hipoteza 2, za: Brak stron zerowych i równomierna wysoka entropia pasują do zaszyfrowanego ładunku drugiego etapu.
- Hipoteza 2, przeciw: Dane nie pokazują wątków, wywołań ani kodu dekodera, które potwierdzałyby działanie stagera.

- Hipoteza 3, za: Silniki JIT na Linuksie aarch64 również alokują anonimową pamięć RWX.
- Hipoteza 3, przeciw: Kod generowany przez JIT ma zwykle niższą entropię niż 7,95, więc ta wartość słabo pasuje do JIT.
- Hipoteza 3, przeciw: Nie podano nazwy procesu ani etykiety regionu, które wskazywałyby na środowisko JIT.

Podsumowanie modelu: Prywatny, anonimowy region RWX o rozmiarze 64 KiB ma niemal maksymalną entropię, co najbardziej pasuje do spakowanego lub zaszyfrowanego kodu albo ładunku. Wymagana jest ręczna analiza zawartości i kontekstu procesu, ponieważ JIT jest mało prawdopodobny, ale nie został wykluczony.

### Region 0xffff9c348000 (wysokie, 70 pkt)

W skrócie: program załadowany do pamięci bez pliku. Wyjaśnienie jest wyżej, w części „Co oznaczają znaleziska w tym procesie".

- X-PRIV: wykonywalna pamięć prywatna/anonimowa bez pliku źródłowego
- HDR: nagłówek ELF w regionie bez pliku źródłowego

| Pole | Wartość |
|---|---|
| Zakres adresów | 0xffff9c348000 - 0xffff9c34c000 (16 KiB, odczytano 16 KiB) |
| Rodzaj i źródło | pamięć prywatna; bez pliku źródłowego |
| Entropia | maksymalna 4.09, średnia 2.81 (skala 0-8); stron zerowych: 0 |
| Sąsiad poniżej | 0xffff9c31f000 r-x /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 (odstęp 8 KiB) |
| Sąsiad powyżej | 0xffff9c34c000 --- pamięć anonimowa (przylega) |

#### Profil entropii regionu

```text
0xffff9c348000 ▃▅▃▃ 0xffff9c34c000
```

Entropia odcinków (0-8): najniższa 2.0, najwyższa 4.1; 4 odcinków po 4 KiB.

#### Nagłówek obrazu odczytany z pamięci

| Pole | Wartość |
|---|---|
| Format | ELF 64-bitowy, AArch64 |
| Typ | biblioteka lub program PIE (DYN) |
| Punkt wejścia | 0xa380 |
| Nagłówki programu / sekcji | 10 / 30 |

#### Podgląd bajtów od 0xffff9c348000

```text
0xffff9c348000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
0xffff9c348010  03 00 b7 00 01 00 00 00 80 a3 00 00 00 00 00 00  ................
0xffff9c348020  40 00 00 00 00 00 00 00 c8 0b 06 00 00 00 00 00  @...............
0xffff9c348030  00 00 00 00 40 00 38 00 0a 00 40 00 1e 00 1d 00  ....@.8...@.....
0xffff9c348040  06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00  ........@.......
0xffff9c348050  40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  @.......@.......
0xffff9c348060  30 02 00 00 00 00 00 00 30 02 00 00 00 00 00 00  0.......0.......
0xffff9c348070  08 00 00 00 00 00 00 00 03 00 00 00 04 00 00 00  ................
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

- Zobacz, czym jest ten region w mapie pamięci procesu: grep -n ffff9c348000 /proc/5/maps
- Zapisz zawartość regionu do pliku (wymaga gdb, zatrzymuje proces na chwilę): gdb -p 5 -batch -ex "dump memory /tmp/region\_ffff9c348000.bin 0xffff9c348000 0xffff9c34c000"
- Sprawdź, kto uruchomił proces i z jakim poleceniem: ps -o pid,ppid,user,lstart,cmd -p 5
- Po zapisaniu regionu sprawdź, co to za plik wykonywalny: file /tmp/region\_ffff9c348000.bin oraz readelf -h /tmp/region\_ffff9c348000.bin

#### Interpretacja LLM (do weryfikacji)

| Nr | Hipoteza | Pewność | Dowody (tagi) |
|---|---|---|---|
| 1 | reflective-load (obraz załadowany z pamięci) | ocena | HDR, X-PRIV |
| 2 | fileless-exec (wykonanie bez pliku na dysku) | niepotwierdzone | X-PRIV, HDR |
| 3 | benign-unknown (prawdopodobnie łagodne, przyczyna nieznana) | niepotwierdzone | X-PRIV |

- Hipoteza 1, za: Na początku prywatnego, wykonywalnego regionu bez pliku źródłowego znaleziono nagłówek obrazu (ELF), co pasuje do ręcznego załadowania biblioteki z pamięci.
- Hipoteza 1, za: Ochrona r-x zamiast RWX sugeruje, że loader po zapisaniu kodu celowo zmienił uprawnienia, jak robią to reflective loadery.
- Hipoteza 1, przeciw: Region ma tylko 16 KiB, co jest mało jak na pełny załadowany obraz.
- Hipoteza 1, przeciw: Nagłówek w pamięci anonimowej może też pochodzić z legalnych mechanizmów, np. kopii obrazu robionych przez runtime lub narzędzia diagnostyczne.

- Hipoteza 2, za: Wykonywalny kod z nagłówkiem obrazu bez żadnego pliku na dysku jest zgodny z bezplikowym uruchamianiem ładunku.
- Hipoteza 2, przeciw: Brak znaczników MEMFD lub DEL-EXEC, które typowo towarzyszą bezplikowemu wykonaniu na Linuksie.

- Hipoteza 3, za: Niska entropia (maks. 4,09) przemawia przeciw spakowanemu lub zaszyfrowanemu kodowi, a region nie jest zapisywalny.
- Hipoteza 3, przeciw: Legalne programy rzadko umieszczają nagłówek obrazu w anonimowej pamięci wykonywalnej, więc wymaga to wyjaśnienia.

Podsumowanie modelu: Prywatny region r-x o rozmiarze 16 KiB zawiera nagłówek obrazu bez pliku źródłowego, co najbardziej pasuje do refleksyjnego ładowania kodu. Niska entropia wskazuje, że nie jest to kod spakowany. Zaleca się zrzut regionu i analizę nagłówka ELF przez analityka.

### Region 0xffff9c353000 (wysokie, 70 pkt)

W skrócie: zaszyfrowany lub spakowany kod z pliku tylko w pamięci. Wyjaśnienie jest wyżej, w części „Co oznaczają znaleziska w tym procesie".

- MEMFD: wykonywalne mapowanie memfd:payload
- ENT-X: bardzo wysoka entropia w regionie wykonywalnym: max 7.95, stron powyżej progu: 2 z 2

| Pole | Wartość |
|---|---|
| Zakres adresów | 0xffff9c353000 - 0xffff9c355000 (8 KiB, odczytano 8 KiB) |
| Rodzaj i źródło | mapowanie; memfd:payload |
| Entropia | maksymalna 7.95, średnia 7.95 (skala 0-8); stron zerowych: 0 |
| Sąsiad poniżej | 0xffff9c351000 rw- pamięć anonimowa (przylega) |
| Sąsiad powyżej | 0xffff9c355000 rw- pamięć anonimowa (przylega) |

#### Profil entropii regionu

```text
0xffff9c353000 ██ 0xffff9c355000
```

Entropia odcinków (0-8): najniższa 8.0, najwyższa 8.0; 2 odcinków po 4 KiB.

#### Podgląd bajtów od 0xffff9c353000

```text
0xffff9c353000  ea 1c 58 d8 97 be 9d 50 12 c9 a7 6e 43 b5 af 76  ..X....P...nC..v
0xffff9c353010  c2 a0 72 7d 39 91 3d 65 90 d8 4f a3 7f c7 4f 6f  ..r}9.=e..O...Oo
0xffff9c353020  09 25 49 a6 b7 01 0d a5 40 3e 28 89 cd ac a8 07  .%I.....@>(.....
0xffff9c353030  0a 25 f2 99 ef b9 bc 68 f4 c6 4b 49 aa e5 7c c1  .%.....h..KI..|.
0xffff9c353040  f6 99 97 47 58 8a 8d d3 e7 b2 25 12 7f 26 76 8f  ...GX.....%..&v.
0xffff9c353050  8b 5c 17 5f 2e 5d 00 2a 93 81 6a a7 63 ff 74 27  .\._.].*..j.c.t'
0xffff9c353060  25 01 8b aa 07 d1 21 26 24 e8 10 24 c7 d5 d6 a9  %.....!&$..$....
0xffff9c353070  cd 69 ce 1b 23 d5 44 40 9b 4a 15 da 26 f4 be 50  .i..#.D@.J..&..P
```

#### Ciągi tekstowe w regionie

- no}P=NHfQr

#### Jak sprawdzić ten region

- Zobacz, czym jest ten region w mapie pamięci procesu: grep -n ffff9c353000 /proc/5/maps
- Zapisz zawartość regionu do pliku (wymaga gdb, zatrzymuje proces na chwilę): gdb -p 5 -batch -ex "dump memory /tmp/region\_ffff9c353000.bin 0xffff9c353000 0xffff9c355000"
- Sprawdź, kto uruchomił proces i z jakim poleceniem: ps -o pid,ppid,user,lstart,cmd -p 5
- Znajdź deskryptor pliku memfd i skopiuj cały plik: ls -l /proc/5/fd \| grep memfd, potem cp /proc/5/fd/NUMER /tmp/memfd\_5.bin
- Po zapisaniu regionu porównaj jego skrót z bazami znanych plików: sha256sum /tmp/region\_ffff9c353000.bin

#### Interpretacja LLM (do weryfikacji)

| Nr | Hipoteza | Pewność | Dowody (tagi) |
|---|---|---|---|
| 1 | fileless-exec (wykonanie bez pliku na dysku) | ocena | MEMFD |
| 2 | packer (kod spakowany lub zaszyfrowany) | niepotwierdzone | ENT-X, MEMFD |
| 3 | jit (kompilacja JIT) | niepotwierdzone | MEMFD |

- Hipoteza 1, za: Region jest wykonywalnym mapowaniem memfd, czyli pliku istniejącego wyłącznie w pamięci RAM, co jest typowe dla wykonywania kodu bez zapisu na dysk.
- Hipoteza 1, za: Backing oznaczony jako usunięty potwierdza brak trwałego pliku na dysku.
- Hipoteza 1, przeciw: Niektóre legalne programy (np. środowiska JIT, sandboksy, przeglądarki) również używają memfd do kodu wykonywalnego.
- Hipoteza 1, przeciw: Region ma tylko 8192 bajty, co jest małym rozmiarem jak na pełny ładunek.

- Hipoteza 2, za: Entropia 7.95 w regionie wykonywalnym wskazuje na zaszyfrowany lub skompresowany kod.
- Hipoteza 2, za: Brak stron zerowych i równomierna wysoka entropia pasują do spakowanej zawartości.
- Hipoteza 2, przeciw: Prawidłowy natywny kod maszynowy zwykle ma niższą entropię, więc zawartość może nie być bezpośrednio wykonywalnym kodem, a np. danymi.
- Hipoteza 2, przeciw: Brak nagłówka obrazu (HDR) nie potwierdza osadzonego, spakowanego pliku wykonywalnego.

- Hipoteza 3, za: Silniki JIT na Linuksie czasem mapują kod przez memfd w celu podwójnego mapowania W^X.
- Hipoteza 3, przeciw: Wygenerowany kod JIT rzadko osiąga entropię bliską 8.
- Hipoteza 3, przeciw: Brak informacji o procesie ani etykiecie wskazujących na środowisko JIT.

Podsumowanie modelu: Region to wykonywalne mapowanie memfd o bardzo wysokiej entropii (7.95), co najbardziej pasuje do wykonywania kodu bez pliku na dysku, być może zaszyfrowanego lub spakowanego. Legalne użycie memfd (np. JIT) jest możliwe, ale wysoka entropia czyni je mniej prawdopodobnym; wymagana ręczna weryfikacja procesu i zawartości.

### Korelacja regionów: interpretacja LLM (do weryfikacji)

Proces na Linuksie (aarch64) ma trzy oznaczone regiony wykonywalne: prywatny region RWX o wysokiej entropii, prywatny region z nagłówkiem ELF bez pliku źródłowego oraz wykonywalne mapowanie memfd o wysokiej entropii. Dane wejściowe nie wykazują bezpośredniego powiązania między regionami (nie sąsiadują ze sobą), dlatego nie zostały zgrupowane. Najpierw należy przeanalizować region RWX z najwyższym wynikiem, a potem region z nagłówkiem i mapowanie memfd.

Proponowana kolejność przeglądu: 0xffff9c120000, 0xffff9c348000, 0xffff9c353000.

#### Proponowane kolejne kroki

- Zrzucić w całości region r:5:ffff9c120000 (RWX, prywatny, wysoka entropia) i sprawdzić, czy da się zidentyfikować kod rozpakowujący lub zaszyfrowany ładunek.
- Zrzucić region r:5:ffff9c348000 z nagłówkiem ELF, sparsować nagłówek (sekcje, segmenty, punkt wejścia) i porównać z bibliotekami załadowanymi przez proces.
- Zrzucić mapowanie memfd r:5:ffff9c353000, odczytać nazwę memfd i link w /proc/&lt;pid&gt;/fd oraz /proc/&lt;pid&gt;/maps, a następnie porównać zawartość z pozostałymi regionami.
- Sprawdzić proces nadrzędny, linię poleceń i środowisko procesu, aby ustalić, co utworzyło memfd i prywatne regiony wykonywalne.
- Na podstawie zrzuconych regionów przygotować regułę YARA dla charakterystycznych wzorców (np. fragmentu nagłówka ELF lub kodu stubu) do przeszukania innych procesów.

## 6\. Czego ten raport nie obejmuje

- 1 regionów ze znaleziskami poniżej poziomu „podejrzane" pominięto; są w pliku wyniku.
- Podgląd bajtów w raporcie to pierwsze 128 bajtów znaleziska; pełne 256 bajtów jest w pliku wyniku (JSON). Pełnego zrzutu regionu narzędzie nie robi.
- Kontekst systemowy to stan z chwili skanu: połączenia zamknięte wcześniej, zakończone procesy potomne i usunięte pliki nie są widoczne. Historii (logów, dziennika audytu) raport nie obejmuje.
- Skan obejmuje pamięć procesów w chwili skanu; nie obejmuje jądra, treści plików na dysku ani zawartości ruchu sieciowego.
- Wynik nie zawiera skrótów SHA-256 plików (skan z --no-hashes albo starsza wersja narzędzia).
- Znalezisko THR-PRIV opiera się na adresie startu wątku (Windows) albo na miejscu wywołania jądra przez wątki czekające (Linux); wątek, który w chwili skanu coś liczył, nie jest na Linuksie oceniany. IMG-MOD mówi, że kod z pliku zmieniono w pamięci, ale nie pokazuje różnic.
- Model nie widział kontekstu systemowego ani mapy pamięci; jego hipotezy opierają się wyłącznie na danych regionów.

## 7\. Słowniczek

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

## 8\. Legenda

| Tag | Znaczenie |
|---|---|
| ENT-X | kod wyglądający na zaszyfrowany: Zawartość regionu wykonywalnego ma rozkład bliski losowemu. Kod maszynowy ma wyraźną strukturę i znacznie niższą entropię. |
| HDR | cały program schowany w pamięci: W pamięci bez pliku źródłowego znajduje się nagłówek pliku wykonywalnego albo biblioteki. Oznacza to, że obraz programu został załadowany z pominięciem mechanizmu ładowania systemu. |
| MEMFD | kod z pliku istniejącego tylko w pamięci: Proces wykonuje kod z pliku utworzonego wywołaniem memfd\_create. Taki plik istnieje wyłącznie w pamięci RAM i nie jest zapisywany na dysku. |
| RWX | pamięć zapisywalna i wykonywalna naraz: Region pamięci jest jednocześnie zapisywalny i wykonywalny. W typowym programie kod jest dostępny wyłącznie do odczytu i wykonania. |
| X-PRIV | kod bez pliku na dysku: Proces zawiera wykonywalny kod, który nie pochodzi z żadnego pliku. Kod powstał w pamięci w trakcie pracy procesu. |

Waga regionu wynika z sumy punktów jego znalezisk: poniżej 30 „info", 30-59 „podejrzane", od 60 „wysokie".

Pewność hipotez LLM: „ustalone" wynika wprost z danych deterministycznych; „ocena" to osąd modelu; „niepotwierdzone" jest możliwe, ale wymaga sprawdzenia przez człowieka. Hipoteza łagodna nigdy nie ma pewności „ustalone".

---

Triage, nie werdykt. Interpretacja LLM niedeterministyczna, do weryfikacji.
