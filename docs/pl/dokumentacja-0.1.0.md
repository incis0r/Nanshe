# Nanshe 0.1.0: dokumentacja wersji początkowej

Wersja angielska: [../documentation-0.1.0.md](../documentation-0.1.0.md).

Stan na 2026-11-22. Dokument opisuje, co ta wersja robi, jak jest zbudowana, co zostało sprawdzone i czego nie umie. Szczegóły dla poszczególnych systemów są w [linux.md](linux.md), [windows.md](windows.md) i [macos.md](macos.md), opis testów w [testy.md](testy.md) i baza wiedzy w [baza-wiedzy.md](baza-wiedzy.md).

## 1. Do czego służy

Nanshe to narzędzie do triage pamięci działających procesów. Wskazuje regiony pamięci, które wyglądają nietypowo (kod bez pliku, kod zapisywalny, kod wyglądający na zaszyfrowany, program schowany w pamięci, działający wątek w pamięci bez pliku, zmieniony kod biblioteki), zbiera wokół nich kontekst systemowy i składa z tego raport dla analityka.

Czym nie jest:

- Nie wydaje werdyktu „zainfekowany / czysty". Każde znalezisko to pytanie do sprawdzenia.
- Nie usuwa ani nie blokuje niczego. Badanego systemu nie zmienia (wyjątki są opisane w punkcie 10).
- Nie zastępuje pełnej analizy zrzutu pamięci: nie czyta pamięci jądra ani procesów chronionych.

## 2. Co potrafi ta wersja

| Obszar | Stan |
|---|---|
| Skan żywych procesów | Linux i Windows; macOS i FreeBSD bez backendu skanu |
| Analiza zrzutów pamięci | zrzuty pojedynczych procesów: plik core (Linux, ELF 64-bit) i minidump (Windows); zrzuty pamięci fizycznej: brak (planowane) |
| Detektory | 11 cech: `RWX`, `X-PRIV`, `X-MAP`, `GUARD-X`, `MEMFD`, `DEL-EXEC`, `X-TMP`, `ENT-X`, `HDR`, `THR-PRIV`, `IMG-MOD` |
| Kontekst systemowy | rodzice i dzieci, wiersz poleceń, użytkownik, plik programu, gniazda, otwarte pliki i uchwyty, cechy bezpieczeństwa |
| Skróty SHA-256 | pliki programów wszystkich procesów, pliki zmapowane w procesach ze znaleziskami, zawartość regionów |
| Interpretacja modelem językowym | lokalnie (Ollama) albo w chmurze (Nous, Anthropic, Google, OpenAI) |
| Raport | Markdown i PDF, z diagramami i objaśnieniami z bazy wiedzy |
| Mapa pamięci w przeglądarce | `nanshe map` (inwentaryzacja metadanych, bez czytania zawartości) |
| Instalator | pakiet MSI oraz paczka zip z instalatorem PowerShell dla Windows |

## 3. Budowa

Projekt jest w języku Rust, podzielony na osiem pakietów (około 8 100 wierszy kodu razem z testami):

| Pakiet | Rola | Wiersze |
|---|---|---|
| `nanshe-core` | wspólne typy: region, znalezisko, wynik skanu, kontekst procesu; interfejs źródła pamięci | 446 |
| `nanshe-analyze` | entropia, detektory, punktacja, obniżka dla środowisk JIT | 1 035 |
| `nanshe-live` | odczyt żywych procesów: Linux (`/proc`), Windows (API systemu); kontekst systemowy; skróty plików; porównanie kodu z plikiem na dysku | 1 744 |
| `nanshe-dump` | zrzuty pamięci procesów jako źródło: plik core ELF i minidump Windows | (nowy) |
| `nanshe-kb` | baza wiedzy do raportu (treść w `kb/*.json`) | 371 |
| `nanshe-report` | model raportu, Markdown, PDF pisany bez zewnętrznych programów, strona mapy pamięci | 2 227 |
| `nanshe-llm` | warstwa modelu: dobór danych, filtry, pseudonimizacja, dostawcy, walidacja odpowiedzi | 1 749 |
| `nanshe-cli` | program `nanshe` | 519 |
| `nanshe-samples` | program `nanshe-sample`: nieszkodliwe próbki do testów | (poza sumą) |

Zasady konstrukcyjne:

- **Detektory widzą tylko abstrakcję.** Analiza pracuje na interfejsie „źródło pamięci" (regiony, odczyt, wątki, zmieniony kod), nie na systemie. Dzięki temu te same detektory zadziałają na zrzutach, gdy dojdzie taki backend.
- **Kod niebezpieczny w jednym miejscu.** `unsafe` jest wyłącznie w module Windows pakietu `nanshe-live` (wywołania API systemu) i w próbkach testowych; pozostałe pakiety mają go zakazanego.
- **Kod sieciowy tylko w warstwie modelu.** Build bez cechy `llm` nie zawiera żadnego kodu sieciowego.
- **Wynik deterministyczny.** Dwa skany tego samego stanu dają ten sam plik (poza znacznikiem czasu). Model językowy niczego w wyniku skanu nie zmienia.
- **Częściowy wynik zamiast żadnego.** Błąd odczytu regionu albo niedostępny proces nie przerywa skanu; wynik jest oznaczany jako częściowy.

Przepływ danych:

```text
proces -> nanshe scan -> wynik.json -> nanshe report  -> wynik.report.md, wynik.report.pdf
                              |
                              +------> nanshe explain -> wynik.llm.json -> (raport z interpretacją)
```

## 4. Polecenia

| Polecenie | Co robi |
|---|---|
| `nanshe scan --pid N` | skan jednego procesu |
| `nanshe scan --all` | skan wszystkich dostępnych procesów (poza samym skanerem) |
| `nanshe scan plik-zrzutu` | analiza zrzutu pamięci procesu tymi samymi detektorami |
| `nanshe report wynik.json` | raport Markdown i PDF |
| `nanshe diff wczesniej.json pozniej.json` | raport różnicowy: co zmieniło się między dwoma skanami tej samej stacji |
| `nanshe explain wynik.json` | interpretacja modelem językowym, potem raport |
| `nanshe map` | interaktywna mapa pamięci w przeglądarce (same metadane) |
| `nanshe ps` | lista procesów |
| `nanshe formats` | obsługiwane źródła, detektory, stan warstwy modelu |
| `nanshe llm check` | test łączności z modelem, bez danych ze skanu |
| `nanshe cloud list providers` / `models` | wbudowani dostawcy chmurowi i ich modele |

Najważniejsze opcje `scan`:

| Opcja | Znaczenie |
|---|---|
| `--json plik` | pełny wynik do pliku (`-` oznacza standardowe wyjście) |
| `--min info\|suspicious\|high` | próg wydruku i kodu wyjścia (domyślnie `suspicious`) |
| `--no-bytes` | bez podglądu bajtów i ciągów tekstowych w wyniku |
| `--no-context` | bez kontekstu systemowego i pełnej mapy regionów |
| `--no-hashes` | bez skrótów plików |
| `--max-region-mib N` | limit odczytu jednego regionu (domyślnie 64) |
| `--heatmap` | mapa entropii wszystkich przeczytanych regionów |

Kody wyjścia `scan`: 0 brak znalezisk od progu, 1 są znaleziska, 2 błąd, 3 wynik częściowy bez znalezisk.

Najważniejsze opcje `report`: `--llm plik` albo `--no-llm`, `--md`, `--pdf`, `--min`, `--kb katalog` (własna baza wiedzy).

### Zrzuty pamięci procesów: `nanshe scan <plik>`

`nanshe scan plik-zrzutu --json wynik.json` analizuje zrzut pamięci jednego procesu tymi samymi detektorami co skan na żywo. Format jest rozpoznawany po sygnaturze pliku.

| Format | Jak powstaje | Co zawiera |
|---|---|---|
| plik core (ELF 64-bit, x86_64 i aarch64) | `gcore <pid>` z pakietu gdb albo zrzut awaryjny jądra | regiony z uprawnieniami, treść pamięci, nazwy zmapowanych plików, rejestry wątków, nazwa i początek wiersza poleceń |
| minidump z pełną pamięcią | Menedżer zadań („Utwórz plik zrzutu"), `procdump -ma`, funkcja `MiniDumpWriteDump` | regiony z uprawnieniami i rodzajem, treść pamięci, moduły, adresy startu wątków |

Różnice wobec skanu na żywo:

- Nie ma kontekstu systemowego (sieć, otwarte pliki, drzewo procesów): zrzut go nie zawiera. Raport pomija te części i mówi, że źródłem jest zrzut.
- Obniżka wagi dla środowisk JIT nie jest stosowana, bo pliku programu nie da się sprawdzić; proces ze środowiskiem .NET albo przeglądarką da więcej znalezisk niż przy skanie na żywo.
- `IMG-MOD` nie działa (nie ma z czym porównać kodu).
- Minidump nie zawiera nazw plików dla mapowań innych niż moduły. Plik core zapisany przez jądro zwykle nie zawiera niezmienionego kodu z plików; takich regionów detektory treści nie sprawdzą, a wynik to odnotowuje.
- W pliku core region vdso (kod dostarczany przez jądro) jest rozpoznawany po wektorze pomocniczym i nie jest zgłaszany jako program bez pliku.

Plik zrzutu jest daną niezaufaną: każde przesunięcie i każda liczba z nagłówków są sprawdzane względem długości pliku, liczby wpisów mają limity, a treść pamięci jest czytana z pliku dopiero na żądanie. Zrzut procesu chronionego (na przykład LSASS) wymaga narzędzia, które potrafi go wykonać; Nanshe takiego narzędzia nie zawiera.

### Raport różnicowy: `nanshe diff`

`nanshe diff wczesniej.json pozniej.json` porównuje dwa wyniki skanu tej samej stacji i zapisuje raport Markdown i PDF (domyślnie `<późniejszy wynik>.diff.md` i `.diff.pdf`; opcje `--md`, `--pdf`, `--min`). Odpowiada na pytanie „co się zmieniło od poprzedniego skanu”:

| Część | Co pokazuje |
|---|---|
| Podsumowanie zmian | ocena ogólna i liczby: nowe regiony w działających procesach, nowe procesy ze znaleziskami, procesy ze zmianami, procesy, które zniknęły, procesy bez zmian |
| Zmiany w działających procesach | dla procesu obecnego w obu skanach: regiony nowe, zmienione (cechy, wynik, prawa, rozmiar, zawartość), takie, które zniknęły albo spadły poniżej progu; poza pamięcią: nowe i zamknięte gniazda, procesy potomne, zmapowane pliki, zmiana skrótu pliku programu |
| Nowe procesy ze znaleziskami | procesy, których nie było wcześniej |
| Procesy, które zniknęły | procesy ze znaleziskami nieobecne w późniejszym skanie |
| Ograniczenia porównania | zasady dopasowania i to, czego porównanie nie widzi |

Najważniejszy sygnał to nowy region ze znaleziskiem w procesie, który działał już przy wcześniejszym skanie: kod pojawił się w trakcie pracy procesu. Ma też przyczyny łagodne (środowiska JIT), więc raport nazywa to sygnałem do weryfikacji, nie dowodem.

Zasady: proces jest „ten sam”, gdy zgadza się PID, nazwa, plik programu i czas startu (PID bywa użyty ponownie); regiony są dopasowywane po adresie początku; zmiana zawartości jest wykrywana przez skrót SHA-256 regionu. Raport ostrzega, gdy wyniki pochodzą z różnych hostów, gdy system uruchomiono ponownie między skanami, gdy skany wykonano z różnymi uprawnieniami albo gdy pliki podano w odwrotnej kolejności. Porównanie niczego nie punktuje na nowo i nie używa modelu językowego.

### Język: `--lang pl|en`

Opcja `--lang` (albo zmienna `NANSHE_LANG`) działa dla wszystkich poleceń i wybiera język tekstów przeznaczonych dla człowieka:

| Polecenie | Co zmienia `--lang` |
|---|---|
| `scan` | opisy zapisywane w wyniku: uzasadnienia znalezisk, nazwy i wartości cech procesu, uwagi skanera, opis uprawnień skanera. Język jest zapisany w polu `lang` wyniku |
| `report` | cały tekst raportu i bazę wiedzy. Bez opcji raport powstaje w języku, w którym wykonano skan |
| `explain` | język, w którym model pisze uzasadnienia i podsumowania |

Tagi, identyfikatory znalezisk, nazwy pól wyniku i punktacja nie zależą od języka.

Raport w całości po angielsku wymaga skanu z `--lang en`. Raport w innym języku niż skan też powstanie, ale opisy zapisane w wyniku zostaną w języku skanu, a objaśnienia cech procesu z bazy wiedzy mogą się nie pojawić; raport uprzedza o tym ramką na początku.

```sh
nanshe --lang en scan --all --json result.json
nanshe report result.json            # po angielsku, bo taki był skan
```

Najważniejsze opcje `explain`: `--llm ollama|nous|anthropic|google|openai`, `--model`, `--allow-cloud`, `--data-level d0|d1|d2`, `--dry-run`, `--max-calls` (domyślnie 60), `--max-regions` (domyślnie 6 na proces), `--key-file`, `--no-report`.

## 5. Detektory i punktacja

Każdy detektor dodaje do regionu punkty. Suma punktów regionu daje wagę: poniżej 30 „info", 30-59 „podejrzane", od 60 „wysokie". Waga procesu to najwyższa waga jego regionów.

| Cecha | Punkty | System | Kiedy |
|---|---|---|---|
| `RWX` | 30 | oba | region jednocześnie zapisywalny i wykonywalny |
| `X-PRIV` | 30 | oba | wykonywalna pamięć bez pliku |
| `X-MAP` | 30 | Windows | wykonywalna sekcja niebędąca obrazem modułu |
| `GUARD-X` | 30 | Windows | wykonywalny region za stroną strażnika; treść celowo nieczytana |
| `MEMFD` | 40 | Linux | wykonywalne mapowanie pliku istniejącego tylko w pamięci |
| `DEL-EXEC` | 30 | Linux | wykonywalne mapowanie pliku usuniętego z dysku |
| `X-TMP` | 30 | Linux | wykonywalne mapowanie pliku z katalogu zapisywalnego dla wszystkich |
| `ENT-X` | 10 / 20 / 30 | oba | wysoka entropia w regionie wykonywalnym: 20 od 7,2, 30 od 7,8; 10, gdy to pojedyncze strony w zwykłym kodzie z pliku |
| `HDR` | 40 | oba | nagłówek ELF, PE albo Mach-O w pamięci bez pliku |
| `THR-PRIV` | 40 | oba | wątek ulokowany w pamięci bez pliku |
| `IMG-MOD` | 10 / 40 | oba | kod w pamięci różni się od pliku na dysku: 40 na Linuksie i dla `amsi.dll`, `wldp.dll`, 10 dla pozostałych bibliotek Windows. Znalezisko mówi, czy treść porównano z plikiem |

Szczegóły, które mają znaczenie przy ocenie wyniku:

- **`HDR`** wymaga więcej niż sygnatury: dla ELF poprawnego typu pliku, dla PE niezerowego pola Machine i 1-96 sekcji. Na początku strony szuka w każdym regionie bez pliku poza niewykonywalnym stosem; pod dowolnym przesunięciem tylko w regionach wykonywalnych. Powód obu ograniczeń jest ten sam: program ładujący trzyma w zwykłych danych kopie nagłówków bibliotek.
- **`THR-PRIV`** na Windows używa adresu startu wątku, na Linuksie adresu instrukcji, z której wątek wywołał jądro (tylko dla wątków czekających w wywołaniu systemowym).
- **`IMG-MOD`** działa w dwóch krokach. Najpierw backend ustala, które strony kodu z pliku proces zapisał (Linux: strony anonimowe wg `smaps`; Windows: strony zestawu roboczego, które nie są już współdzielone). Potem porównuje ich treść z plikiem na dysku: na Linuksie z odpowiednim fragmentem pliku (otwieranego przez `/proc/<pid>/map_files`, a po ścieżce tylko wtedy, gdy urządzenie i i-węzeł zgadzają się z mapą procesu), na Windows z treścią odtworzoną z pliku PE z naniesionymi relokacjami dla faktycznego adresu załadowania. Znalezisko podaje liczbę różnych bajtów i adres pierwszego. Porównanie nie może wygasić znaleziska po cichu: gdy którejś strony nie da się odczytać w całości, gdy tablica relokacji pliku jest uszkodzona albo zbyt duża, albo gdy nagłówek obrazu w pamięci nie odpowiada nagłówkowi pliku (inny plik niż załadowany, na przykład po aktualizacji), znalezisko mówi wprost, że treści nie porównano. Na Linuksie plik jest na pewno tym zmapowanym, więc strona będąca tylko prywatną kopią bez zmiany treści nie daje znaleziska. Na Windows tożsamości pliku nie da się potwierdzić (zgodność nagłówków to tylko przesłanka), więc przy braku różnic zostaje znalezisko informacyjne (10 punktów) mówiące, że treść jest zgodna z plikiem pod tą ścieżką.
- **`HDR` z wymazaną sygnaturą.** Gdy na początku strony w regionie wykonywalnym nie ma poprawnego nagłówka, detektor szuka jeszcze tablicy sekcji PE (co najmniej dwa spójne wpisy, w tym wykonywalny) albo tablicy segmentów ELF (co najmniej dwa segmenty ładowane, w tym wykonywalny). Tak wygląda obraz załadowany ręcznie, z którego usunięto znaczniki formatu, żeby nie dało się go znaleźć po sygnaturze.

### Obniżka dla środowisk tworzących kod w locie

Środowiska JIT (.NET, Java, silniki JavaScript) stale tworzą regiony, które wyglądają jak wstrzyknięty kod. Dla rozpoznanego środowiska punkty `RWX`, `X-PRIV`, `X-MAP` (tylko sekcje bez pliku) i `ENT-X` są dzielone przez 3. Znaleziska zostają w wyniku z adnotacją; `HDR`, `GUARD-X`, `THR-PRIV` i `IMG-MOD` nie są obniżane.

- **Linux:** po pliku programu. Musi nazywać się jak znane środowisko (m.in. `node`, `java`, `dotnet`, przeglądarki), leżeć w katalogu systemowym, należeć do roota, nie być zapisywalny dla innych i być tym samym plikiem, który widzi skaner.
- **Windows:** po załadowanym module. Plik programu musi leżeć w katalogu systemowym (poza podkatalogami zapisywalnymi dla użytkowników) i należeć do konta systemowego, a moduł środowiska (`clr.dll`, `coreclr.dll`, `msedge.dll`) musi być załadowany jako obraz ze swojego katalogu instalacyjnego.

Znane ryzyko obniżki: kod wstrzyknięty do legalnego procesu ze środowiskiem JIT dziedziczy ją. Prywatny region zapisywalny i wykonywalny o niskiej entropii spada wtedy do wagi „info". Sygnałem, który tego nie dotyczy, jest `THR-PRIV`.

## 6. Kontekst systemowy

Dla procesu ze znaleziskiem od wagi „podejrzane" skan zbiera dane spoza pamięci, wyłącznie odczytem:

| Dane | Linux | Windows |
|---|---|---|
| rodzic, przodkowie, dzieci | tak | tak (z ochroną przed ponownie użytym numerem procesu) |
| wiersz poleceń, czas startu, liczba wątków | tak | tak |
| użytkownik | tak | tak |
| plik programu: rozmiar, czas zmiany, SHA-256 | tak (także usunięty z dysku) | tak (pliki lokalne) |
| właściciel i tryb pliku programu | tak | nie |
| katalog roboczy | tak | nie |
| gniazda TCP i UDP (IPv4, IPv6) | tak, plus gniazda uniksowe | tak |
| otwarte pliki | deskryptory (do 200) | nazwane uchwyty: pliki, klucze rejestru, sekcje, muteksy, uchwyty do innych procesów (do 300) |
| cechy bezpieczeństwa | ptrace, uprawnienia, seccomp, zmienne `LD_PRELOAD` i podobne | poziom integralności, sesja |
| pełna mapa regionów | tak | tak |

Wynik zawiera też opis hosta (system, wersja jądra albo kompilacji, czas startu) oraz uprawnienia, z którymi działał skaner. Skan bez pełnych uprawnień jest w raporcie oznaczony ostrzeżeniem na pierwszej stronie.

## 7. Plik wyniku

Wynik to jeden plik JSON (`schema_version` 1). Najważniejsze pola:

| Pole | Zawartość |
|---|---|
| `host`, `timestamp`, `tool_version`, `partial` | metryka skanu; `partial` oznacza wynik częściowy |
| `host_info` | system, czas startu, konto i uprawnienia skanera |
| `processes[]` | wynik każdego procesu |
| `processes[].info` | numer, nazwa, system, plik programu, czy plik potwierdzony jako systemowy |
| `processes[].error` | powód niedostępności albo obcięcia mapy |
| `processes[].regions[]` | regiony ze znaleziskami: opis regionu, punkty, waga, entropia, znaleziska, profil entropii, ciągi tekstowe, SHA-256 zawartości, adnotacja obniżki |
| `processes[].regions[].findings[]` | cecha, adres, punkty, uzasadnienie, podgląd do 256 bajtów |
| `processes[].layout` | pełna mapa regionów (tylko procesy od wagi „podejrzane") |
| `processes[].context` | kontekst systemowy (tylko procesy od wagi „podejrzane") |
| `files[]` | skróty SHA-256 plików programów i plików zmapowanych |

Plik zawiera dane z badanej stacji bez filtrowania: ścieżki, wiersze poleceń, adresy sieciowe, fragmenty pamięci. Trzeba go traktować jak materiał dowodowy. Pola nieznane starszej wersji są pomijane przy wczytywaniu, a brakujące przyjmują wartości puste, więc raport da się wygenerować także ze starszego wyniku.

## 8. Interpretacja modelem językowym

Polecenie `explain` wysyła do modelu opis każdego regionu ze znaleziskiem i prosi o uszeregowane hipotezy z argumentami za i przeciw, a potem o powiązanie regionów procesu i proponowane kroki. Wynik trafia do osobnego pliku i jest w raporcie wyraźnie oznaczony jako niedeterministyczny.

**Ile danych wychodzi (poziom danych):**

| Poziom | Co dostaje model | Domyślnie dla |
|---|---|---|
| `d0` | same metadane regionu: uprawnienia, rozmiar, entropia, cechy, punkty | chmury |
| `d1` | dodatkowo ciągi tekstowe po filtrze sekretów, nazwa procesu, ścieżki | modelu lokalnego |
| `d2` | dodatkowo surowe bajty | nigdy nie idzie do chmury |

**Zabezpieczenia przed wysłaniem:**

- Chmura wymaga jawnej zgody `--allow-cloud`; `--dry-run` pokazuje dokładnie, co zostałoby wysłane.
- Filtr sekretów wycina klucze, tokeny, hasła i ciągi o wysokiej entropii (poziom `d1`).
- Filtr wstrzyknięć usuwa tekst wyglądający na instrukcję dla modelu (z pamięci, nazwy procesu, ścieżek, etykiet) i podnosi znacznik w wyniku.
- Pseudonimizacja dla chmury zastępuje nazwę hosta, nazwy użytkowników w ścieżkach i adresy IP (v4 i v6) etykietami, a w odpowiedzi przywraca wartości. To ograniczenie ryzyka, nie gwarancja; dla danych klienta najbezpieczniejszy jest poziom `d0`.
- Model nie dostaje kontekstu systemowego ani mapy pamięci.

**Kontrola odpowiedzi:** odpowiedź musi pasować do schematu, odwoływać się tylko do istniejących znalezisk i zawierać uzasadnienie. Hipoteza łagodna nie może mieć najwyższej pewności. Odpowiedź niespełniająca warunków jest ponawiana, a potem odrzucana z zapisanym powodem. Odmowa albo błąd dostawcy dają wynik częściowy, bez automatycznego przełączania na inny model.

**Dostawcy:** Ollama (lokalnie), Nous, Anthropic, Google, OpenAI. Klucz podaje się zmienną środowiskową albo plikiem; nie trafia do wyniku ani do logów.

Sprawdzone na żywo: Ollama (`gemma3:12b`) i Nous (modele Claude). Dostawcy Anthropic, Google i OpenAI mają tylko testy kształtu zapytań.

## 9. Raport

Raport powstaje w dwóch formatach o tej samej treści: Markdown i PDF. PDF jest pisany wprost przez narzędzie, z osadzoną czcionką (polskie znaki, tekst do zaznaczania), i jest powtarzalny: ten sam wynik daje ten sam plik.

Układ (rozdziały główne są numerowane):

1. Metryka: host, czas, wersja, kompletność, uprawnienia skanera, klasyfikacja dokumentu, SHA-256 pliku wyniku, oraz ostrzeżenia (wynik to triage, nie werdykt; raport zawiera dane ze stacji; ewentualnie niepełne uprawnienia).
   Po metryce jest spis treści rozdziałów głównych; w PDF z numerami stron (układ liczony jest dwa razy: pierwszy przebieg ustala strony rozdziałów, drugi wpisuje je do spisu).
   Ułatwienia w czytaniu: wpisy spisu treści i wiersze znalezisk na mapie przestrzeni adresowej są odnośnikami do rozdziału albo opisu regionu (w PDF klikalne, w Markdown jako odnośniki do kotwic); wiersz poleceń i polecenia sprawdzające są wyróżnione jako kod; priorytet (P1-P3) i waga mają stałe kolory; kroki „Jak sprawdzić ten region" mają pod poleceniem akapit „Jak czytać wynik"; argumenty każdej hipotezy modelu są w dwóch kolumnach (co ją wspiera, co ją podważa), a pewność ma etykiety „ustalone z danych", „osąd modelu", „niepotwierdzone" z objaśnieniem pod tabelą.
2. **Podsumowanie dla decydenta**: ocena ogólna w jednym akapicie, zakres i kompletność, liczba procesów według priorytetu, najważniejsze procesy z uzasadnieniem, zalecane działania i ograniczenia oceny.
3. „Jak czytać ten raport": wstęp, znaczenie wag, opis każdej części.
4. Przegląd procesów: tabela z priorytetami, wykres cech, macierz procesy x cechy, wspólne drzewo procesów ze znaleziskami.
5. Dla każdego procesu (w kolejności priorytetu):
   - dane procesu i **„Ocena"**: priorytet weryfikacji, uzasadnienie, pierwszy krok,
   - „Co to za program" (opis z bazy wiedzy, porównanie położenia pliku i rodzica z typowymi),
   - drzewo procesów, sieć, otwarte pliki i uchwyty, pliki zmapowane z opisami i skrótami,
   - mapa przestrzeni adresowej,
   - „Co oznaczają znaleziska": każdy zestaw cech raz, z wyjaśnieniem łagodnym i niepokojącym, podstawą techniczną i powiązanymi technikami MITRE ATT&CK,
   - wykres rozmiar x entropia regionów i diagram „od pamięci do sieci",
   - szczegóły najwyżej 6 regionów o najwyższym wyniku: sąsiedzi, profil entropii, podgląd bajtów, pola nagłówka ELF albo PE, ciągi tekstowe, polecenia do sprawdzenia regionu, interpretacja modelu.
6. „Czego ten raport nie obejmuje": procesy niedostępne, regiony nieprzeczytane, braki danych.
7. Słowniczek i legenda.

Tekst ma dwie warstwy. Opis każdej cechy jest zrozumiały bez przygotowania z analizy pamięci, a obok niego stoi warstwa dla doświadczonego czytelnika: dokładny warunek detektora (flagi stron, źródło danych) i odniesienie do katalogu MITRE ATT&CK.

**Priorytet weryfikacji** porządkuje pracę analityka i wynika wprost ze znalezisk oraz kontekstu:

| Priorytet | Kiedy |
|---|---|
| P1 | cecha, której nie tłumaczy środowisko kompilujące kod w locie (`THR-PRIV`, `HDR`, `MEMFD`, `GUARD-X`, `IMG-MOD` w module ochronnym), albo waga „wysokie" w procesie bez rozpoznanego takiego środowiska |
| P2 | waga „wysokie" z rozpoznanym środowiskiem albo bez mapy pamięci; waga „podejrzane" w programie spoza katalogów systemowych |
| P3 | pozostałe |

Priorytet nie jest oceną szkodliwości i nie zmienia punktacji. Wysokie uprawnienia procesu i połączenia z adresami zdalnymi są dopisywane do uzasadnienia.

Cała treść pochodząca z badanego systemu albo od modelu jest w raporcie neutralizowana (nie może wstawić znaczników ani rozbić tabeli). Raport odmawia dołączenia interpretacji, która dotyczy innego pliku wyniku.

Objaśnienia prostym językiem pochodzą z bazy wiedzy w `kb/` (wspólna, Linux, Windows). Można ją podmienić bez przebudowy programu opcją `--kb`. Baza tylko objaśnia; punktacji nie zmienia.

## 10. Bezpieczeństwo samego narzędzia

**Zasada „tylko odczyt".** Skaner nie zapisuje do badanych procesów, nie zatrzymuje ich i nie wstrzykuje kodu. Na Linuksie czyta `/proc`. Na Windows otwiera procesy z prawami do zapytań i odczytu pamięci.

Miejsca, w których narzędzie robi coś więcej niż bierny odczyt:

| Miejsce | Co robi | Dlaczego |
|---|---|---|
| uchwyty na Windows | otwiera proces z prawem kopiowania uchwytów i na chwilę kopiuje uchwyt do siebie bez żadnych praw | inaczej nie da się poznać typu i nazwy obiektu |
| strony strażnika na Windows | celowo ich nie czyta | odczyt zdjąłby flagę strażnika, czyli zmienił stan procesu |
| `SeDebugPrivilege` | włącza przywilej we własnym tokenie | bez niego widać tylko własne procesy |

**Dane niezaufane.** Nazwy procesów, ścieżki, treść pamięci i odpowiedzi modelu są traktowane jako dane kontrolowane przez atakującego: nie wpływają na obniżkę punktów (liczy się plik potwierdzony przez system, nie nazwa), nie trafiają do modelu bez filtrów i nie mogą zmienić układu raportu.

**Ochrona skanera:**

- Skróty liczone są tylko dla zwykłych plików: urządzenia i potoki nie są otwierane wcale, plik jest otwierany raz, sprawdzany ponownie po otwarciu i czytany do limitu 512 MiB.
- Na Windows skaner nie otwiera ścieżek sieciowych podanych przez badany proces (otwarcie wysłałoby poświadczenia komputera na obcy serwer).
- Zapytania o nazwy uchwytów mają limit czasu; nazw potoków skaner nie pyta wcale.
- Limity: 64 MiB na region, 1 048 576 regionów na proces, limity liczby zapisywanych plików, uchwytów i ciągów.

**Instalacja na Windows.** Instalator umieszcza program w katalogu zapisywalnym tylko dla administratorów, a wyniki w katalogu dostępnym tylko dla administratorów i konta SYSTEM. Odmawia, gdy docelowy katalog został wcześniej podstawiony (dowiązanie albo obcy właściciel), i sprawdza skróty plików paczki. Skrypt usuwania stosuje te same kontrole przed usunięciem katalogów.

## 11. Wymagania i uruchomienie

| | Linux | Windows |
|---|---|---|
| Uprawnienia | root albo `CAP_SYS_PTRACE` | administrator z podniesionymi uprawnieniami |
| Build | `cargo build --release -p nanshe-cli --features llm` | to samo, toolchain MSVC |
| Instalacja | kopia binarium | pakiet MSI (`scripts\package-msi.ps1`) albo paczka z `scripts\package-windows.ps1` i `install.ps1`; opis w [windows.md](windows.md) |
| Sprawdzone na | Debian 12, aarch64, w kontenerze | Windows 11 Pro x64 (stacja testowa) |

Typowa sesja:

```sh
nanshe scan --all --json wynik.json          # skan całej stacji
nanshe report wynik.json                     # raport bez modelu
nanshe explain wynik.json --llm nous --allow-cloud --key-file klucz.txt   # interpretacja i raport
```

Na stacji bez backendu skanu (macOS) działają polecenia pracujące na pliku wyniku: `report`, `explain`, `map --input`.

## 12. Co zostało sprawdzone

| Warstwa | Stan |
|---|---|
| Testy jednostkowe | 110, wszystkie przechodzą; pisane parami (przypadek i kontrola różniąca się jedną cechą) |
| Testy na żywych próbkach, Linux | 17 próbek statycznych i 2 dynamiczne, plus asercje wyniku, raportu i kontekstu |
| Testy na żywych próbkach, Windows | 16 próbek statycznych i 2 dynamiczne, plus asercje wyniku, raportu, kontekstu i uchwytów |
| Instalator Windows | test instalacji, odmów i odinstalowania (wynik pierwszego przebiegu w [testy.md](testy.md)) |
| Model lokalny i chmura | przebiegi ręczne na próbkach i na pełnym skanie stacji testowej |

Pomiar na stacji testowej Windows (240 procesów, 2026-11-22):

- pełny skan trwa około 30 s i zbiera skróty 335 plików,
- 18-20 procesów jest niedostępnych (procesy chronione przez system), tak samo dla administratora i dla konta SYSTEM,
- po obniżce dla środowisk JIT zostaje 5 procesów ze znaleziskami od wagi „podejrzane" (przed obniżką było 20); wszystkie pięć to programy spoza katalogów systemowych,
- `THR-PRIV` nie dał żadnego alarmu; `IMG-MOD` wystąpił łagodnie w 19 procesach, stąd niska waga dla zwykłych bibliotek.

To pomiar z jednej stacji. Na serwerach, stacjach deweloperskich i w kontenerach liczby będą inne.

## 13. Znane ograniczenia

**Czego narzędzie nie widzi:**

- procesów chronionych przez system (na Windows między innymi LSASS, procesy antywirusa) i pamięci jądra,
- kodu wstrzykniętego do procesu ze środowiskiem JIT, jeśli nie ma własnego wątku, wysokiej entropii ani nagłówka,
- nagłówka programu z wymazanymi sygnaturami,
- nagłówka poza początkiem strony w danych niewykonywalnych,
- na Windows: sekcji obrazu załadowanej z pliku spoza katalogów systemowych,
- na Linuksie: wątków, które w chwili skanu nie czekały w jądrze,
- tego, co działo się przed skanem: skan to stan z jednej chwili.

**Czego nie robi:**

- nie analizuje zrzutów pamięci fizycznej (zrzuty pojedynczych procesów analizuje),
- nie obserwuje procesu w czasie (raport różnicowy porównuje dwa stany, ale nie widzi tego, co pojawiło się i znikło między skanami),
- nie pokazuje, co dokładnie zmieniono w kodzie biblioteki,
- nie sprawdza podpisów cyfrowych ani skrótów w zewnętrznych bazach,
- nie skanuje macOS ani FreeBSD.

**Czego nie zmierzono:**

- fałszywych alarmów poza jedną stacją Windows i próbkami na Linuksie,
- skuteczności na prawdziwym złośliwym oprogramowaniu (wszystkie próbki są syntetyczne),
- jakości interpretacji modeli (brak zestawu oceny; są tylko obserwacje z pojedynczych przebiegów),
- Linuksa na architekturze x86_64.

**Braki wydania:** brak ciągłej integracji i testów losowych parserów, brak podpisu cyfrowego programu i instalatorów. Po angielsku dostępne są raport, baza wiedzy i opisy w wyniku skanu; pomoc wiersza poleceń (`--help`), komunikaty warstwy modelu w terminalu i mapa pamięci (`nanshe map`) są tylko po polsku.

## 14. Co dalej

Kolejność uzgodniona w toku prac:

1. Analiza zrzutów pamięci fizycznej jako nowe źródło (te same detektory), z translacją adresów przez gotową bibliotekę. Zrzuty pojedynczych procesów są już obsługiwane.
2. Odczyt pamięci maszyn wirtualnych z hiperwizora (daje dostęp do procesów chronionych bez śladu w badanym systemie).
3. Porównanie zmienionego kodu z plikiem na dysku (pokazanie, co zmieniono) i wykrywanie nagłówków z wymazanymi sygnaturami.
4. Znaleziska z kontekstu: proces o wysokich uprawnieniach uruchomiony z katalogu zapisywalnego dla zwykłych użytkowników.
5. Obserwacja procesu w czasie.
6. Backendy macOS i FreeBSD.

## 15. Licencja

Apache License 2.0, pliki `LICENSE` i `NOTICE` w katalogu głównym. Biblioteki, z których korzysta program, mają licencje zezwalające (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode); wbudowana czcionka DejaVu ma własną licencję (`crates/nanshe-report/fonts/LICENSE-DejaVu.txt`).
