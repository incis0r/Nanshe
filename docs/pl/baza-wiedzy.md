# Baza wiedzy raportu

Wersja angielska: [../knowledge-base.md](../knowledge-base.md).

Raport ma być zrozumiały dla osoby (i dla modelu językowego), która nie zajmuje się analizą pamięci na co dzień. Dlatego obok danych technicznych zawiera objaśnienia prostym językiem. Ich treść nie jest zaszyta w kodzie, tylko leży w plikach danych w katalogu `kb/`:

| Plik | Zakres |
|---|---|
| `kb/common.json` | wspólne dla wszystkich systemów: przewodnik po raporcie, wagi, cechy `RWX`, `X-PRIV`, `ENT-X`, `HDR`, podstawowy słowniczek |
| `kb/linux.json` | Linux: `MEMFD`, `DEL-EXEC`, `X-TMP`, polecenia sprawdzające, znane procesy i biblioteki, cechy procesu z `/proc` |
| `kb/windows.json` | Windows: `X-MAP`, `GUARD-X`, polecenia sprawdzające, znane procesy i moduły, uchwyty, poziomy integralności |
| `kb/macos.json` | macOS: warstwa techniczna cech, polecenia sprawdzające (`vmmap`, `lldb`, `codesign`), zestaw `ENT-X`, znane procesy i biblioteki, podpis kodu i uprawnienia programu |

Wersja angielska leży w podkatalogu `kb/en/` (te same cztery pliki) i jest używana, gdy raport powstaje po angielsku (`--lang en` albo skan wykonany po angielsku). Oba języki muszą mieć identyczną strukturę: te same tagi, zestawy, kroki sprawdzenia, procesy i moduły; różni się tylko tekst. Pilnuje tego test `english_base_mirrors_the_polish_one`, więc każdą zmianę w `kb/*.json` trzeba powtórzyć w `kb/en/*.json`. Klucze w sekcji `flags` muszą odpowiadać nazwom cech, które skaner zapisuje w danym języku (np. `poziom integralności` i `integrity level`).

FreeBSD nie ma jeszcze własnego pliku: raport dla niego użyje części wspólnej. Dodanie systemu to nowy plik `kb/<system>.json` i wpis w `crates/nanshe-kb/src/lib.rs` (stała `SYSTEMS` i funkcja `embedded`).

Pliki są wbudowane w binarium przy kompilacji. Nowszą albo własną wersję można wskazać bez przebudowy:

```sh
nanshe report wynik.json --kb /sciezka/do/kb        # albo zmienna NANSHE_KB_DIR
```

Katalog musi zawierać `common.json`; plik systemu jest opcjonalny. Dla raportu angielskiego używany jest podkatalog `en` wskazanego katalogu, jeśli istnieje. Błąd składni w plikach zatrzymuje generowanie raportu z komunikatem, zamiast po cichu wrócić do bazy wbudowanej.

## Co baza wnosi do raportu

| Część raportu | Skąd w bazie | Co robi |
|---|---|---|
| „Jak czytać ten raport" | `guide`, `severity`, `sections` | wstęp bez żargonu, znaczenie wag, opis każdej części raportu |
| „Co to za program" | `processes` | czym zwykle jest program o tej nazwie; porównanie położenia pliku i procesu nadrzędnego z typowymi, z ostrzeżeniem przy rozbieżności |
| „Co oznaczają cechy procesu" | `flags` | objaśnienie pól takich jak seccomp, CapEff, poziom integralności |
| „Pliki zmapowane do pamięci", kolumna opisu | `modules` | czym jest biblioteka; moduły środowisk JIT są zawsze pokazane, bo tłumaczą znaleziska |
| „Co oznaczają znaleziska w tym procesie" | `combos`, `tags` | każdy zestaw cech raz: co oznacza, łagodne i niepokojące wyjaśnienia, wskazówka zależna od tego, czy w procesie jest środowisko JIT, podstawa techniczna i powiązane techniki ATT&CK |
| „Ocena" i „Podsumowanie dla decydenta" | `modules` (rozpoznanie środowiska JIT), nazwy cech | priorytet weryfikacji procesu z uzasadnieniem; reguły priorytetu są w kodzie raportu, baza dostarcza nazwy i rozpoznanie środowisk |
| „Jak sprawdzić ten region" | `verify` | kroki: co zrobić, gotowe polecenie z wstawionym numerem procesu i adresami regionu oraz wskazówka, jak czytać wynik (co jest zwykłe, co powinno zaniepokoić, co zrobić dalej) |
| „Procesy i cechy", „Rozmiar i entropia regionów", „Skróty SHA-256" | `sections` | opis, jak czytać macierz, wykres rozrzutu i tabele skrótów |
| „Słowniczek" i „Legenda" | `terms`, `tags` | pojęcia użyte w raporcie |

Słowniczek tagów w zapytaniu do modelu (pole `en` w `tags`) też pochodzi z bazy, więc raport i model korzystają z jednego opisu.

## Zasady, których baza się trzyma

- **Baza objaśnia, nie punktuje.** Wagi i znaleziska ustalają wyłącznie detektory. Ostrzeżenie „plik leży w nietypowym miejscu" nie zmienia wyniku regionu.
- **Nazwa procesu to tylko wskazówka.** Proces może nazwać się dowolnie, więc opis programu zawsze idzie w parze ze sprawdzeniem ścieżki i przypomnieniem o skrócie SHA-256.
- **Raport nie zgaduje.** Wskazówka o środowisku JIT pojawia się tylko, gdy wynik zawiera mapę regionów procesu. Zestaw cech bez własnego opisu jest składany z opisów pojedynczych cech.
- **Każde wyjaśnienie ma dwie strony.** Zestaw cech musi mieć co najmniej jedno łagodne i jedno niepokojące wyjaśnienie; pilnuje tego test.
- **Dwie warstwy.** Każda cecha ma opis zrozumiały bez przygotowania (`meaning`, `why`) i warstwę techniczną dla doświadczonego czytelnika (`tech`: dokładny warunek detektora; `attack`: powiązane techniki MITRE ATT&CK). Warstwa techniczna zależna od systemu leży w pliku systemu i jest scalana z opisem wspólnym. Odniesienia do ATT&CK są orientacyjne i raport mówi wprost, że znalezisko nie dowodzi użycia techniki.
- **Prosty język.** Zdania bez skrótów branżowych; pojęcia, których nie da się uniknąć, są w słowniczku. Bez długich myślników (sprawdza test).

## Format plików

Każdy plik to jeden obiekt JSON. Plik systemu jest nakładany na wspólny: obiekty są scalane po kluczach (wpis systemu wygrywa), a listy sklejane (wpisy systemu mają pierwszeństwo przy wyszukiwaniu).

```json
{
  "tags":   { "RWX": { "name": "krótka nazwa", "en": "definicja dla modelu", "meaning": "co to jest", "why": "dlaczego ma znaczenie",
                       "tech": "dokładny warunek detektora", "attack": ["T1055 Process Injection"] } },
  "combos": [ { "tags": ["RWX", "X-PRIV"], "title": "...", "meaning": "...",
                "benign": ["..."], "malicious": ["..."],
                "hints": [ { "runtime": true, "text": "... {runtime} ..." }, { "runtime": false, "text": "..." } ] } ],
  "verify": { "*": [{ "do": "co zrobić", "cmd": "polecenie {pid} {start} {end} {start_plain} {size}", "look": "jak czytać wynik" }], "HDR": [{ "do": "krok tylko dla tego tagu", "cmd": "", "look": "..." }] },
  "processes": [ { "names": ["svchost.exe"], "what": "...", "paths": ["\\windows\\system32\\svchost.exe"], "parents": ["services.exe"] } ],
  "modules":   [ { "names": ["clr.dll"], "what": "...", "runtime": ".NET Framework" },
                 { "names": ["v8_context_snapshot"], "what": "...", "runtime": "Chromium", "family": "aplikacja zbudowana na ..." } ],
  "flags":   { "seccomp": "objaśnienie; klucz jest początkiem nazwy cechy" },
  "handles": { "file": "..." },
  "terms":   { "entropia": "..." }
}
```

- `combos.tags`: dokładny zestaw cech regionu, kolejność bez znaczenia.
- `hints.runtime`: `true` pokazuje wskazówkę, gdy wśród zmapowanych plików procesu jest moduł z polem `runtime`; `false`, gdy takiego nie ma.
- `processes.names` i `parents`: małe litery, także na macOS, gdzie nazwy programów mają wielkie litery (`windowserver`); wyszukiwanie zamienia nazwę z wyniku na małe litery, a test `names_and_paths_are_lowercase_so_that_lookups_can_match` odrzuca wpis z wielką literą. `paths`: małe litery, bez litery dysku. Wpis bez końcowego separatora to dokładna ścieżka pliku; z końcowym separatorem oznacza plik bezpośrednio w tym katalogu; z końcówką `**` dowolnie głęboko w nim. Na Windows plik musi dodatkowo leżeć na dysku systemowym (zapisanym w wyniku skanu; gdy go brak, przyjmowany jest `C:`). Puste listy oznaczają brak oczekiwań i brak oceny.
- `modules.names`: początek nazwy pliku (małe litery), np. `libssl` pasuje do `libssl.so.3`.

## Rodziny programów

Aplikacji zbudowanych na silniku przeglądarki Chromium (Electron, Qt WebEngine, CEF) jest zbyt wiele, żeby opisywać je po nazwie. Baza rozpoznaje je po plikach silnika zmapowanych do pamięci; służy do tego pole `family` wpisu w `modules`:

| Plik | Rodzina | Środowisko JIT w procesie |
|---|---|---|
| `v8_context_snapshot.bin` | Electron i przeglądarki oparte na Chromium (Windows, Linux) | tak |
| `Electron Framework`, `Chromium Embedded Framework`, `Google Chrome Framework` | to samo na macOS | tak |
| `Qt5WebEngineCore`, `Qt6WebEngineCore` | Qt WebEngine | tak |
| `EmbeddedBrowserWebView.dll`, `WebView2Loader.dll`, `Microsoft.Web.WebView2.*` | program korzystający z WebView2 | nie: silnik działa w procesach `msedgewebview2.exe` |

Pole `family` robi dwie rzeczy:

- **Opis programu o nieznanej nazwie.** W części „Co to za program" raport podaje rodzaj programu zamiast samego „baza nie opisuje programu o tej nazwie". Opis mówi, jak program jest zbudowany, a nie kto go wydał.
- **Przeniesienie rozpoznania na inne procesy tego samego pliku.** Aplikacja Electron działa jako kilka procesów jednego pliku `.exe` i nie każdy z nich mapuje pliki silnika (zmierzone 2026-11-26: z pięciu procesów jednej aplikacji z regionami o wadze „wysokie" plik silnika miały dwa). Jeżeli środowisko rozpoznano w innym procesie o tej samej ścieżce pliku programu, raport przyjmuje je także dla tego procesu i pisze wprost, z którego procesu pochodzi rozpoznanie.

Przeniesienie działa tylko dla wpisów z polem `family`. Biblioteka .NET w jednym procesie `svchost.exe` nic nie mówi o pozostałych, więc `clr.dll` tego pola nie ma.

Przejęte środowisko nie tłumaczy wzorca kodu samodzielnego. Proces z regionem o wadze „wysokie" i znaleziskiem `SHC` o wadze co najmniej 30, w którego własnych plikach środowiska nie rozpoznano, dostaje P1 z osobnym uzasadnieniem. Środowisko rozpoznane we własnych plikach procesu działa jak dotąd (P2). Na czterech zapisanych skanach (2026-11-27) reguła nie zmieniła żadnego priorytetu: żaden proces z przejętym środowiskiem nie miał takiego znaleziska.

Pomiar wpisów dla Linuksa (2026-11-27, kontener arm64): Electron 30.5.1 mapuje `v8_context_snapshot.bin` we wszystkich sześciu procesach aplikacji, a aplikacja PyQt5 mapuje `libQt5WebEngineCore.so.5` w procesie głównym i w trzech procesach `QtWebEngineProcess`. To po jednej aplikacji z każdej rodziny.

Ograniczenia:

- Rozpoznanie opiera się na nazwie zmapowanego pliku. Program, który zmapuje własny plik o nazwie `v8_context_snapshot.bin`, dostanie łagodniejsze uzasadnienie (P2 zamiast P1); to samo dotyczy każdego wpisu `modules` ze środowiskiem. Dlatego P2 zawsze każe potwierdzić znalezisko, a cechy, których środowisko nie tłumaczy (`THR-PRIV`, `HDR`, `IMG-MOD` o wysokiej wadze i pozostałe z tej listy), dają P1 niezależnie od rozpoznania.
- Rozpoznanie zmienia priorytet weryfikacji i objaśnienia w raporcie. Nie zmienia punktacji ani wag: te ustalają detektory.
- Bez ścieżki pliku programu w wyniku przeniesienie nie działa; nazwa procesu do tego nie służy.

## Jak dodać wpis

1. Dopisz wpis w odpowiednim pliku `kb/`.
2. Uruchom `scripts/dev.sh cargo test -p nanshe-kb -p nanshe-report`. Testy sprawdzają między innymi, że każdy tag zgłaszany przez detektory danego systemu ma opis, że zestawy odwołują się do znanych tagów i nie dublują się, że każde polecenie sprawdzające ma wypełnione wszystkie pola i że tekst nie zawiera długich myślników.
3. Wygeneruj raport z próbki i przeczytaj nowy fragment oczami osoby spoza branży.

## Ograniczenia

- Treść jest po polsku i po angielsku; każdą zmianę trzeba wprowadzić w obu wersjach.
- Opisy procesów i modułów to kilkadziesiąt najczęstszych pozycji, nie katalog oprogramowania. Program nieopisany w bazie dostaje w raporcie informację, że brak opisu nie jest oceną.
- Typowe ścieżki i rodzice dotyczą standardowych instalacji. Niestandardowa instalacja da ostrzeżenie, które trzeba wyjaśnić ręcznie.
- Polecenia sprawdzające zakładają dostęp administratora i obecność narzędzi (gdb, Sysinternals, System Informer, pe-sieve); raport ich nie uruchamia.
- Kroki dla `SHC` sprawdzono 2026-11-27: deasemblację debuggerem Windows (`cdb`) na próbce na stacji testowej oraz `objdump` i `strings` na kodzie x86-64 i arm64 w kontenerach. Składnię `pe-sieve` i opis jego podsumowania porównano z kodem źródłowym narzędzia, bez uruchomienia. Kroku `lldb` na macOS nie uruchomiono (wymaga uprawnień root).
- Wyjaśnienia opisują typowe przypadki i pochodzą z wiedzy ogólnej, nie z pomiaru na dużej liczbie stacji.
