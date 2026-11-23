<p align="center"><img src="img/logo/nanshe-logo.svg" alt="Nanshe" width="420"></p>

# Nanshe

Triage pamięci: wskazuje regiony, którym powinien przyjrzeć się człowiek. Pełny opis: [docs/pl/dokumentacja-0.1.0.md](docs/pl/dokumentacja-0.1.0.md). Wersja angielska tego pliku: [README.md](README.md).

## Build i testy (kontener Linux, podman)

```sh
scripts/dev.sh cargo test --workspace --features nanshe-cli/llm   # testy jednostkowe
scripts/dev.sh sh scripts/e2e.sh                                  # próbki -> skan na żywo
scripts/dev.sh cargo build --release -p nanshe-cli                # binarium bez kodu sieciowego
scripts/dev.sh cargo build --release -p nanshe-cli --features llm # z warstwą LLM (stacja analityka)
```

## Windows (natywnie, toolchain MSVC)

```powershell
cargo build --release -p nanshe-cli -p nanshe-samples --features nanshe-cli/llm
powershell -ExecutionPolicy Bypass -File scripts\e2e.ps1 -Bin target\release -Out e2e-out
```

Testy end-to-end i testy instalatorów zmieniają stację, na której działają (uruchamiają próbki, instalują i usuwają program): tylko na dedykowanej stacji testowej.

Skan wymaga administratora (SeDebugPrivilege); procesy chronione (PPL) są raportowane jako niedostępne.

## Graficzna mapa pamięci

`nanshe` bez argumentów zbiera metadane wszystkich widocznych procesów, zapisuje
`nanshe.memory.html` i otwiera lokalny raport w przeglądarce. Raport działa offline,
bez serwera, zależności CDN i wysyłania danych. Nie czyta treści pamięci ani nie uruchamia detektorów.

```sh
nanshe map --json host.memory.json                 # wszystkie procesy, HTML + metadane
nanshe map --pid 1234 --output proces.memory.html
nanshe map --input host.memory.json                # otwarcie migawki, także na macOS
nanshe map --no-open                               # maszyna bez środowiska graficznego
```

Raport zawiera wybór i wyszukiwanie procesu, pasek regionów uporządkowanych po adresach,
grupowanie po ścieżce pliku, adresy i rozmiary, R/W/X, offset pliku oraz device:inode na Linuksie, RSS/PSS na Linuksie (gdy dostępne),
filtry wykonywalności, RWX i usuniętych plików. Sygnały metadanych nie są diagnozą infekcji.
Rozmiar wirtualny nie jest zajętością RAM; mapa pomija luki i nie reprezentuje pamięci fizycznej.
Nazwy bibliotek są rozpoznawane heurystycznie; pliki nie są haszowane ani weryfikowane.
Windows pokazuje tylko MEM_COMMIT; RSS/PSS i zgodność ścieżki NT ze ścieżką programu mogą być nieznane.
Błędy i ograniczenia są widoczne w raporcie; kod 3 oznacza ograniczony wynik.
Procesy są odczytywane kolejno, więc nie jest to atomowa migawka systemu.
JSON i HTML zawierają nazwy procesów, hosta i ścieżki: traktuj je jako dane wrażliwe.

W kontenerze użyj `scripts/dev.sh cargo run -p nanshe-cli -- map --no-open`; wynik opisuje
procesy **kontenera**, a HTML otwórz na hoście. Live działa na Linux/Windows; macOS pozostaje
stacją analityka z opcją `--input`.

## Użycie

```sh
nanshe ps
nanshe scan --pid 1234 --json wynik.json
nanshe scan --all --min high
nanshe llm check --url http://127.0.0.1:11434
nanshe explain wynik.json --dry-run            # pokazuje, co zostałoby wysłane
nanshe explain wynik.json --model gemma3:12b   # zapisuje wynik.llm.json
```

Raport dla człowieka (Markdown i PDF, czcionka wbudowana, bez zewnętrznych programów):

```sh
nanshe report wynik.json                 # wynik.report.md + wynik.report.pdf; dołącza wynik.llm.json, jeśli istnieje
nanshe report wynik.json --no-llm --min high --pdf raport.pdf
```

Raport ma być samodzielnym dokumentem dla analityka. Poza znaleziskami zawiera to, co skan zebrał o procesie poza pamięcią (schodzimy od pamięci do systemu):

- kontekst procesu: wiersz poleceń, użytkownik, czas startu, plik programu ze skrótem SHA-256, cechy bezpieczeństwa,
- drzewo procesów (przodkowie i dzieci), gniazda sieciowe, otwarte pliki, pliki zmapowane do pamięci,
- diagram całej przestrzeni adresowej z zaznaczonymi znaleziskami,
- dla każdego regionu: sąsiedzi, profil entropii, podgląd bajtów, odczytane pola nagłówka ELF/PE, ciągi tekstowe, skrót SHA-256 zawartości,
- diagram „od pamięci do sieci": regiony ze znaleziskami, proces i jego połączenia z chwili skanu,
- przegląd całego hosta: macierz procesy x cechy i wspólne drzewo procesów ze znaleziskami; dla procesu wykres rozmiar x entropia regionów,
- skróty SHA-256 plików programów wszystkich procesów i plików zmapowanych w procesach ze znaleziskami (`--no-hashes` wyłącza).

Zrzut pamięci procesu (plik core z Linuksa, minidump z Windows) analizuje się tym samym poleceniem: `nanshe scan plik-zrzutu --json wynik.json`; opis w [dokumentacji](docs/pl/dokumentacja-0.1.0.md), rozdział 4.

Dwa skany tej samej stacji można porównać: `nanshe diff wczesniej.json pozniej.json` daje raport różnicowy (nowe regiony w działających procesach, nowe i zakończone procesy ze znaleziskami, zmiany w sieci i plikach).

Raport i opisy w wyniku skanu są dostępne po polsku i po angielsku: `nanshe --lang en scan ...`, potem `nanshe report ...` (raport powstaje w języku skanu; opis w [dokumentacji](docs/pl/dokumentacja-0.1.0.md), rozdział 4).

Żeby raport dało się czytać bez przygotowania z analizy pamięci, każda część ma objaśnienie prostym językiem z bazy wiedzy (`kb/`): czym jest program, co oznacza dany zestaw cech, jakie są łagodne i niepokojące wyjaśnienia i jakim poleceniem sprawdzić region. Opis: [docs/pl/baza-wiedzy.md](docs/pl/baza-wiedzy.md).

Kontekst jest zbierany tylko dla procesów ze znaleziskami od wagi „podejrzane"; `nanshe scan --no-context` go wyłącza. Raport i plik wyniku zawierają wtedy dane ze stacji bez filtrowania (wiersze poleceń, ścieżki, adresy, bajty z pamięci), więc trzeba je traktować jak materiał dowodowy. Model LLM tych danych nie dostaje. Przykład: [docs/examples/](docs/examples/).

`nanshe explain` generuje ten raport sam po zakończeniu interpretacji (`--no-report` wyłącza). Raport nie przyjmie interpretacji innego wyniku skanu (sprawdzane po SHA-256).

Chmura (dane wychodzą poza własną sieć, więc tylko za jawną zgodą):

```sh
nanshe cloud list providers                               # nous, anthropic, google, openai
nanshe cloud list models --provider nous --key-file nous.key --filter claude
nanshe explain wynik.json --llm nous --dry-run            # podgląd ładunku, bez klucza i bez sieci
nanshe explain wynik.json --llm nous --allow-cloud --key-file nous.key
```

Klucz: `NOUS_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY`, `NANSHE_<DOSTAWCA>_KEY_FILE` albo `--key-file`. Chmura dostaje domyślnie poziom d0 (same metadane), d1 po `--data-level d1`, d2 nigdy; nazwa hosta, użytkownicy w ścieżkach i adresy IP są zastępowane etykietami.

Ollama po czystym HTTP poza loopback wymaga `--insecure-llm`; docelowo tunel SSH (`ssh -L 11434:127.0.0.1:11434 <host>`) albo proxy z TLS.

Wynik skanu zawiera fragmenty pamięci (do 256 B na znalezisko), więc może zawierać sekrety; `--no-bytes` je wyłącza.

## Dokumentacja

- [docs/pl/baza-wiedzy.md](docs/pl/baza-wiedzy.md): baza wiedzy (`kb/`), z której raport bierze objaśnienia prostym językiem; jak ją rozszerzać
- [docs/examples/](docs/examples/): przykładowy raport z próbki syntetycznej, z interpretacją LLM i bez (`.md` i `.pdf`)
- [docs/pl/dokumentacja-0.1.0.md](docs/pl/dokumentacja-0.1.0.md): pełny opis wersji 0.1.0: możliwości, budowa, detektory, plik wyniku, raport, bezpieczeństwo, co sprawdzono i czego narzędzie nie umie
- [docs/pl/linux.md](docs/pl/linux.md), [docs/pl/windows.md](docs/pl/windows.md), [docs/pl/macos.md](docs/pl/macos.md): build, uprawnienia, detektory i ograniczenia per system
- [docs/pl/testy.md](docs/pl/testy.md): wszystkie testy, co sprawdzają i czego nie obejmują

## Licencja

Apache License 2.0; pełny tekst jest w pliku [LICENSE](LICENSE), informacje o prawach autorskich w [NOTICE](NOTICE). Program jest rozpowszechniany bez jakiejkolwiek gwarancji.

Copyright 2026 HoneyLens.

Składniki na innych licencjach: czcionka DejaVu wbudowana w raport PDF ([LICENSE-DejaVu.txt](crates/nanshe-report/fonts/LICENSE-DejaVu.txt)) oraz biblioteki Rust na licencjach zezwalających (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode).
