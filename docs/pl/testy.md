# Testy Nanshe

Wersja angielska: [../tests.md](../tests.md).

Trzy warstwy: testy jednostkowe (logika, bez żywych procesów), testy end-to-end na żywych próbkach (Linux w kontenerze, Windows na dedykowanej stacji testowej) i przebiegi na żywo z modelami. Zasada wspólna: **każdy test musi umieć oblać**. Dlatego testy są parami: przypadek, który ma dać wynik, i kontrola różniąca się jedną cechą, która ma go nie dać.

## Jak uruchomić

```sh
scripts/dev.sh cargo test --workspace --features nanshe-cli/llm   # jednostkowe (Linux, kontener)
scripts/dev.sh sh scripts/e2e.sh                                  # e2e Linux
powershell -ExecutionPolicy Bypass -File scripts\e2e.ps1 -Bin target\release -Out e2e-out   # e2e Windows, natywnie na stacji testowej
```

Kod wyjścia skryptów e2e: 0 gdy wszystko zgodne, 1 gdy cokolwiek odbiega.

## Stan na 2026-11-23

| Warstwa | Wynik |
|---|---|
| Testy jednostkowe | 128 przechodzi (analyze 24, core 3, dump 5, kb 7, live 20, llm 40, report 29) |
| e2e Linux (aarch64, kontener) | 16 próbek statycznych, 2 dynamiczne i 8 grup asercji dodatkowych |
| e2e Windows (stacja testowa, x64) | 14 próbek, próbka kontekstu, 2 dynamiczne i 8 grup asercji dodatkowych |
| Model lokalny na żywo | `gemma3:12b` na lokalnej Ollamie |
| Chmura na żywo | Nous: `anthropic/claude-opus-5.5` (d0), `anthropic/claude-haiku-5.5` (d1) |
| Chmura bez próby na żywo | `anthropic`, `google`, `openai` bezpośrednio: tylko testy kształtu zapytań (brak kluczy) |

Nie ma: CI, fuzzingu parsera `maps`, testów na Linuksie x86_64, zestawu oceny jakości modeli.

## Testy jednostkowe

### `nanshe-analyze` (detektory i punktacja)

| Test | Co sprawdza | Kontrola |
|---|---|---|
| `clean_process_has_no_findings` | kod z pliku i dane RW o wysokiej entropii nie dają znalezisk | - |
| `rwx_anon_high_entropy_is_high` | RWX + anonimowy + entropia daje trzy tagi, wagę „wysokie" i podgląd 256 bajtów | - |
| `each_condition_is_necessary` | usunięcie jednej cechy (W, X, brak pliku, entropia) gasi odpowiadający jej tag | to jest test mutacyjny |
| `memfd_and_deleted` | `MEMFD` i `DEL-EXEC` na Linuksie | brak tych tagów na Windows sprawdza `x_map_is_windows_only...` |
| `x_tmp_flags_exec_from_world_writable_dir` | `X-TMP` (30 punktów, „podejrzane") dla wykonywalnego mapowania pliku z `/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm` | katalog systemowy, brak prawa wykonania, Windows: brak; plik usunięty daje tylko `DEL-EXEC` |
| `hdr_only_without_backing` | `HDR` dla nagłówka w regionie bez pliku, z adresem strony | ten sam nagłówek w regionie z plikiem: brak |
| `hdr_found_at_any_offset_with_same_validation` | w regionie wykonywalnym nagłówek ELF i PE jest wykrywany pod dowolnym przesunięciem, z adresem i przesunięciem w opisie | ten sam nagłówek w danych RW, uszkodzone pole ELF, `MZ` bez `PE`, Mach-O poza początkiem strony, dane losowe: brak |
| `windows_jit_needs_verified_exe_and_system_runtime_image` | Windows: sterta JIT w procesie z systemowym .NET spada z 60 do 20 punktów, `X-MAP` z 30 do 10, znaleziska zostają widoczne ze stałym znacznikiem | program spoza katalogów systemowych, brak modułu środowiska, plik zmapowany jako dane, `clr.dll` z profilu użytkownika, z `\Windows\Temp`, z podkatalogu udającego `\Windows\` albo spoza katalogu środowiska: bez obniżki; wykonywalne mapowanie pliku (`X-MAP` z plikiem) nigdy nie jest obniżane; ładunek o wysokiej entropii zostaje „podejrzany", a nagłówek obrazu nie jest obniżany |
| `detectors::headers` (PE) | nagłówek PE wymaga niezerowego pola Machine i 1-96 sekcji | `MZ...PE` z zerowym Machine albo bez sekcji: brak |
| `thread_in_memory_without_a_file_is_flagged_at_full_weight` | `THR-PRIV` (40 punktów) dla wątku ulokowanego w pamięci bez pliku; w procesie ze środowiskiem JIT `X-PRIV` jest obniżany, a `THR-PRIV` nie | wątek w kodzie z pliku, brak wątków, region jądra `[vdso]`: brak |
| `modified_code_of_a_file_is_flagged_only_in_read_only_executable_mappings` | `IMG-MOD` dla zmienionego kodu z pliku: 40 punktów na Linuksie i dla `amsi.dll` na Windows, 10 dla zwykłej biblioteki Windows | brak zmian, zero bajtów, dane bez prawa wykonania, kod zapisywalny, pamięć bez pliku: brak |
| `region_limit_keeps_findings_and_marks_result_incomplete` | mapa o długości limitu: znaleziska sprzed limitu zostają, wynik procesu ma błąd o obcięciu | poniżej limitu: wynik pełny, bez błędu |
| `unreadable_region_does_not_allocate_its_full_size` | nieczytelny region 64 MiB nie powoduje alokacji 64 MiB | - |
| `ent_x_in_file_backed_code_needs_large_share` | pojedyncze strony o wysokiej entropii w kodzie z pliku dają 10 punktów, nie 20/30 | udział powyżej 25% stron: pełna waga |
| `x_map_is_windows_only_and_needs_exec_mapped` | `X-MAP` dla wykonywalnego `MEM_MAPPED` | bez X, obraz modułu, Linux: brak |
| `guarded_exec_region_is_flagged_and_counted_unreadable` | `GUARD-X`, region liczony jako nieodczytany, 0 bajtów przeczytanych mimo nagłówka PE w danych | ten sam region bez strażnika jest czytany i daje `HDR`; strażnik bez X nie jest znaleziskiem |
| `jit_allowlist_lowers_but_shows` | lista dozwolonych obniża wynik z 60 do 20, znaleziska zostają widoczne, w wyniku jest stały znacznik `jit:node` | plik niezweryfikowany, nieznany, usunięty albo spoza zaufanych katalogów: bez obniżki, mimo nazwy procesu `node` |
| `unreadable_region_is_counted_and_scan_continues` | błąd odczytu jednego regionu nie przerywa skanu | - |
| `deterministic_and_no_bytes` | dwa skany tego samego źródła dają identyczny wynik; `--no-bytes` usuwa podgląd | - |
| `detectors::headers`, `entropy::bounds`, `entropy::pages_and_heat` | rozpoznawanie PE/ELF/Mach-O (w tym `MZ` bez `PE`), granice entropii 0-8, mapa ciepła | - |
| `profile_downsamples_with_max` | profil entropii regionu: najwyżej 64 odcinki, w odcinku liczy się maksimum | pusty region: pusty profil |
| `strings_found_in_ascii_and_utf16_and_noise_rejected` | ciągi tekstowe ASCII i UTF-16LE, bez powtórzeń, z limitem liczby | ciąg samych znaków specjalnych i ciąg krótszy niż 10 znaków są odrzucane |

### `nanshe-live`

- `maps::parses`: parser `/proc/<pid>/maps`, w tym nazwy ze spacjami i sufiks `(deleted)`.
- Kontekst systemowy, Linux (`sysctx`): `stat_with_hostile_name` (nazwa procesu ze spacjami i nawiasami nie przesuwa pól `stat`), `status_and_cmdline`, `addresses_and_tables` (adresy IPv4/IPv6 i stany z `/proc/net/tcp`; wiersz bez i-węzła jest pomijany; gniazda uniksowe z nazwą ze spacją i bez nazwy), `descriptors_users_and_loader_env` (rodzaje deskryptorów, sufiks `(deleted)`; ze środowiska brane są tylko zmienne ładowania kodu, zmienna z sekretem nie jest zbierana).
- Wątki i zmieniony kod, Linux (`sysctx::thread_pc_and_modified_pages`): adres instrukcji z pliku `syscall` wątku (wątek działający i błędne dane dają brak adresu) oraz strony anonimowe mapowań z `smaps` (pole bez nagłówka mapowania jest ignorowane).
- Skróty plików (`sysctx::hashing_opens_once_and_takes_only_regular_files`): skrót znanej zawartości; katalog, brak pliku, urządzenie znakowe i potok nazwany bez piszącego nie dają skrótu i nie zawieszają skanu.
- Uprawnienia skanera: `sysctx::scanner_privileges_from_status` (root z `CAP_SYS_PTRACE` pełne; root bez niej i zwykły użytkownik niepełne) oraz `wintables::scanner_privileges_follow_integrity_and_debug_privilege` (poziom wysoki albo systemowy z `SeDebugPrivilege` pełne; poziom średni albo brak `SeDebugPrivilege` niepełne).
- Ścieżki sieciowe (`wintables::network_paths_are_never_treated_as_local`): UNC, `\Device\Mup`, `LanmanRedirector`, WebDAV i urządzenia inne niż wolumen dyskowy nie są uznawane za lokalne.
- Kontekst systemowy, Windows (`wintables`): `tcp_and_udp_tables` (tabele gniazd z właścicielem, porty w kolejności sieciowej; licznik większy niż dane i obcięty bufor nie powodują paniki), `handle_table_filtered_by_pid` (tabela uchwytów systemu filtrowana po PID, rodzaje obiektów, prawa do obcego procesu; kontrola: samo prawo zapytania o metadane nie jest oznaczane), `exe_must_sit_under_a_system_root` (program w katalogu systemowym; kontrole: `C:\temp`, profil użytkownika, `C:\WindowsEvil`, inny dysk, ścieżka z `..`, podkatalogi `\Windows` zapisywalne dla użytkowników; właściciel pliku: SYSTEM i Administratorzy tak, zwykły użytkownik i grupa Użytkownicy nie), `time_and_integrity` (czas FILETIME, poziomy integralności). Parsery działają na surowym buforze, więc te testy przechodzą także na Linuksie; samych wywołań API sprawdza tylko e2e na stacji testowej Windows.
- `exe_trust_requires_every_condition`: plik programu jest zaufany tylko, gdy spełnia wszystkie warunki naraz (właściciel root, brak zapisu dla grupy i innych, ten sam i-węzeł); zmiana jednego warunku odbiera zaufanie.

### `nanshe-llm` (warstwa interpretacji)

Backend jest w tych testach atrapą, więc sieć nie jest potrzebna.

| Obszar | Testy | Co sprawdzają |
|---|---|---|
| Przebieg | `per_process_region_limit_skips_without_calls` (limit regionów na proces: reszta jest pomijana bez zapytania; kontrola bez limitu), `happy_path_and_scan_untouched`, `backend_failure_gives_partial_result`, `correlation_and_call_limit`, `cache_reuses_valid_answer`, `dry_run_sends_nothing`, `oversized_prompt_refused_not_truncated` | wynik skanu nie jest zmieniany; awaria backendu daje wynik częściowy; limit zapytań; pamięć podręczna; `--dry-run` nie woła backendu; za długie zapytanie jest odrzucane, nie obcinane |
| Walidator | `accepts_valid`, `rejects_each_violation`, `benign_is_never_established`, `explanation_without_reasoning_is_rejected`, `correlation_never_drops_regions`, `hallucinated_reference_retried_then_rejected` | etykieta i pewność spoza słownika, odwołanie do nieistniejącego znaleziska, brak dowodów, dodatkowe pola, hipoteza łagodna z pewnością „ustalone", puste uzasadnienie: każde osobno odrzucane; pominięte regiony są dopisywane do kolejności przeglądu |
| Dane wychodzące | `d0_leaks_nothing_from_memory_or_user_paths`, `d1_redacts_secrets_d2_keeps`, `secrets_detected`, `strings_extracted`, `region_strings_reach_the_model_through_the_same_filters` | poziom d0 nie zawiera niczego z pamięci ani ścieżek użytkownika; d1 wycina sekrety (klucze PEM, JWT, przedrostki tokenów GitHub, GitLab, Slack, AWS, Google, Docker, dane logowania w adresach, ciągi o wysokiej entropii); d2 je zostawia; nazwa funkcji i zwykły adres nie są sekretem (kontrola); ciągi z całego regionu (także UTF-16) trafiają do modelu przez te same filtry sekretów i wstrzyknięć, a na poziomie d0 nie trafiają wcale |
| Wstrzyknięcia | `injection_marked_and_removed`, `injection_marker_and_text_not_sent`, `process_controlled_fields_are_filtered` | tekst wyglądający na instrukcję nie trafia do modelu, znacznik `LLM-INJECT` jest podnoszony; dotyczy też nazwy procesu, ścieżek i opisów |
| Adres modelu | `plain_http_only_to_loopback` | czyste HTTP tylko do loopback; adresy z danymi logowania, zapytaniem albo sztuczkami parsera są odrzucane |
| Chmura: zasady | `cloud_never_gets_d2`, `providers_built_in` | brak `--allow-cloud` i poziom d2 to odmowa, także gdy wywołujący pominie sprawdzenie; lokalnie d2 jest dozwolone (kontrola); czterej dostawcy, wszyscy `https` |
| Chmura: pseudonimizacja | `cloud_payload_pseudonymized_and_answer_reversed`, `replaces_host_users_and_ips_and_reverses`, `not_an_ip_is_left_alone`, `reverse_never_breaks_json`, `case_and_short_host_do_not_bypass`, `known_value_never_splits_a_longer_name`, `known_value_inside_a_token_masks_the_whole_token`, `retry_feedback_does_not_leak_restored_values`, `generic_host_name_does_not_break_paths_or_words`, `ipv6_is_masked_and_lookalikes_are_not` | host, użytkownicy w ścieżkach i adresy IPv4 nie wychodzą; odpowiedź ma przywrócone wartości; bez trybu chmury dane idą bez zmian (kontrola); numery wersji nie są mylone z adresami; inna wielkość liter i krótka nazwa hosta nie omijają podmiany; znana nazwa wewnątrz dłuższego tokenu (`jkowalski_backup`) maskuje cały token; krótka wartość w zwykłym słowie (`ann` w `scanner`) zostaje (kontrola i zarazem znana luka); ponowione zapytanie nie zawiera przywróconych wartości; host o nazwie `dev` albo `win` nie psuje `/dev/shm` ani `Windows`, ale jest podmieniany jako słowo, w adresie URL i ścieżce UNC; adresy IPv6 są podmieniane, a znaczniki czasu, adresy MAC i `std::string` nie |
| Chmura: zapytania | `openai_body_follows_supported_params`, `anthropic_body_has_no_sampling_params`, `strict_schema_drops_only_item_bounds`, `responses_parsed_and_failures_named`, `models_parsed_from_both_api_styles`, `key_from_file_must_be_a_single_token` | temperatura, ziarno i schemat idą tylko, gdy model je obsługuje; odmowa, obcięcie i pusta odpowiedź mają nazwane błędy; plik klucza z czymś więcej niż klucz jest odrzucany |

Nowe w tej wersji (analiza i odczyt na żywo):

- `header_with_wiped_signature_is_recognised_by_its_tables` (analyze): nagłówek PE bez `MZ`, bez `PE` albo z wyzerowanym początkiem strony oraz nagłówek ELF bez sygnatury są rozpoznawane po tablicy sekcji albo segmentów; nagłówek z sygnaturą nie jest zgłaszany drugi raz; kontrole: jedna sekcja, brak sekcji wykonywalnej, adresy nierosnące, dane losowe, zera, tekst z nazwami sekcji, jeden segment ładowany.
- `modified_code_of_a_file_is_flagged_only_in_read_only_executable_mappings` (analyze) obejmuje też wynik porównania z plikiem: liczba bajtów i adres w opisie, 10 punktów dla zwykłej biblioteki Windows i 40 dla modułu ochronnego; kontrola: porównanie bez różnic nie daje znaleziska.
- `relocated_image_matches_the_file_and_a_patch_is_counted` (live, `pediff`): obraz PE po relokacji pod trzy różne adresy nie różni się od pliku; pięć zmienionych bajtów jest policzonych z adresem pierwszego; kontrole: bez naniesienia relokacji i dla pliku bez tablicy relokacji różnice są widoczne.
- `garbage_and_truncated_files_do_not_panic` (live, `pediff`): śmieci, każde obcięcie pliku i każdy bajt nagłówków ustawiony na 0xff nie powodują awarii; uszkodzona tablica relokacji (blok poza tablicą, nieznany typ wpisu) oznacza brak porównania po załadowaniu pod inny adres; katalog relokacji deklarujący 4 GiB nie zajmuje skanera (limit czasu w teście).
- `image_header_in_memory_must_match_the_file` (live, `pediff`): nagłówek w pamięci ze zmienionym adresem załadowania odpowiada plikowi; inny znacznik czasu, liczba sekcji, rozmiar obrazu albo suma kontrolna oznacza inny plik; wymazany nagłówek i plik niebędący obrazem nie dają potwierdzenia.
- Zgodność treści z plikiem o niepotwierdzonej tożsamości nie wygasza znaleziska (część testu `modified_code_of_a_file_...`): zostaje 10 punktów z opisem, że tożsamości pliku nie potwierdzono.
- `headers_decoded_and_garbage_ignored` (report) obejmuje nagłówek PE pod przesunięciem 0xf0 w podglądzie 256 bajtów (format, sekcje i znacznik czasu są odczytywane bez pola rodzaju pliku).

### `nanshe-dump` (zrzuty pamięci procesów)

| Test | Co sprawdza |
|---|---|
| `core_file_gives_regions_threads_names_and_memory` | plik core (x86_64 i aarch64): regiony z uprawnieniami, nazwy plików z NT_FILE (w tym `memfd` i plik usunięty), stos rozpoznany po wskaźniku stosu wątku, vdso po wektorze pomocniczym (kontrola: taki sam region bez wpisu nie dostaje etykiety), wątki z licznikiem rozkazów, nazwa, PID, ścieżka programu; odczyt daje tyle, ile jest w zrzucie, kończy na luce, a brak treści to błąd, nie zera |
| `hostile_headers_do_not_panic_or_read_outside_the_file` | plik core: segment deklarujący treść poza plikiem jest przycinany i odnotowany; tablica segmentów poza plikiem, zły typ pliku i zrzut 32-bitowy dają błąd; każde obcięcie pliku i notatka z rozmiarem przepełniającym licznik nie powodują awarii |
| `minidump_gives_regions_modules_threads_and_memory` | minidump: regiony z uprawnieniami i rodzajem jak w skanie na żywo, moduł przypisany do regionu obrazu, strona strażnika i strona bez dostępu jako nieczytelne, adresy startu wątków; odczyt przechodzi przez przylegające fragmenty i kończy na luce |
| `hostile_minidump_does_not_panic_or_read_outside_the_file` | minidump: każde obcięcie pliku i każdy bajt nagłówka oraz katalogu ustawiony na 0xff nie powodują awarii ani odczytu poza plik; nieprawdopodobna liczba strumieni to błąd |
| `unknown_or_short_files_are_rejected` | plik pusty, za krótki i tekstowy są odrzucane |

### `nanshe-kb` (baza wiedzy)

| Test | Co sprawdza |
|---|---|
| `every_system_explains_every_tag_its_detectors_can_raise` | każdy tag, który detektory mogą zgłosić na danym systemie, ma nazwę, definicję dla modelu, znaczenie i uzasadnienie; systemy bez własnego pliku (macOS, FreeBSD) dostają część wspólną |
| `combos_reference_known_tags_and_are_unambiguous` | zestawy cech odwołują się do znanych tagów, nie dublują się, mają łagodne i niepokojące wyjaśnienie; zestaw Windows nie jest widoczny na Linuksie (kontrola) |
| `text_is_plain_and_placeholders_are_filled` | brak długich myślników; polecenia sprawdzające mają wstawiony numer procesu i adresy, bez niewypełnionych pól; krok innego tagu się nie pojawia (kontrola) |
| `processes_modules_and_expectations` | `svchost.exe` w `System32` i z rodzicem `services.exe` jest typowy, w profilu użytkownika i z innym rodzicem nie; program bez oczekiwań nie jest oceniany; `clrjit.dll` nie pasuje do wzorca `clr.dll` |
| `merge_and_external_directory` | plik systemu nadpisuje wpis wspólny; katalog zewnętrzny bez `common.json` to błąd, bez pliku systemu daje część wspólną |
| `llm_glossary_covers_all_tags_in_stable_order` | słowniczek dla modelu zawiera wszystkie tagi w stałej kolejności |
| `english_base_mirrors_the_polish_one` | wersja angielska bazy (`kb/en/`) ma tę samą strukturę co polska: te same tagi, definicje dla modelu, odniesienia ATT&CK, zestawy cech, liczby kroków sprawdzenia, procesy ze ścieżkami i rodzicami, moduły; bez polskich znaków i długich myślników. Sprawdzone mutacją: usunięcie jednego kroku z `kb/en/linux.json` oblewa test |

### `nanshe-report` (raport)

| Test | Co sprawdza |
|---|---|
| `report_without_llm_lists_findings_and_gaps` | treść raportu bez LLM: znaleziska, wynik częściowy, procesy niedostępne, regiony pominięte przez próg; proces bez znalezisk i region poniżej progu nie mają sekcji |
| `report_with_llm_marks_it_and_rejects_foreign_analysis` | sekcje LLM są oznaczone; interpretacja innego wyniku skanu (inne SHA-256) jest odrzucana; próg wyższy niż znaleziska daje komunikat zamiast pustej tabeli |
| `untrusted_text_cannot_inject_markup`, `table_cell_cannot_break_the_row` | tekst z badanego procesu albo od modelu nie może wstawić znaczników Markdown/HTML ani rozbić tabeli |
| `structure_is_valid_and_offsets_point_at_objects` | PDF: nagłówek, tablica odsyłaczy wskazuje właściwe obiekty, dwie osadzone czcionki |
| `long_document_breaks_into_pages_and_is_deterministic` | długi dokument dzieli się na strony; ten sam dokument daje identyczny plik |
| `toc_page_numbers_are_stable_between_passes` | spis treści w PDF: numery stron rozdziałów rosną, a wpisanie ich do spisu nie przesuwa rozdziałów (drugi przebieg układu daje te same strony); dokument bez spisu renderuje się jednym przebiegiem (kontrola). Sprawdzone mutacją: spis o wysokości zależnej od numerów stron oblewa test |
| `long_token_is_broken_and_unknown_glyph_replaced` | długi ciąg bez spacji jest łamany; znak spoza czcionki staje się pytajnikiem |
| `map_merges_files_marks_findings_and_shows_gaps` | diagram przestrzeni adresowej: mapowania jednego pliku łączone w wiersz, znalezisko ma własny wiersz, duże odstępy są przerwami; kontrola: bez znaleziska ten sam region jest zwykłą pamięcią, bez mapy regionów diagramu nie ma |
| `long_map_is_collapsed_but_findings_and_neighbours_stay` | mapa 201 regionów zwija się do kilku wierszy, znalezisko i jego sąsiedzi zostają, suma rozmiarów się zgadza |
| `knowledge_base_explains_findings_in_plain_language` | raport zawiera przewodnik, opis zestawu cech z łagodnym i niepokojącym wyjaśnieniem, polecenia sprawdzające z adresami regionu i słowniczek; wskazówka o środowisku JIT zmienia się po dodaniu `libjvm` do mapy, a bez mapy regionów nie pojawia się wcale; zestaw bez własnego opisu jest składany z pojedynczych cech |
| `overview_matrix_tree_scatter_and_hashes` | macierz procesy x cechy z liczbą regionów, wspólne drzewo z jednym korzeniem i wspólnym rodzicem pokazanym raz, wykres rozrzutu tylko dla procesu z co najmniej trzema regionami, skrót regionu i skrót pliku zmapowanego w raporcie; kontrola: jeden proces nie ma wspólnego drzewa, a wynik bez skrótów mówi o tym wprost |
| `flow_links_regions_process_and_sockets_without_overclaiming` | diagram „od pamięci do sieci": regiony, proces z użytkownikiem i gniazda (zdalne przed nasłuchem, uniksowe pominięte), z zastrzeżeniem w podpisie; proces bez gniazd mówi to wprost, bez kontekstu diagramu nie ma |
| `report_states_scanner_privileges_and_warns_when_limited` | raport podaje uprawnienia skanera i ostrzega przy niepełnych; przy pełnych ostrzeżenia nie ma |
| `priority_follows_findings_and_context_and_summary_is_calibrated` | priorytet weryfikacji: P1 dla wagi „wysokie" bez środowiska JIT i dla cech, których JIT nie tłumaczy; P2 z rozpoznanym środowiskiem albo bez mapy pamięci; P3 i P2 dla wagi „podejrzane" zależnie od położenia programu. Podsumowanie dla decydenta: przy P1 zaleca zabezpieczenie zrzutu, brak znalezisk nie jest nazywany czystością, skan bez pełnych uprawnień zaczyna zalecenia od powtórki; rozdziały główne numerowane kolejno |
| `identity_check_flags_a_known_name_in_the_wrong_place` | `svchost.exe` w `System32` z rodzicem `services.exe`: bez ostrzeżeń; w profilu użytkownika z rodzicem `WINWORD.EXE`: dwa ostrzeżenia; nieznany program: informacja o braku opisu, bez ostrzeżeń |
| `external_knowledge_base_replaces_the_embedded_one` | katalog wskazany w opcjach zastępuje bazę wbudowaną; bez niego jest wbudowana (kontrola) |
| `english_report_has_no_polish_text` | raport angielski (z interpretacją LLM i bez) ze skanu bez polskich danych zawiera angielskie nagłówki i ani jednego wiersza z polskimi znakami. Sprawdzone mutacją: polski tekst w miejscu angielskiego oblewa test |
| `report_language_follows_the_scan_unless_chosen` | bez wyboru języka raport powstaje w języku skanu; raport w innym języku niż skan zaczyna się uwagą o tym (w obie strony), raport jednojęzyczny jej nie ma (kontrola); wybór języka nie zostaje po wywołaniu |
| `new_region_in_a_running_process_is_the_headline` (raport różnicowy) | nowy region ze znaleziskiem w procesie obecnym w obu skanach jest wykazany i trafia do oceny ogólnej; region bez zmian i proces bez znalezisk nie są wymieniane; kontrola: porównanie wyniku z samym sobą nie daje żadnej zmiany |
| `reused_pid_is_a_new_process_not_a_change` | ten sam PID z innym czasem startu albo innym plikiem programu to nowy proces i proces, który zniknął, a nie zmiana; bez czasu startu w jednym z wyników decydują PID, nazwa i plik |
| `changed_gone_and_threshold_crossings_are_told_apart` | region zmieniony (nowe cechy, wynik, inny skrót zawartości), region, który zniknął, region, który spadł poniżej progu, i region, który próg przekroczył, są rozróżniane; region bez zmian nie jest wymieniany (kontrola); przy niższym progu przejście przez próg jest zwykłą zmianą |
| `context_changes_and_scan_level_warnings` | zmiany poza pamięcią: nowe i zamknięte gniazda, nowy proces potomny, nowy zmapowany plik, inny skrót pliku programu; pozycje bez zmian nie są wymieniane; ostrzeżenia o różnych hostach, ponownym uruchomieniu systemu i odwrotnej kolejności plików pojawiają się tylko wtedy, gdy jest powód (kontrola) |
| `english_differential_report_has_no_polish_text` | raport różnicowy po angielsku nie zawiera polskiego tekstu |
| `headers_decoded_and_garbage_ignored` | pola nagłówka ELF i PE z podglądu bajtów; kontrole: sama sygnatura `MZ`, obcięty ELF, dane losowe, wskaźnik nagłówka PE poza podglądem |

Dodatkowo PDF z próbki został otwarty zewnętrznym narzędziem (`pypdf`: 5 stron, tekst z polskimi znakami do wyciągnięcia) i obejrzany po wyrenderowaniu.

## Testy end-to-end

Próbki to program `nanshe-sample` (`tests/samples`): tworzy układ pamięci, którego szukają detektory, wypisuje `ready <pid>` i śpi. **Niczego nie wykonuje z utworzonych regionów.** Dla każdej próbki skrypt sprawdza trzy rzeczy: kod wyjścia skanu, zbiór tagów i powtarzalność (dwa skany tego samego procesu). Osobną rodziną są próbki dynamiczne (`churn`, `sleepmask`), które zmieniają układ w czasie — patrz podsekcja na końcu tego rozdziału.

Różnica między systemami: na Linuksie porównywany jest cały JSON bez znacznika czasu, a zbiór tagów obejmuje cały proces (stąd `ENT-X` z biblioteki libc w każdej próbce). Na Windows porównywane są znaleziska bez liczników regionów, a tagi tylko z regionów od wagi „podejrzane".

### Linux (`scripts/e2e.sh`)

| Próbka | Co robi | Oczekiwany kod | Oczekiwane tagi |
|---|---|---|---|
| `clean` | nic | 0 | `ENT-X` (tło libc, 10 pkt) |
| `rwx` | anonimowy RWX z danymi o wysokiej entropii | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `elf` | nagłówek ELF w anonimowej pamięci R-X | 1 | `ENT-X`, `HDR`, `X-PRIV` |
| `memfd` | wykonywalne mapowanie `memfd` | 1 | `ENT-X`, `MEMFD` |
| `inject` | jak `rwx`, z tekstem instrukcji dla modelu w pamięci | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `data-noise` | wysoka entropia w danych RW (kontrola negatywna) | 0 | `ENT-X` (tło) |
| `rx-file` | R-X z pliku w `/tmp`, niska entropia | 1 | `ENT-X`, `X-TMP` (do 2026-11-22 ślepy punkt, kod 0) |
| `rwx-lowent` | RWX z kodem o niskiej entropii | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `rx-stage` | zapis do RW, potem zmiana na R-X | 1 | `ENT-X`, `X-PRIV` |
| `hdr-corrupt` | nagłówek ELF z polem spoza zakresu | 1 | `ENT-X`, `X-PRIV`: `HDR` nie reaguje |
| `hdr-offset` | nagłówek ELF w środku strony w regionie R-X | 1 | `ENT-X`, `HDR`, `X-PRIV` (do 2026-11-22 `HDR` nie reagował) |
| `delexec` | wykonywalne mapowanie usuniętego pliku | 1 | `DEL-EXEC`, `ENT-X` |
| `execstack` | stos RWX | 1 | `ENT-X`, `RWX`, `X-PRIV` |
| `inject-memfd` | instrukcja dla modelu w nazwie `memfd` | 1 | `ENT-X`, `MEMFD` |
| `inject-path` | instrukcja dla modelu w nazwie usuniętego pliku | 1 | `DEL-EXEC`, `ENT-X` |
| `ctx` | jak `all`, plus ślady poza pamięcią: gniazdo nasłuchujące i połączenie na 127.0.0.1, plik w `/tmp`, otwarty plik usunięty z dysku, proces potomny | 1 | `ENT-X`, `HDR`, `MEMFD`, `RWX`, `X-PRIV` |

Asercje dodatkowe:

1. `scan --all` z próbką `all` kończy się kodem 1.
2. Nieistniejący PID daje kod 2.
3. `rwx` ma region z wynikiem 90 (kontrola), `rwx-lowent` ma 60 i nie ma 90.
4. `explain --dry-run` dla `inject`, `inject-memfd`, `inject-path`: tekst instrukcji nie występuje w ładunku, a znacznik `instruction_like_text_detected` jest ustawiony.
5. `report` dla `rwx`: plik PDF zaczyna się od `%PDF-`, Markdown zawiera tagi i sekcję procesu; raport z wyniku bez znalezisk (kontrola) nie ma sekcji procesu i mówi o braku znalezisk.
6. Kontekst systemowy (`ctx`): w wyniku są gniazda w stanach `LISTEN` i `ESTABLISHED`, oba pliki próbki (w tym oznaczony jako usunięty), przodkowie, wiersz poleceń procesu i jego dziecka, SHA-256 pliku programu i mapa regionów. W raporcie są sekcje drzewa procesów, sieci, otwartych plików, plików zmapowanych, mapy przestrzeni adresowej, profilu entropii i podglądu bajtów. Kontrole: skan z `--no-context` i skan procesu bez znalezisk (`clean`) nie mają kontekstu ani mapy.
7. Wersja angielska (`ctx`): skan z `--lang en` zapisuje `"lang": "en"`; raport z tego wyniku ma angielskie części (podsumowanie, ocena, drzewo procesów, sieć, pliki, mapa, objaśnienia cech procesu z bazy wiedzy, kroki sprawdzenia) i ani wynik, ani raport nie zawierają polskich znaków; raport jednojęzyczny nie ma uwagi o językach (kontrola), a raport z `--lang pl` z angielskiego skanu jest po polsku i ją ma. Ta asercja przy pierwszym uruchomieniu wykryła dwa nieprzetłumaczone opisy przy skrótach plików.
8. Raport różnicowy: dwa skany tego samego procesu `rwx` nie dają nowych regionów ani procesów (kontrola); porównanie wyniku `rwx` z wynikiem `elf` pokazuje jeden nowy proces ze znaleziskami (z tagiem `HDR`) i jeden, który zniknął; wersja angielska ma angielski tytuł; PDF zaczyna się od `%PDF-`.
9. Zrzut pamięci procesu: plik core próbek `ctx` i `clean` zrobiony narzędziem `gcore` daje te same tagi co skan na żywo (dla `clean` tylko `ENT-X`, czyli vdso nie jest zgłaszane); raport mówi, że źródłem jest zrzut, i nie ma sekcji sieci; plik niebędący zrzutem daje kod 2. Bez `gcore` test jest pomijany z komunikatem.
10. Zmiana kodu biblioteki: próbka `patch` (jeden bajt nieużywanej funkcji libc zmieniony w pamięci) daje `IMG-MOD` z opisem „1 bajtów”; próbka `touch` (ta sama strona zapisana tą samą treścią) nie daje znaleziska (kontrola).
11. Wymazana sygnatura: próbka `hdr-wiped` daje `HDR`; `hdr-corrupt` (bez tablicy segmentów) nadal nie (kontrola).

### Windows (`scripts/e2e.ps1`, natywnie na dedykowanej stacji testowej)

| Próbka | Co robi | Oczekiwany kod | Tagi regionu ładunku | Punkty |
|---|---|---|---|---|
| `clean` | nic | 0 | brak | - |
| `rwx` | prywatny RWX, wysoka entropia | 1 | `ENT-X`, `RWX`, `X-PRIV` | 90 |
| `pe` | nagłówek PE w prywatnej pamięci R-X | 1 | `HDR`, `X-PRIV` | 70 |
| `xmap` | wykonywalny widok sekcji bez pliku | 1 | `RWX`, `X-MAP` | 60 |
| `rx-stage` | zapis do RW, potem R-X | 1 | `X-PRIV` | 30 |
| `thread` | prywatny region R-X i wątek z adresem startu w tym regionie, utworzony jako wstrzymany (nic się nie wykonuje) | 1 | `THR-PRIV`, `X-PRIV` | 70 |
| `inject` | jak `rwx`, z instrukcją dla modelu | 1 | `ENT-X`, `RWX`, `X-PRIV` | 90 |
| `data-noise` | wysoka entropia w danych RW (kontrola negatywna) | 0 | brak | - |
| `rwx-lowent` | RWX, niska entropia | 1 | `RWX`, `X-PRIV` | 60 |
| `pe-corrupt` | `MZ` z wymazaną sygnaturą `PE` | 1 | `X-PRIV`: `HDR` nie reaguje | 30 |
| `pe-offset` | nagłówek PE w środku strony w regionie R-X | 1 | `HDR`, `X-PRIV` | 70 |
| `ximage` | sekcja `SEC_IMAGE` z kopii exe w `%TEMP%` | 0 | brak: **udokumentowany ślepy punkt** | - |
| `guard` | RWX ze strażnikiem | 1 | `GUARD-X`, `RWX`, `X-PRIV` | 90 |
| `guard-hide` | nagłówek PE za strażnikiem | 1 | `GUARD-X`, `X-PRIV`: `HDR` nie widzi treści | 60 |
| `inject-map` | instrukcja dla modelu w nazwie mapowanego pliku | 1 | `X-MAP` | 30 |

Asercje dodatkowe:

1. Nieistniejący PID daje kod 2.
2. `explain --dry-run` dla `inject` i `inject-map`: instrukcja odcięta, znacznik ustawiony.
3. `rwx` ma 90 punktów (kontrola), `rwx-lowent` ma 60 i nie ma 90.
4. `guard-hide`: jeden region nieodczytany i wynik częściowy; `pe` (kontrola, ten sam ładunek bez strażnika): zero nieodczytanych, wynik pełny.
5. `report`: jak na Linuksie.
6. Kontekst systemowy (próbka `ctx`: RWX, nagłówek PE, gniazdo nasłuchujące, połączenie na 127.0.0.1, proces potomny): wiersz poleceń, użytkownik, czas startu, SHA-256 pliku programu, przodkowie, dziecko, gniazda `LISTEN` i `ESTABLISHED`, poziom integralności, mapa regionów, otwarte uchwyty (plik próbki z nazwą, uchwyt do procesu potomnego z prawami ingerencji, co najmniej jeden klucz rejestru, liczba wszystkich uchwytów większa niż zapisanych); w raporcie te same sekcje co na Linuksie oraz odczytany format nagłówka PE. Kontrole jak na Linuksie.
7. Wersja angielska: jak na Linuksie, dodatkowo cecha `integrity level` w wyniku, opis uprawnień skanera i uchwyt do innego procesu z prawami ingerencji w raporcie angielskim.
8. Raport różnicowy: jak na Linuksie (wynik `rwx` porównany z samym sobą i z wynikiem `pe`).
9. Zrzut pamięci procesu: pełny minidump próbek `rwx`, `pe`, `thread`, `guard` i `clean`, zrobiony funkcją systemową `MiniDumpWriteDump`, daje te same tagi co skan na żywo (dla `clean` żadnych); numer procesu i nazwa programu pochodzą ze zrzutu; raport mówi o zrzucie i nie ma sekcji sieci.
10. Zmiana kodu biblioteki: próbka `patch` (jeden bajt funkcji z `version.dll`) daje dokładnie jedno znalezisko `IMG-MOD` w tej bibliotece, 10 punktów, z opisem „1 bajt”; próbka `touch` (kontrola) nie zgłasza różnicy: zostaje jedno znalezisko informacyjne o zgodności z plikiem pod tą ścieżką, bo tożsamości pliku na Windows nie da się potwierdzić.
11. Wymazana sygnatura: próbka `pe-wiped` daje `HDR`; `pe-corrupt` nadal nie (kontrola).

Powtarzalność na Windows porównuje regiony ze znaleziskami (z profilem entropii i ciągami), a nie pełną mapę regionów ani kontekst: te zmieniają się między skanami żywego procesu.

Para `pe` / `guard-hide` sprawdza też zasadę „tylko odczyt": gdyby skaner czytał stronę strażnika, pierwszy skan zdjąłby flagę, a drugi znalazłby `HDR` i test powtarzalności by oblał.

### Próbki dynamiczne: `churn` i `sleepmask` (oba systemy)

Dotychczasowe próbki są statyczne: budują układ pamięci i śpią. Próbki dynamiczne zmieniają go w czasie — to materiał pod przyszłą obserwację zmian (`--watch`) i zarazem test, że skan wykonany w dowolnym momencie życia procesu daje spójny obraz. Argumenty: `<interwał_s> <czas_całkowity_s>` (domyślnie 3 i 60); po czasie całkowitym kończą się same.

Każdą zmianę próbka zgłasza linią `<tryb> <kolejka> <faza>` na stdout **po** jej wykonaniu. Harness czyta wyjście na bieżąco, skanuje w stabilnym oknie między wpisami i porównuje zbiór tagów ze wzorcem fazy. Test oblewa, gdy któraś faza da inne tagi albo nie wystąpi w zadeklarowanym czasie.

`churn` — cykl sześciu faz (alokuje, zmienia uprawnienia RW → R-X → RWX, dokłada i zwalnia regiony):

| Faza | Stan pamięci | Tagi Linux | Tagi Windows |
|---|---|---|---|
| `quiet` | brak regionów próbki | `ENT-X` | brak |
| `stage-rw` | nowy region RW z kodem (staging) | `ENT-X` | brak |
| `stage-rx` | ten sam region po zmianie na R-X | `ENT-X`, `X-PRIV` | `X-PRIV` |
| `hdr` | dokłada drugi region R-X z nagłówkiem (ELF/PE) | `ENT-X`, `HDR`, `X-PRIV` | `HDR`, `X-PRIV` |
| `armed-rwx` | pierwszy region po zmianie na RWX z szumem | `ENT-X`, `HDR`, `RWX`, `X-PRIV` | `ENT-X`, `HDR`, `RWX`, `X-PRIV` |
| `cleanup` | oba regiony zwolnione | `ENT-X` | brak |

W fazie `armed-rwx` region z nagłówkiem wciąż istnieje (zwalniany jest dopiero w `cleanup`), więc `HDR` zostaje. To celowe: faza sprawdza zarazem dwa równoległe znaleziska.

`sleepmask` — symulacja maskowania w czasie snu (MITRE T1027/T1140): jeden region na przemian `armed` (R-X z kodem: Linux `ENT-X`, `X-PRIV`; Windows `X-PRIV`) i `masked` (RW z szumem o wysokiej entropii: samo tło, czyli `ENT-X` na Linuksie i brak tagów na Windows). W fazie `masked` znalezisko znika; pojedynczy skan trafiony w to okno nie odróżnia procesu od czystego — to ilustruje granicę skanowania jednorazowego i motywuje obserwację w czasie.

### Instalator Windows (`scripts/test-installer.ps1`)

Uruchamiany na stacji testowej po buildzie; zmienia host (Program Files, ProgramData, PATH, rejestr) i sprząta po sobie. Nie startuje, gdy na hoście jest już instalacja Nanshe.

| Krok | Co sprawdza |
|---|---|
| paczka | `package-windows.ps1` tworzy zip z listą skrótów i bazą wiedzy |
| zmieniona paczka | po dopisaniu znaku do pliku bazy wiedzy instalator kończy się kodem 1 i niczego nie instaluje |
| dowiązanie | gdy `C:\ProgramData\Nanshe` jest dowiązaniem do innego katalogu, instalator odmawia, nie tworzy katalogu programu i niczego nie zapisuje w celu dowiązania |
| instalacja | kod 0, program działa z katalogu instalacji, baza wiedzy i skrypt usuwania na miejscu |
| uprawnienia | katalog programu: użytkownicy tylko odczyt i nikt poza Administratorami i SYSTEM nie ma prawa zapisu; katalog wyników: tylko Administratorzy i SYSTEM; dziedziczenie wyłączone |
| integracja | systemowy PATH, wpis w „Programy i funkcje", skrót w menu Start |
| ponowna instalacja | przechodzi i nie dubluje wpisu PATH |
| odinstalowanie przy dowiązaniu | z `-RemoveData` i dowiązaniem podstawionym w katalogu wyników skrypt kończy się kodem 1 i niczego nie usuwa (plik w celu dowiązania i program zostają) |
| odinstalowanie | program, PATH, rejestr i skrót usunięte, plik w katalogu wyników zostaje; na koniec host jest posprzątany |

Wynik na stacji testowej (2026-11-22): wszystkie 16 kroków przeszło, a host został po teście posprzątany.

Nie sprawdza: odmowy dla katalogu należącego do zwykłego konta (test działa jako administrator, więc nie ma jak go założyć z innym właścicielem), uruchomienia skrótu z menu Start ani zachowania na Windows innym niż stacja testowa.

### Instalator MSI (`scripts/test-msi.ps1`)

Test buduje pakiet (z kontrolą spójności ICE narzędzia WiX), instaluje go po cichu na stacji testowej, sprawdza i odinstalowuje. Wynik z 2026-11-23: 18 z 18 kroków; kontrola ICE wykonana, jedno ostrzeżenie przyjęte świadomie (ICE61: pakiet zastępuje także tę samą wersję, bo kolejne buildy mają ten sam numer).

| Krok | Co sprawdza |
|---|---|
| budowanie | skrypt kończy się kodem 0 i powstaje plik `.msi`; przy błędzie budowania plik jest usuwany |
| instalacja cicha | `msiexec /i ... /qn` kończy się kodem 0; program uruchamia się z katalogu instalacji |
| pliki | baza wiedzy po polsku i angielsku, obie licencje, plik konsoli (`nanshe-console.cmd`) |
| uprawnienia katalogu programu | zwykli użytkownicy nie mają żadnego prawa zapisu do katalogu, `nanshe.exe` ani pliku konsoli. Kontrola samego sprawdzenia: katalog z prawem zapisu dla użytkowników jest wykrywany (pierwsza wersja sprawdzenia miała za szeroką maskę i oblewała poprawną instalację) |
| katalog wyników | wpisy tylko dla Administratorów i SYSTEM, dziedziczenie wyłączone, właściciel Administratorzy |
| PATH, wpis w „Programy i funkcje", skrót | obecne po instalacji; wpis pochodzi od Instalatora Windows, wydawca HoneyLens |
| ponowna instalacja | druga instalacja tego samego pakietu kończy się kodem 0, zostaje jeden wpis i działający program |
| odinstalowanie | kod 0; program, baza, wpis w PATH, wpis w „Programy i funkcje" i skrót usunięte; plik w katalogu wyników zostaje |
| sprzątanie | host bez śladów instalacji |

Nie sprawdzono: instalacji z oknami (ekran licencji), działania skrótu (wymaga sesji interaktywnej i zgody UAC), odmowy przy wersji zainstalowanej skryptem, aktualizacji z niższego numeru wersji (nie ma jeszcze drugiej wersji).

## Przebiegi na żywo z modelami

Nie są częścią skryptów (wymagają sieci i klucza, a wynik jest niedeterministyczny). Wykonane ręcznie na próbkach syntetycznych:

| Przebieg | Wynik |
|---|---|
| `gemma3:12b`, lokalna Ollama, d1 | interpretacje poprawne formalnie; próbka z wstrzyknięciem nie zmieniła hipotezy (jedna obserwacja) |
| Nous, `anthropic/claude-opus-5.5`, d0 | po poprawce kolejności pól schematu 4 z 4 przebiegów kompletne; przed poprawką co kilka zapytań pusty szkielet odpowiedzi |
| Nous, `anthropic/claude-haiku-5.5`, d1 | komplet interpretacji, raport `.md` i `.pdf` wygenerowany |
| stacja Windows -> Ollama w sieci lokalnej | `llm check` i `explain` działają z hosta Windows |

To obserwacje, nie pomiar jakości: próby są małe, a zestawu oceny jakości modeli jeszcze nie ma.

## Czego testy nie obejmują

- `THR-PRIV` na Linuksie w teście end-to-end: próbki niczego nie wykonują z utworzonych regionów, a na Linuksie adres wątku da się uzyskać tylko z wątku, który faktycznie tam działa. Detektor ma testy jednostkowe; odczyt `/proc/<pid>/task/<tid>/syscall` sprawdziłem ręcznie w kontenerze.
- `IMG-MOD` na prawdziwej zmianie kodu: żadna próbka nie łata biblioteki. Na stacji testowej zmierzona została tylko liczba łagodnych wystąpień.
- Kontekstu systemowego na prawdziwych programach: próbka `ctx` ma jedno gniazdo, jedno dziecko i kilka plików. Procesy z tysiącami deskryptorów, kontenery z własną przestrzenią sieci i ponowne użycie PID rodzica na Windows nie były ćwiczone.
- Wyglądu diagramów dla dużych procesów: mapa przestrzeni adresowej była oglądana dla próbek (26 regionów na Linuksie); zwijanie długich map sprawdza tylko test jednostkowy.
- Obserwacji ciągłej w czasie: próbki dynamiczne (`churn`, `sleepmask`) zgłaszają fazy, a skrypty skanują w oknach między nimi; trybu `--watch` śledzącego zmiany jednego procesu jeszcze nie ma.

- Prawdziwego złośliwego oprogramowania: wszystkie próbki są syntetyczne.
- Fałszywych alarmów na prawdziwych programach poza jednym pomiarem `scan --all` na stacji testowej Windows (opis w [windows.md](windows.md)). Dla `X-TMP` nie ma żadnego pomiaru na prawdziwym hoście Linux.
- Szczelności filtru wstrzyknięć: próbki używają frazy, którą filtr zna; test dowodzi, że filtr jest podłączony do każdego kanału, a nie że nie da się go obejść.
- Backendów `anthropic`, `google`, `openai` na żywo.
- macOS i FreeBSD (brak backendu skanu).

## Atlas pamięci (inwentaryzacja metadanych)

- `scripts/dev.sh cargo test --workspace --features nanshe-cli/llm`: parser maps
  z kolumnami oddzielonymi białymi znakami i ścieżkami ze spacjami; smaps z RSS/PSS,
  offsetem, device:inode, trybem współdzielenia i nieznanymi licznikami;
  bezpieczne osadzanie metadanych w HTML (próba zamknięcia `script`).
- `node scripts/test-memory-view.cjs`: logika widoku na modelu DOM bez przeglądarki;
  grupowanie, filtry, wyszukiwanie, błędy dostępu, brak procesów, tekstowe etykiety
  i dokładne adresy powyżej zakresu precyzji Number. Nie weryfikuje CSS ani wyglądu.
- Smoke test Linux: `nanshe map --pid <PID> --no-open --json host.memory.json`,
  następnie `nanshe map --input host.memory.json --no-open`. Sprawdzono na procesie
  powłoki w kontenerze, także brak procesu (raport z błędem, kod 3).

Live na Windows i wizualny podgląd HTML nie zostały zweryfikowane w tej sesji.
Mapa nie zastępuje testów detektorów: nie czyta bajtów pamięci i nie wykonuje detekcji.
