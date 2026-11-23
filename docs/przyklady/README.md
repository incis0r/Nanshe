# Przykładowe raporty

Wszystkie pliki powstały poleceniem `nanshe report` ze skanów próbki syntetycznej `nanshe-sample ctx` w kontenerze Linux. Pliki bez LLM odtwarza `scripts/dev.sh sh scripts/example.sh docs/przyklady`.

| Plik | Źródło |
|---|---|
| `raport-bez-llm.md`, `.pdf` | skan próbki `ctx` na Linuksie (kontener), bieżąca wersja narzędzia: ze skrótami SHA-256, wykresami i objaśnieniami z bazy wiedzy |
| `wynik-skanu.json` | plik wyniku, z którego powstał `raport-bez-llm` |
| `raport-z-llm.md`, `.pdf` | wcześniejszy skan tej samej próbki z interpretacją modelu (Opus 5.5 przez Nous, poziom d0). Interpretacja jest przypisana do tamtego wyniku skanu, dlatego ten raport nie ma skrótów plików |
| `en/report-without-llm.md`, `.pdf`, `en/scan-result.json` | wersja angielska: skan próbki `ctx` na Linuksie (kontener) z `--lang en` i raport z tego wyniku |

Raporty zawierają dane z kontenera testowego bez filtrowania (ścieżki, wiersze poleceń, fragmenty pamięci).
