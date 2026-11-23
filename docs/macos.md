# Nanshe na macOS i innych systemach

Stan: **skan żywych procesów nie jest zaimplementowany** na macOS, FreeBSD ani innych systemach poza Linuksem i Windows. `nanshe scan` zwraca tam błąd „nieobsługiwane".

Zapisaną inwentaryzację z Linux/Windows można otworzyć jako lokalny atlas HTML:

```sh
nanshe map --input host.memory.json
```

Uruchomienie bez argumentów próbuje wykonać inwentaryzację live, więc na macOS zwróci
błąd braku backendu. Nie generuje zastępczych ani syntetycznych danych systemowych.

## Do czego służy stacja z macOS

Jako stacja analityka: wynik skanu zebrany na Linuksie albo Windows można tu interpretować i zamieniać w raport. Komendy `explain`, `report`, `llm check` i `cloud list` nie zależą od systemu, bo pracują na pliku JSON.

Uwaga: natywny build na macOS nie był sprawdzany (stacja robocza projektu nie ma Rusta). Sprawdzona droga to kontener Linux:

```sh
scripts/dev.sh cargo build --release -p nanshe-cli --features llm
scripts/dev.sh /target/release/nanshe report wynik.json
scripts/dev.sh /target/release/nanshe explain wynik.json --llm nous --allow-cloud --key-file .nous
```

`scripts/dev.sh` montuje katalog repo jako `/src`, więc pliki wyniku muszą leżeć w repo albo w wolumenie `/target`. Pliki `*.llm.json`, `*.report.md` i `*.report.pdf` są w `.gitignore`, bo zawierają dane z pamięci.

## Wdrażanie i testy zdalne z macOS

- Windows: natywnie na dedykowanej stacji testowej (`scripts\e2e.ps1`), opis w [windows.md](windows.md).
- Linux: testy w kontenerze, opis w [testy.md](testy.md).

## Plan

Backendy macOS (`mach_vm_region_recurse` + `mach_vm_read_overwrite`, z ograniczeniami SIP) i FreeBSD to etap M3 w planie rozwoju ([dokumentacja-0.1.0.md](dokumentacja-0.1.0.md), rozdział 14); bez terminu.
