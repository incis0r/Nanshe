# Nanshe na macOS

Wersja angielska: [../macos.md](../macos.md).

Stan: **pierwsza wersja skanu żywych procesów** (nowa w 0.2.0). Budowana i testowana natywnie na Apple Silicon (arm64), macOS 26. Komputery Mac z procesorem Intel, starsze wersje macOS i procesy x86_64 działające pod Rosettą nie były testowane.

## Build

```sh
cargo build --release -p nanshe-cli            # z --features llm dla warstwy interpretacji
cargo test --workspace --features nanshe-cli/llm
scripts/e2e-macos.sh                           # testy end-to-end na próbkach syntetycznych
```

## Jaki dostęp daje macOS

Odczyt pamięci innego procesu wymaga jego portu zadania. O tym, kto go dostanie, decyduje macOS:

| Skaner działa jako | Procesy, które może czytać |
|---|---|
| zwykły użytkownik, binarium bez podpisu albo ze zwykłym podpisem adhoc | żadne (działa tylko lista procesów) |
| zwykły użytkownik, binarium podpisane lokalnie z uprawnieniem debugera | procesy tego samego użytkownika, które nie są chronione: własne kompilacje, wiele aplikacji firm trzecich bez utwardzonego środowiska |
| root | dodatkowo procesy innych użytkowników, z tymi samymi wyjątkami |
| ktokolwiek, przy włączonej ochronie SIP | nigdy: procesy systemowe Apple i programy z utwardzonym środowiskiem, które nie zezwalają na debugowanie |

Podpisanie lokalnej kopii z uprawnieniem debugera (adhoc, bez konta dewelopera):

```sh
codesign -f -s - --entitlements packaging/macos/debugger.entitlements target/release/nanshe
```

Proces, którego nie da się otworzyć, jest w wyniku wymieniony jako niedostępny, z przyczyną; wynik skanu jest wtedy oznaczony jako częściowy. Na stacji deweloperskiej (SIP włączony, zwykły użytkownik, uprawnienie jak wyżej) czytelnych było 25 z 788 procesów. To cecha systemu, a nie usterka do obejścia: Nanshe nie prosi o wyłączenie SIP.

## Co jest badane

- **Mapa regionów** z jądra (`mach_vm_region_recurse`): adres, rozmiar, bieżąca ochrona, znacznik alokacji. Nazwy plików pochodzą z `proc_pidinfo` (`PROC_PIDREGIONPATHINFO`), ze sprawdzeniem, że opis dotyczy dokładnie pytanego regionu.
- **Biblioteki systemowe.** macOS mapuje wszystkie biblioteki systemowe z jednego wspólnego pliku (dyld shared cache) pod tym samym adresem w każdym procesie. Regiony widziane przez to wspólne mapowanie mają etykietę `[dyld shared cache]`, nie są zgłaszane jako kod bez pliku i nie są czytane (ponad 1 GiB, wszędzie identyczne). Strona w tym zakresie podmieniona prywatnie nie należy już do wspólnego mapowania i jest badana jak każdy region prywatny.
- **Zawartość** czytana przez `mach_vm_read_overwrite`, wyłącznie do odczytu.

`nanshe map` (interaktywna mapa pamięci) działa na macOS na tych samych zasadach dostępu.

Działające detektory: `RWX`, `X-PRIV`, `ENT-X`, `HDR` (nagłówki Mach-O, PE i ELF w pamięci bez pliku) oraz `SHC` (na arm64: bezpośrednie wywołanie jądra, `svc #0x80` z ustawieniem numeru wywołania tuż przed nim, w kodzie bez pliku).

Uwagi do czytania wyników:

- Na Apple Silicon zwykły program nie może mieć pamięci jednocześnie zapisywalnej i wykonywalnej. `RWX` oznacza więc region kompilatora JIT (`MAP_JIT`), który przeglądarki, środowiska JavaScript i maszyny wirtualne mają zasadnie.
- **Obniżona waga regionów JIT opiera się na dowodzie z systemu, a nie na nazwach programów.** Znaleziska JIT mają obniżoną wagę (znacznik `jit:macos-allow-jit`) tylko wtedy, gdy zachodzą cztery fakty: ważny podpis, utwardzone środowisko, uprawnienie `allow-jit` i tożsamość wydawcy (identyfikator zespołu z certyfikatu wydanego przez Apple albo program systemowy Apple). Wszystkie sprawdza jądro. Program podpisany lokalnie nie dostaje obniżki nawet z tym uprawnieniem: każdy może tak podpisać własny program. Tożsamość wydawcy mówi, kto podpisał program, a nie że program jest nieszkodliwy.

## Jeszcze niezaimplementowane

- Połączenia sieciowe i otwarte pliki procesu. Już dostępne: procesy nadrzędne i potomne, użytkownik, czas startu, liczba wątków, wiersz poleceń, stan podpisu kodu i istotne uprawnienia.
- Adresy startowe wątków (`THR-PRIV`) i porównanie kodu z plikiem na dysku (`IMG-MOD`).
- Zrzuty pamięci procesów macOS (pliki core w formacie Mach-O).
- Podpisana i notaryzowana paczka.

## Testy

- Testy jednostkowe backendu: układ struktury jądra, klasyfikacja regionów, reguła dokładnego regionu dla nazw plików oraz skan samego procesu testu (lista, mapa, odczyt własnych danych i własnego kodu, etykieta wspólnej pamięci bibliotek).
- `scripts/e2e-macos.sh`: próbki `clean`, `data-noise`, `rx-stage`, `rx-lowent`, `macho`, `jit`, `all`; odmowa dla procesu chronionego; nieistniejący proces; raport polski i angielski z krokami sprawdzenia dla macOS; skan wszystkich procesów.
- Nieobjęte: root, procesy innych użytkowników, Mac z procesorem Intel, Rosetta, prawdziwe złośliwe oprogramowanie.

## Jako stacja analityka

Niezależnie od skanu na żywo wynik zebrany na Linuksie albo Windows można tu zinterpretować i zamienić w raport: `explain`, `report`, `diff`, `llm check` i `cloud list` nie zależą od backendu skanu.
