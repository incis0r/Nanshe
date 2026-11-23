# Nanshe — identyfikacja wizualna

Znak opiera się na sześciokątnej geometrii HoneyLens; turkusowe słupki symbolizują analizę i sygnał wykryty w pamięci. Wektor jest ręczną interpretacją zaakceptowanej koncepcji, a nie automatycznym obrysem obrazu.

## Pliki

- `nanshe-logo.svg` — podstawowy logotyp poziomy, przezroczyste tło; `nanshe-logo-light.svg` — wariant na ciemne tło. Napisy są krzywymi, nie wymagają fontu.
- `nanshe-symbol.svg` i `nanshe-symbol-light.svg` — sam znak na jasne i ciemne tło.
- `nanshe-icon.svg` — ikona na granatowym polu; `nanshe.ico` — Windows (16, 24, 32, 48, 64, 128 i 256 px); `favicon.ico` — 16, 32 i 48 px.
- `nanshe-icon-*.png` — ikony rastrowe od 16 do 1024 px; PNG logotypu i symbolu mają przezroczyste tło.

## Kolory

| Zastosowanie | Kolor |
|---|---|
| Slate / znak i tekst | `#475569` |
| Navy / ciemne tło | `#142338` |
| Teal / sygnał | `#159C9C` |
| Jasny znak | `#F8FAFC` |

Zapewnij wokół znaku wolną przestrzeń co najmniej równą grubości zewnętrznego sześciokąta. Na małych powierzchniach używaj samej ikony, a nie poziomego logotypu. W interfejsach używaj czytelnego kroju bezszeryfowego; napis w pliku SVG jest własnym rysunkiem.

Przykład HTML: `<link rel="icon" href="/img/logo/favicon.ico" sizes="any">` oraz `<link rel="icon" type="image/svg+xml" href="/img/logo/nanshe-icon.svg">`.

Pliki można odtworzyć poleceniem `python3 scripts/generate_brand.py` (wymaga Pillow i CairoSVG). Ikona jest gotowa do dołączenia jako zasób Windows; obecny projekt CLI nie osadza jej automatycznie w pliku EXE.
