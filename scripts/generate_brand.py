#!/usr/bin/env python3
"""Generate the Nanshe brand exports from editable vector geometry."""
from pathlib import Path
import io
import ctypes.util
import sys
if sys.platform == 'darwin' and Path('/opt/local/lib/libcairo.2.dylib').exists():
    original_find_library = ctypes.util.find_library
    ctypes.util.find_library = lambda name: '/opt/local/lib/libcairo.2.dylib' if name == 'cairo' else original_find_library(name)
import cairosvg
from PIL import Image

OUT = Path(__file__).resolve().parents[1] / 'img' / 'logo'
OUT.mkdir(parents=True, exist_ok=True)

# Hexagonal lens and three memory-signal bars, redrawn from the approved concept.
def mark(light=False):
    main = '#F8FAFC' if light else '#475569'
    return f'''<path fill="{main}" fill-rule="evenodd" d="M128 8 232 68v120l-104 60L24 188V68L128 8zm0 30L50 83v90l78 45 78-45V83L128 38z"/>
<path fill="{main}" d="M128 51 190 87v39l-94-54z M68 92l24-14v67L68 131z M164 130l26 15v30l-26 15z M68 145l92 53-32 18-60-35z"/>
<g fill="#159C9C"><rect x="104" y="141" width="10" height="17" rx="2"/><rect x="123" y="130" width="10" height="28" rx="2"/><rect x="142" y="118" width="10" height="40" rx="2"/></g>'''

def svg(view, body):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}">{body}</svg>\n'

# Wordmark is drawn as paths: no font installation is required.
letters = '''<g fill="none" stroke="CURRENT" stroke-width="13" stroke-linecap="square" stroke-linejoin="miter">
<path d="M0 72V4l56 68V4"/><path d="M76 29h32q10 0 10 10v33H87q-11 0-11-10v-5q0-10 11-10h31"/>
<path d="M139 72V29h30q11 0 11 11v32"/><path d="M239 29h-34q-8 0-8 8v3q0 8 8 8h26q8 0 8 8v8q0 8-8 8h-34"/>
<path d="M257 4v68 M257 29h29q11 0 11 11v32"/><path d="M358 53h-42v-13q0-11 11-11h20q11 0 11 11v13zm-42 0v8q0 11 11 11h31"/></g>'''

def logo(light=False):
    color = '#F8FAFC' if light else '#475569'
    return svg('0 0 1050 256', f'<g>{mark(light)}</g><g transform="translate(300 67) scale(1.7)">{letters.replace("CURRENT", color)}</g>')

assets = {
    'nanshe-symbol.svg': svg('0 0 256 256', mark()),
    'nanshe-symbol-light.svg': svg('0 0 256 256', mark(True)),
    'nanshe-logo.svg': logo(),
    'nanshe-logo-light.svg': logo(True),
    'nanshe-icon.svg': svg('0 0 256 256', '<rect x="4" y="4" width="248" height="248" rx="52" fill="#142338"/><g transform="translate(32 32) scale(.75)">' + mark(True) + '</g>'),
}
for name, content in assets.items():
    (OUT / name).write_text(content, encoding='utf-8')

def render(name, width, height):
    return Image.open(io.BytesIO(cairosvg.svg2png(bytestring=assets[name].encode(), output_width=width, output_height=height))).convert('RGBA')

for size in (16, 32, 48, 64, 128, 256, 512, 1024):
    render('nanshe-icon.svg', size, size).save(OUT / f'nanshe-icon-{size}.png')
for name in ('nanshe-logo', 'nanshe-logo-light'):
    render(name + '.svg', 2100, 512).save(OUT / (name + '.png'))
render('nanshe-symbol.svg', 1024, 1024).save(OUT / 'nanshe-symbol-1024.png')
icon = render('nanshe-icon.svg', 256, 256)
icon.save(OUT / 'nanshe.ico', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
icon.save(OUT / 'favicon.ico', sizes=[(16,16),(32,32),(48,48)])
