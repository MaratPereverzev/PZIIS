#!/usr/bin/env python3
"""Приводит номера страниц в оглавлении к фактическим и перерендеривает."""
import re, subprocess, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build import render

frag, html_out, pdf_out, title = sys.argv[1:5]

def pages_of(pdf, total):
    out = {}
    for p in range(2, total + 1):
        txt = subprocess.run(["pdftotext", "-f", str(p), "-l", str(p), pdf, "-"],
                             capture_output=True, text=True).stdout
        for m in re.finditer(r"(?m)^\s*(\d{1,2})\.\s+\S", txt):
            n = m.group(1)
            out.setdefault(n, p)
    return out

for attempt in range(4):
    total = render(frag, html_out, pdf_out, title)
    # заголовки разделов: ищем «N. » в начале строки на каждой странице
    real = pages_of(pdf_out, total)
    body = open(frag, encoding="utf-8").read()
    changed = False

    def repl(m):
        global changed
        num = m.group(1).split(".")[0]
        want = real.get(num)
        if want and str(want) != m.group(2):
            changed = True
            return '<div>%s <span>%d</span></div>' % (m.group(1), want)
        return m.group(0)

    body = re.sub(r'<div>((?:\d+)\..*?) <span>(\d+)</span></div>', repl, body)
    if not changed:
        print("оглавление верно, страниц: %d" % total)
        break
    open(frag, "w", encoding="utf-8").write(body)
else:
    print("не сошлось за 4 прохода")
