#!/usr/bin/env python3
"""Сборка PDF из фрагмента HTML: подставляет общий шаблон и печатает через Chrome."""
import os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CSS = open(os.path.join(HERE, "theme.css"), encoding="utf-8").read()

TPL = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>%s</title>
<style>%s</style></head><body>
%s
</body></html>"""


def render(fragment_path, html_out, pdf_out, title):
    body = open(fragment_path, encoding="utf-8").read()
    html = TPL % (title, CSS, body)
    open(html_out, "w", encoding="utf-8").write(html)
    subprocess.run([
        "google-chrome", "--headless", "--disable-gpu", "--no-sandbox",
        "--no-pdf-header-footer", "--virtual-time-budget=4000",
        "--print-to-pdf=" + pdf_out, "file://" + os.path.abspath(html_out),
    ], check=True, capture_output=True)
    pages = subprocess.run(["pdfinfo", pdf_out], capture_output=True, text=True)
    n = re.search(r"Pages:\s+(\d+)", pages.stdout)
    return int(n.group(1)) if n else 0


def toc_pages(pdf, labels):
    """Определяет реальную страницу каждого заголовка."""
    total = int(re.search(r"Pages:\s+(\d+)", subprocess.run(
        ["pdfinfo", pdf], capture_output=True, text=True).stdout).group(1))
    found = {}
    for lab in labels:
        for p in range(2, total + 1):
            txt = subprocess.run(["pdftotext", "-f", str(p), "-l", str(p), pdf, "-"],
                                 capture_output=True, text=True).stdout
            if lab in txt:
                found[lab] = p
                break
    return found, total


if __name__ == "__main__":
    frag, html_out, pdf_out, title = sys.argv[1:5]
    print("страниц:", render(frag, html_out, pdf_out, title))
