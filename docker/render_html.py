#!/usr/bin/env python3
"""Render a downloaded HTML page to prefixed text parts, offline, inside the extract image.

Usage: render_html.py <target_dir> <source_dir>

The judge and the later reader see the text a browser shows plus the places text hides
(comments, hidden elements, templates, attribute text). Inline script and style bodies
are counted, never shown. Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unicodedata
from html.parser import HTMLParser
from pathlib import Path

RENDERER = "scout-render-1"
NAME = "downloaded-content"
HTML_MIMES = ("text/html", "application/xhtml+xml")
MAX_VALUE = 500
MAX_LINE = 1000
PART_LINES = 180
PART_BYTES = 20000

VOID = frozenset("br img input meta link hr area base col embed source track wbr".split())
BLOCK = frozenset("""address article aside blockquote body caption dd details dialog div dl dt
    fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 head header hgroup hr html legend
    li main nav ol optgroup option p pre section select summary table tbody td textarea tfoot
    th thead title tr ul""".split())
SOURCE_ATTR = {"script": "src", "iframe": "src", "frame": "src", "embed": "src",
               "object": "data", "form": "action", "link": "href", "base": "href"}
ATTR_TEXT = ("alt", "title", "aria-label", "placeholder")
HIDE_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden"
                        r"|font-size\s*:\s*0+(?:\.0+)?(?![\d.])|opacity\s*:\s*0+(?:\.0+)?(?![\d.])",
                        re.IGNORECASE)
HTML_SPACE = re.compile(r"[ \t\n\r\f]+")
# Zl/Zp too: a line or paragraph separator would let page text start a new line elsewhere.
ESCAPE_CATEGORIES = frozenset(("Cc", "Cf", "Co", "Cs", "Zl", "Zp"))


def cut(value: str) -> str:
    value = value.replace("\t", " ").replace("\n", " ")
    if len(value) > MAX_VALUE:
        return value[:MAX_VALUE] + f"…[+{len(value) - MAX_VALUE} chars]"
    return value


def collapse(text: str) -> str:
    return HTML_SPACE.sub(" ", text).strip()


def units(text: str) -> list[str]:
    # One unit per source character, so a split never lands inside an escape.
    out = []
    for ch in text:
        if ch in "\t\n":
            ch = " "
        out.append(f"\\u{{{ord(ch):04X}}}" if unicodedata.category(ch) in ESCAPE_CATEGORIES else ch)
    return out


def emit(prefix: str, body: str) -> list[str]:
    budget = MAX_LINE - len(prefix)
    lines, cur, size = [], [], 0
    for u in units(body):
        if cur and size + len(u) > budget:
            lines.append(prefix + "".join(cur))
            cur, size = [], 0
        cur.append(u)
        size += len(u)
    lines.append(prefix + "".join(cur))
    return lines


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[dict] = []
        self.meta: list[tuple[str, str]] = []
        self.text: list[tuple[str, str]] = []
        self.sources: list[tuple[str, str]] = []
        self.hidden: list[tuple[str, str]] = []
        self.anchors: list[dict] = []
        self.buf: dict[str, list[str]] = {"T": [], "hidden": [], "template": []}
        self.images = 0
        self.omitted = {"script": [0, 0], "style": [0, 0]}

    def _kind(self) -> str:
        if any(e["tag"] == "template" for e in self.stack):
            return "template"
        return "hidden" if any(e["hide"] for e in self.stack) else "T"

    def _flush(self, kinds=("T", "hidden", "template")) -> None:
        for kind in kinds:
            body = collapse("".join(self.buf[kind]))
            self.buf[kind] = []
            if body:
                if kind == "T":
                    self.text.append(("T: ", body))
                else:
                    self.hidden.append((f"H: [{kind}] ", body))

    def _close(self, entry: dict) -> None:
        tag = entry["tag"]
        if tag in self.omitted and entry["bytes"]:
            self.omitted[tag][0] += 1
            self.omitted[tag][1] += entry["bytes"]
        elif tag == "title":
            body = collapse("".join(entry["text"]))
            if body:
                self.meta.append(("M: ", body))
        elif entry.get("anchor") is not None:
            a = entry["anchor"]
            self.buf[a["kind"]].append(f" <{a['href']}>")
        if entry["hide"] or tag == "template":
            self._flush(("hidden", "template"))

    def _pop_to(self, index: int) -> None:
        while len(self.stack) > index:
            self._close(self.stack.pop())

    def handle_starttag(self, tag, attrs):
        d: dict[str, str] = {}
        for k, v in attrs:
            d.setdefault(k, v if v is not None else "")
        for k in ATTR_TEXT:
            if d.get(k, "").strip():
                self.hidden.append((f"H: [{k}] ", cut(d[k])))
        if tag == "meta" and "content" in d:
            key = next((d[k] for k in ("name", "property", "http-equiv") if k in d), None)
            if key is not None:
                self.meta.append(("M: ", f"{cut(key)}={cut(d['content'])}"))
        if tag in SOURCE_ATTR and SOURCE_ATTR[tag] in d:
            self.sources.append(("S: ", f"{tag} {cut(d[SOURCE_ATTR[tag]])}"))
        if tag == "img":
            self.images += 1
        if tag == "area" and "href" in d:
            self.anchors.append({"href": cut(d["href"]), "text": [d.get("alt", "")]})
        if tag in BLOCK or tag == "br":
            self._flush()
        if tag in VOID:
            return
        if tag == "a":
            # An <a> start closes an open <a>, as in a browser.
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i]["tag"] == "a":
                    self._pop_to(i)
                    break
        hide = ("hidden" in d or d.get("aria-hidden", "").strip().lower() == "true"
                or bool(HIDE_STYLE.search(d.get("style", ""))))
        entry = {"tag": tag, "hide": hide, "bytes": 0, "text": [], "anchor": None}
        if tag == "a" and "href" in d:
            entry["anchor"] = {"href": cut(d["href"]), "text": [], "kind": self._kind()}
            self.anchors.append(entry["anchor"])
        self.stack.append(entry)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                self._pop_to(i)
                break
        if tag in BLOCK or tag == "br":
            self._flush()

    def handle_data(self, data):
        top = self.stack[-1]["tag"] if self.stack else None
        if top in self.omitted:
            self.stack[-1]["bytes"] += len(data.encode("utf-8", "surrogatepass"))
            return
        title = next((e for e in reversed(self.stack) if e["tag"] == "title"), None)
        if title is not None:
            title["text"].append(data)
            return
        self.buf[self._kind()].append(data)
        for e in self.stack:
            if e["anchor"] is not None:
                e["anchor"]["text"].append(data)

    def handle_comment(self, data):
        body = collapse(data)
        if body:
            self.hidden.append(("H: [comment] ", body))

    # A browser shows neither CDATA sections nor processing instructions in HTML.
    unknown_decl = handle_comment
    handle_pi = handle_comment

    def close(self):
        super().close()
        self._pop_to(0)
        self._flush()


def render(html_text: str) -> tuple[list[str], dict]:
    html_text = html_text.removeprefix("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    p = _Page()
    p.feed(html_text)
    p.close()
    links, seen = [], set()
    for a in p.anchors:
        line = f"{a['href']} | {collapse(''.join(a['text']))}".rstrip()
        if line not in seen:
            seen.add(line)
            links.append(("L: ", line))
    lines = []
    for prefix, body in p.meta + p.text + links + p.sources + p.hidden:
        lines.extend(emit(prefix, body))
    stats = {"links": len(links), "images": p.images,
             "scripts_omitted": {"count": p.omitted["script"][0], "bytes": p.omitted["script"][1]},
             "styles_omitted": {"count": p.omitted["style"][0], "bytes": p.omitted["style"][1]}}
    return lines, stats


def part_names(n: int) -> list[str]:
    if n > 999:
        raise ValueError(f"rendered page needs {n} parts; at most 999 are named")
    width = 2 if n < 100 else 3
    return [NAME] + [f"{NAME}.part{i:0{width}d}" for i in range(2, n + 1)]


def chunk(lines: list[str], stats: dict, sha256: str, source_bytes: int) -> list[str]:
    s, st = stats["scripts_omitted"], stats["styles_omitted"]
    first = [f"# source sha256={sha256} bytes={source_bytes}",
             f"# not shown: {s['count']} inline script bodies ({s['bytes']} bytes), "
             f"{st['count']} style blocks ({st['bytes']} bytes); {stats['images']} images not listed"]
    digits = 1
    while True:
        widest = 10 ** digits - 1
        head_bytes = len(f"# {RENDERER} part {widest}/{widest}\n")
        parts: list[list[str]] = []
        cur: list[str] = []
        extra = first
        used_lines = 1 + len(extra)
        used_bytes = head_bytes + sum(len(x.encode()) + 1 for x in extra)
        for line in lines:
            size = len(line.encode("utf-8")) + 1
            if cur and (used_lines + 1 > PART_LINES or used_bytes + size > PART_BYTES):
                parts.append(extra + cur)
                cur, extra = [], []
                used_lines, used_bytes = 1, head_bytes
            cur.append(line)
            used_lines += 1
            used_bytes += size
        parts.append(extra + cur)
        if len(parts) <= widest:
            break
        digits += 1
    n = len(parts)
    return [f"# {RENDERER} part {i}/{n}\n" + "".join(x + "\n" for x in body)
            for i, body in enumerate(parts, 1)]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: render_html.py <target_dir> <source_dir>", file=sys.stderr)
        return 2
    target, source = Path(argv[1]), Path(argv[2])
    raw_path = target / NAME
    if not os.path.lexists(raw_path):
        print('render: skipped (no file)')
        return 0
    mime = subprocess.run(["file", "-b", "--mime-type", "--", str(raw_path)],
                          check=True, capture_output=True, text=True).stdout.strip()
    if mime not in HTML_MIMES:
        print(f"render: skipped ({mime})")
        return 0
    raw = raw_path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    lines, stats = render(raw.decode("utf-8", errors="replace"))
    parts = chunk(lines, stats, sha, len(raw))
    names = part_names(len(parts))
    for name in names[1:]:
        if os.path.lexists(target / name):
            raise FileExistsError(f"{name} already exists in the target")
    for name, text in zip(names[1:], parts[1:]):
        (target / name).write_text(text, encoding="utf-8")
    rendered_bytes = sum(len(p.encode("utf-8")) for p in parts)
    record = {"renderer": RENDERER, "source_sha256": sha, "source_bytes": len(raw),
              "rendered_bytes": rendered_bytes, "parts": names, **stats}
    (source / "render.json").write_text(json.dumps(record, indent=2) + "\n")
    # target and source are separate mounts, so the move is a copy then an atomic replace
    # of the raw file by part 1; until that replace the raw page stays in place.
    shutil.copyfile(raw_path, source / f"{NAME}.html")
    tmp = target / f".{NAME}.render-tmp"
    try:
        tmp.write_text(parts[0], encoding="utf-8")
        os.replace(tmp, raw_path)
    finally:
        if tmp.exists():
            tmp.unlink()
    print(f"render: html -> {len(parts)} part(s), {rendered_bytes} bytes")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as e:  # any failure must fail the scan, never fall back to the raw page
        print(f"render: error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
