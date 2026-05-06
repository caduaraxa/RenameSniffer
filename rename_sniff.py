"""
sniff.py — Brute-force file name & type recovery  (VERBOSE MODE)
=================================================================
Usage:
    python sniff.py <filename>
    python sniff.py *.bak

Every check is shown in real time as it runs.
Progress bar stays pinned at the bottom throughout.
Nothing is written or renamed — report only.
"""

import os
import re
import sys
import struct
import string
import zipfile
import io
import time
import shutil
from pathlib import Path

# ── ANSI ──────────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"
DIM    = "\033[2m"

def c(text, color):
    return f"{color}{text}{RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS BAR  — pinned to bottom line, log() streams findings above it
# ─────────────────────────────────────────────────────────────────────────────

STEPS = [
    ("Reading file",        0.10),
    ("Magic bytes",         0.20),   # verbose — checks each signature
    ("Embedded filenames",  0.35),
    ("Metadata",            0.20),
    ("Printable strings",   0.10),
    ("Suggestion",          0.05),
]
TOTAL_WEIGHT = sum(w for _, w in STEPS)


class Progress:
    BAR_WIDTH = 26
    UP1  = "\033[1A"
    COL0 = "\r"

    def __init__(self, filesize: int):
        self.filesize    = filesize
        self.start       = time.monotonic()
        self.done_w      = 0.0
        self._idx        = -1
        self._step_start = self.start
        self._times: list[float] = []
        self._tw         = shutil.get_terminal_size((80, 20)).columns
        self._drawn      = False
        self._last_bar   = ""
        self._pct        = 0.0
        self._eta        = None

    def _fmt(self, secs) -> str:
        if secs is None or secs < 0 or secs > 3600: return "--:--"
        m, s = divmod(int(secs), 60)
        return f"{m:02d}:{s:02d}"

    def _build(self) -> str:
        filled  = int(self.BAR_WIDTH * self._pct)
        bar     = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        elapsed = time.monotonic() - self.start
        sz      = self.filesize
        szs     = f"{sz/1048576:.1f}MB" if sz >= 104858 else f"{sz/1024:.1f}KB"
        name    = STEPS[self._idx][0] if self._idx >= 0 else "starting"
        line    = (f"  [{bar}] {self._pct*100:5.1f}%  {name:<20} "
                   f"elapsed {self._fmt(elapsed)}  eta {self._fmt(self._eta)}  {szs}")
        return line[:self._tw - 1]

    def _draw_bar(self):
        self._last_bar = self._build()
        sys.stderr.write("\r[2K" + self._last_bar)
        sys.stderr.flush()

    def log(self, text: str = ""):
        """
        Print a finding to stdout normally — fully accumulative, no tricks.
        Bar runs on stderr so it never mixes with stdout log lines.
        """
        if not self._drawn:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            return
        # Erase bar on stderr, print log on stdout, redraw bar on stderr
        sys.stderr.write("\r[2K")
        sys.stderr.flush()
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        self._draw_bar()

    def step(self, idx: int):
        now = time.monotonic()
        if self._idx >= 0:
            self._times.append(now - self._step_start)
            self.done_w += STEPS[self._idx][1]
        self._idx        = idx
        self._step_start = now
        self._pct        = self.done_w / TOTAL_WEIGHT
        if self._times:
            wd = sum(STEPS[i][1] for i in range(idx))
            if wd > 0:
                self._eta = (sum(self._times) / wd) * (TOTAL_WEIGHT - self.done_w)
            else:
                self._eta = None
        else:
            self._eta = None
        if not self._drawn:
            # Print an empty line on stdout so bar on stderr appears below
            sys.stdout.write("\n")
            sys.stdout.flush()
            self._drawn = True
        self._draw_bar()

    def finish(self):
        elapsed = time.monotonic() - self.start
        sys.stderr.write("\r[2K\n")
        sys.stderr.flush()
        sys.stdout.write(c(f"  Done in {self._fmt(elapsed)}  ({self.filesize:,} bytes)", DIM) + "\n\n")
        sys.stdout.flush()


# Shorthand: emit a line through the bar
def L(pb, text="", color=None):
    pb.log(c(f"  {text}", color) if color else f"  {text}")

def LH(pb, text):  L(pb, text, CYAN)     # header
def LG(pb, text):  L(pb, text, GREEN)    # hit
def LY(pb, text):  L(pb, text, YELLOW)   # warning / partial
def LD(pb, text):  L(pb, text, DIM)      # dim / miss
def LR(pb, text):  L(pb, text, RED)      # error
def SEP(pb):       L(pb, "─" * 54, DIM)


# ─────────────────────────────────────────────────────────────────────────────
# 1. MAGIC BYTES  — verbose: show every signature tested
# ─────────────────────────────────────────────────────────────────────────────

# (magic_bytes, mime, ext, label)
MAGIC_TABLE = [
    (b"\xff\xd8\xff",          "image/jpeg",              ".jpg",   "JPEG image"),
    (b"\x89PNG\r\n\x1a\n",    "image/png",               ".png",   "PNG image"),
    (b"GIF87a",                "image/gif",               ".gif",   "GIF87a image"),
    (b"GIF89a",                "image/gif",               ".gif",   "GIF89a image"),
    (b"BM",                    "image/bmp",               ".bmp",   "BMP image"),
    (b"\x00\x00\x01\x00",     "image/ico",               ".ico",   "ICO icon"),
    (b"II*\x00",               "image/tiff",              ".tif",   "TIFF (little-endian)"),
    (b"MM\x00*",               "image/tiff",              ".tif",   "TIFF (big-endian)"),
    (b"%PDF",                  "application/pdf",         ".pdf",   "PDF document"),
    (b"PK\x03\x04",           "application/zip",         ".zip",   "ZIP / Office Open XML"),
    (b"\xd0\xcf\x11\xe0",     "application/msoffice",    ".doc",   "MS Office OLE (doc/xls/ppt)"),
    (b"{\rtf",                 "text/rtf",                ".rtf",   "Rich Text Format"),
    (b"ID3",                   "audio/mp3",               ".mp3",   "MP3 with ID3 tag"),
    (b"\xff\xfb",              "audio/mp3",               ".mp3",   "MP3 frame sync (0xFFFB)"),
    (b"\xff\xf3",              "audio/mp3",               ".mp3",   "MP3 frame sync (0xFFF3)"),
    (b"fLaC",                  "audio/flac",              ".flac",  "FLAC audio"),
    (b"OggS",                  "audio/ogg",               ".ogg",   "OGG container"),
    (b"RIFF",                  "audio/wav",               ".wav",   "RIFF container (WAV/WEBP)"),
    (b"\x1aE\xdf\xa3",        "video/mkv",               ".mkv",   "Matroska / MKV"),
    (b"ftyp",                  "video/mp4",               ".mp4",   "MP4/MOV ftyp box (offset 0)"),
    (b"FLV\x01",              "video/flv",               ".flv",   "Flash Video"),
    (b"\x30\x26\xb2\x75",    "video/wmv",               ".wmv",   "Windows Media Video"),
    (b"Rar!\x1a\x07",         "application/rar",         ".rar",   "RAR archive"),
    (b"\x1f\x8b",             "application/gzip",        ".gz",    "GZIP compressed"),
    (b"BZh",                   "application/bzip2",       ".bz2",   "BZIP2 compressed"),
    (b"\xfd7zXZ\x00",         "application/xz",          ".xz",    "XZ compressed"),
    (b"7z\xbc\xaf\x27\x1c",  "application/7z",          ".7z",    "7-Zip archive"),
    (b"MZ",                    "application/exe",         ".exe",   "Windows PE (exe/dll)"),
    (b"\x7fELF",              "application/elf",         ".elf",   "ELF binary (Linux)"),
    (b"SQLite format 3",       "application/sqlite",      ".db",    "SQLite database"),
    (b"wOFF",                  "font/woff",               ".woff",  "WOFF font"),
    (b"wOF2",                  "font/woff2",              ".woff2", "WOFF2 font"),
    (b"<?xml",                 "text/xml",                ".xml",   "XML document"),
    (b"<!DOCTYPE html",        "text/html",               ".html",  "HTML document"),
    (b"<html",                 "text/html",               ".html",  "HTML document"),
    (b"#!",                    "text/script",             ".sh",    "Shell script (shebang)"),
]


def _identify_ftyp(pb, data: bytes) -> tuple:
    compat = data[8:40] if len(data) >= 40 else data[8:]
    brands = {
        b"M4A ": ("audio/m4a",  ".m4a",  "M4A audio"),
        b"m4a ": ("audio/m4a",  ".m4a",  "M4A audio"),
        b"M4V ": ("video/m4v",  ".m4v",  "M4V video"),
        b"m4v ": ("video/m4v",  ".m4v",  "M4V video"),
        b"qt  ": ("video/mov",  ".mov",  "QuickTime MOV"),
    }
    for brand, (mime, ext, label) in brands.items():
        if brand in compat:
            LG(pb, f"    ftyp brand '{brand.decode(errors='replace').strip()}' -> {label}  ({ext})")
            return mime, ext
    brand_str = compat[:4].decode(errors="replace")
    LG(pb, f"    ftyp brand '{brand_str}' -> MP4 video  (.mp4)")
    return "video/mp4", ".mp4"


def detect_magic(pb, data: bytes) -> tuple:
    SEP(pb)
    LH(pb, "[1] MAGIC BYTES / FILE HEADER")
    SEP(pb)
    LD(pb, f"  File header (first 16 bytes): {data[:16].hex(' ')}")
    L(pb)

    # Special case: ftyp at offset 4 (standard MP4/MOV layout)
    if len(data) >= 8 and data[4:8] == b"ftyp":
        LG(pb, "  ✔ ftyp box detected at offset 4 (standard MP4/MOV/M4A layout)")
        return _identify_ftyp(pb, data)

    for magic, mime, ext, label in MAGIC_TABLE:
        match = data.startswith(magic)
        status = c(f"  ✔ MATCH", GREEN) if match else c(f"  · ", DIM)
        sig_hex = magic[:6].hex(' ')
        LD(pb, f"{status}  {label:<36} {sig_hex}")

        if match:
            # Special handling
            if magic == b"RIFF" and len(data) >= 12:
                tag = data[8:12]
                if tag == b"WAVE":
                    LG(pb, f"    RIFF sub-type: WAVE -> WAV audio  (.wav)")
                    return "audio/wav", ".wav"
                elif tag == b"WEBP":
                    LG(pb, f"    RIFF sub-type: WEBP -> WebP image  (.webp)")
                    return "image/webp", ".webp"
                else:
                    LY(pb, f"    RIFF sub-type unknown: {tag}")
                    return "audio/riff", ".riff"

            if magic == b"PK\x03\x04":
                LG(pb, "    ZIP-based — inspecting internal structure...")
                return _detect_zip_office(pb, data)

            if magic == b"ftyp":
                return _identify_ftyp(pb, data)

            LG(pb, f"    -> {label}  ({ext})")
            return mime, ext

    L(pb)
    LY(pb, "  ✘ No magic bytes matched any known signature.")
    return None, None


def _detect_zip_office(pb, data: bytes) -> tuple:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
        LD(pb, f"    ZIP entries: {len(names)} files inside")
        checks = [
            ("word/",   "application/docx", ".docx", "Word document (.docx)"),
            ("xl/",     "application/xlsx", ".xlsx", "Excel spreadsheet (.xlsx)"),
            ("ppt/",    "application/pptx", ".pptx", "PowerPoint (.pptx)"),
        ]
        for prefix, mime, ext, label in checks:
            found = any(n.startswith(prefix) for n in names)
            LD(pb, f"    {'✔' if found else '·'} '{prefix}' folder: {label}")
            if found:
                LG(pb, f"    -> {label}  ({ext})")
                return mime, ext
        if "mimetype" in names:
            mt = z.read("mimetype").decode(errors="ignore")
            LD(pb, f"    mimetype: {mt}")
            for key, mime, ext, label in [
                ("opendocument.text",         "application/odt",  ".odt",  "OpenDocument Text"),
                ("opendocument.spreadsheet",  "application/ods",  ".ods",  "OpenDocument Spreadsheet"),
                ("opendocument.presentation", "application/odp",  ".odp",  "OpenDocument Presentation"),
                ("epub",                      "application/epub", ".epub", "EPUB ebook"),
            ]:
                if key in mt:
                    LG(pb, f"    -> {label}  ({ext})")
                    return mime, ext
        LY(pb, "    -> Generic ZIP archive  (.zip)")
        return "application/zip", ".zip"
    except Exception as e:
        LR(pb, f"    ZIP parse error: {e}")
        return "application/zip", ".zip"

# ─────────────────────────────────────────────────────────────────────────────
# TEXT SNIFF
# ─────────────────────────────────────────────────────────────────────────────

def sniff_text(pb, data: bytes) -> str | None:
    sample = data[:4096]
    checks = [
        (b"\xef\xbb\xbf", "UTF-8 with BOM"),
        (b"\xff\xfe",      "UTF-16 LE"),
        (b"\xfe\xff",      "UTF-16 BE"),
    ]
    for bom, label in checks:
        hit = sample.startswith(bom)
        LD(pb, f"  {'✔' if hit else '·'} BOM check: {label}")
        if hit:
            LG(pb, f"    -> {label}")
            return label
    try:
        sample.decode("utf-8")
        ratio = sum(0x20 <= b < 0x7f or b in (9,10,13) for b in sample) / max(len(sample),1)
        LD(pb, f"  · UTF-8 decode: OK  printable ratio: {ratio:.0%}")
        if ratio > 0.90:
            LG(pb, "    -> UTF-8 plain text")
            return "UTF-8"
    except UnicodeDecodeError:
        LD(pb, "  · UTF-8 decode: failed")
    ratio = sum(0x20 <= b < 0x7f or b in (9,10,13) for b in sample) / max(len(sample),1)
    LD(pb, f"  · Latin-1 printable ratio: {ratio:.0%}")
    if ratio > 0.85:
        LG(pb, "    -> Latin-1/ASCII plain text")
        return "Latin-1/ASCII"
    return None

# ─────────────────────────────────────────────────────────────────────────────
# 2. EMBEDDED FILENAMES
# ─────────────────────────────────────────────────────────────────────────────

FILENAME_RE = re.compile(
    rb"([\w\-. ]{1,64}\.(jpe?g|png|gif|bmp|webp|tiff?|pdf|docx?|xlsx?|pptx?|"
    rb"odt|ods|odp|txt|csv|rtf|mp3|mp4|mkv|avi|mov|flac|ogg|wav|"
    rb"zip|rar|7z|gz|tar|exe|dll|py|js|ts|html?|xml|json|sql|db|"
    rb"log|cfg|ini|bat|sh|ps1|apk|iso|img))",
    re.IGNORECASE,
)

def find_embedded_names(pb, data: bytes) -> list:
    SEP(pb)
    LH(pb, "[2] EMBEDDED FILENAMES  —  regex scan over raw bytes")
    SEP(pb)
    LD(pb, f"  Scanning {len(data):,} bytes for filename patterns...")
    LD(pb, f"  Pattern: [word chars + dot + known extension]")
    L(pb)

    hits = set()
    for m in FILENAME_RE.finditer(data):
        candidate = m.group(0).decode("utf-8", errors="ignore").strip()
        stem = candidate.rsplit(".", 1)[0]
        if len(stem) >= 2 and any(ch.isalpha() for ch in stem):
            if candidate not in hits:
                hits.add(candidate)
                LG(pb, f"  ✔ Found: {candidate}")

    result = sorted(hits)
    L(pb)
    if result:
        LG(pb, f"  Total: {len(result)} unique filename candidate(s)")
    else:
        LD(pb, "  ✘ No embedded filenames found.")
    L(pb)
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 3. METADATA — verbose per parser
# ─────────────────────────────────────────────────────────────────────────────

def extract_metadata(pb, data: bytes, mime: str) -> dict:
    SEP(pb)
    LH(pb, "[3] FORMAT METADATA")
    SEP(pb)

    meta = {}
    if not mime:
        LD(pb, "  No MIME type — skipping format-specific parsers.")
        L(pb)
        return meta

    parsers = []
    if "jpeg"     in mime: parsers.append(("EXIF (JPEG)",           _exif_metadata))
    if "pdf"      in mime: parsers.append(("PDF info dict",         _pdf_metadata))
    if any(x in mime for x in ("docx","xlsx","pptx","odt","ods","odp","epub","zip")):
                           parsers.append(("Office Open XML",       _office_xml_metadata))
    if "msoffice" in mime or mime.endswith(".doc"):
                           parsers.append(("OLE/CFB property set",  _ole_metadata))
    if "mp3"      in mime: parsers.append(("ID3v2 tags",            _id3_metadata))
    if "png"      in mime: parsers.append(("PNG text chunks",       _png_text_chunks))

    if not parsers:
        LD(pb, f"  No format-specific parser for: {mime}")
        L(pb)
        return meta

    for label, fn in parsers:
        LD(pb, f"  Running parser: {label}...")
        result = fn(pb, data)
        if result:
            for k, v in result.items():
                vd = (v[:80] + "...") if len(v) > 80 else v
                LG(pb, f"    ✔ {k:<22} : {vd}")
            meta.update(result)
        else:
            LD(pb, f"    · No data found.")
        L(pb)

    return meta


def _exif_metadata(pb, data: bytes) -> dict:
    LD(pb, "    Searching for APP1/Exif marker in JPEG segments...")
    try:
        i = 2
        while i < len(data) - 4:
            marker  = data[i:i+2]
            seg_len = struct.unpack(">H", data[i+2:i+4])[0]
            if marker == b"\xff\xe1":
                app1 = data[i+4:i+2+seg_len]
                if app1[:4] == b"Exif":
                    LD(pb, f"    APP1/Exif marker found at offset {i}")
                    return _parse_exif(pb, app1[6:])
            i += 2 + seg_len
    except Exception as e:
        LD(pb, f"    EXIF parse error: {e}")
    return {}


def _parse_exif(pb, raw: bytes) -> dict:
    result = {}
    try:
        bo = ">" if raw[:2] == b"MM" else "<"
        LD(pb, f"    Byte order: {'big-endian (MM)' if bo == '>' else 'little-endian (II)'}")
        ifd_offset  = struct.unpack(bo + "I", raw[4:8])[0]
        num_entries = struct.unpack(bo + "H", raw[ifd_offset:ifd_offset+2])[0]
        LD(pb, f"    IFD0 at offset {ifd_offset}, {num_entries} entries")
        TAG_NAMES = {
            0x010e: "ImageDescription", 0x010f: "Make",   0x0110: "Model",
            0x0131: "Software",         0x013b: "Artist", 0x8298: "Copyright",
        }
        pos = ifd_offset + 2
        for _ in range(num_entries):
            tag, typ, count = struct.unpack(bo + "HHI", raw[pos:pos+8])
            val_raw = raw[pos+8:pos+12]
            if tag in TAG_NAMES and typ == 2:
                offset = struct.unpack(bo + "I", val_raw)[0]
                val = raw[offset:offset+count].rstrip(b"\x00").decode("latin-1", errors="ignore")
                if val.strip():
                    result[TAG_NAMES[tag]] = val.strip()
            pos += 12
    except Exception as e:
        LD(pb, f"    EXIF IFD parse error: {e}")
    return result


def _pdf_metadata(pb, data: bytes) -> dict:
    result = {}
    text   = data[:8192]
    fields = [b"/Title", b"/Author", b"/Subject", b"/Creator"]
    LD(pb, f"    Scanning first 8KB for PDF info dict fields: {[f.decode() for f in fields]}")
    for field in fields:
        idx = text.find(field)
        found = idx != -1
        LD(pb, f"    {'✔' if found else '·'} {field.decode()}")
        if found:
            snippet = text[idx+len(field):idx+len(field)+256]
            m = re.search(rb"\(([^)]{1,200})\)", snippet)
            if m:
                val = m.group(1).decode("latin-1", errors="ignore").strip()
                if val:
                    result[field.decode().strip("/")] = val
    return result


def _office_xml_metadata(pb, data: bytes) -> dict:
    result = {}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        targets = ["docProps/core.xml", "docProps/app.xml"]
        for name in targets:
            present = name in z.namelist()
            LD(pb, f"    {'✔' if present else '·'} {name}")
            if not present:
                continue
            xml = z.read(name).decode("utf-8", errors="ignore")
            tags = ["dc:title","dc:subject","dc:creator","cp:lastModifiedBy",
                    "dc:description","Application","Company"]
            for tag in tags:
                m = re.search(rf"<{tag}[^>]*>([^<]+)</{tag}>", xml)
                LD(pb, f"      {'✔' if m else '·'} <{tag}>")
                if m:
                    val = m.group(1).strip()
                    if val:
                        result[tag] = val
    except Exception as e:
        LD(pb, f"    Office XML parse error: {e}")
    return result


def _ole_metadata(pb, data: bytes) -> dict:
    result = {}
    LD(pb, "    Scanning for OLE/CFB UTF-16LE property strings...")
    try:
        text = data.decode("utf-16-le", errors="ignore")
        for field in ("Title", "Subject", "Author", "Keywords"):
            idx = text.find(field)
            found = idx != -1 and len(text[idx:idx+80].split("\x00")[0]) > len(field) + 1
            LD(pb, f"    {'✔' if found else '·'} {field}")
            if found:
                snippet = text[idx:idx+80].split("\x00")[0]
                result[field] = snippet[len(field):].strip()
    except Exception as e:
        LD(pb, f"    OLE parse error: {e}")
    return result


def _id3_metadata(pb, data: bytes) -> dict:
    result = {}
    if data[:3] != b"ID3":
        LD(pb, "    No ID3 header found.")
        return result
    ver = data[3]
    LD(pb, f"    ID3v2.{ver} header detected")
    TAG_MAP = {
        "TIT2": "Title",    "TPE1": "Artist",   "TALB": "Album",
        "TCOM": "Composer", "TCON": "Genre",     "TDRC": "Year",
        "TRCK": "Track",    "TENC": "EncodedBy",
    }
    try:
        i = 10
        while i < min(len(data), 8192):
            frame_id = data[i:i+4].decode("ascii", errors="ignore")
            if not frame_id.strip() or not all(ch in string.ascii_uppercase + string.digits for ch in frame_id):
                break
            size = struct.unpack(">I", data[i+4:i+8])[0]
            if size == 0:
                break
            content = data[i+10:i+10+size]
            hit = frame_id in TAG_MAP
            LD(pb, f"    {'✔' if hit else '·'} Frame {frame_id} ({size}B)" +
               (f" = {TAG_MAP[frame_id]}" if hit else ""))
            if hit:
                val = content[1:].decode("utf-8", errors="ignore").strip("\x00").strip()
                if val:
                    result[TAG_MAP[frame_id]] = val
            i += 10 + size
    except Exception as e:
        LD(pb, f"    ID3 parse error: {e}")
    return result


def _png_text_chunks(pb, data: bytes) -> dict:
    result = {}
    LD(pb, "    Walking PNG chunks for text metadata...")
    try:
        i = 8
        chunk_count = 0
        while i < len(data) - 12:
            length     = struct.unpack(">I", data[i:i+4])[0]
            chunk_type = data[i+4:i+8].decode("ascii", errors="ignore")
            chunk_data = data[i+8:i+8+length]
            is_text    = chunk_type in ("tEXt", "iTXt", "zTXt")
            LD(pb, f"    {'✔' if is_text else '·'} Chunk {chunk_type} ({length}B)")
            if is_text:
                parts = chunk_data.split(b"\x00", 1)
                key   = parts[0].decode("ascii", errors="ignore")
                val   = parts[1].lstrip(b"\x00").decode("utf-8", errors="ignore").strip() if len(parts) > 1 else ""
                if val:
                    result[f"PNG:{key}"] = val
            chunk_count += 1
            if chunk_count > 50:
                LD(pb, "    (stopping after 50 chunks)")
                break
            i += 12 + length
    except Exception as e:
        LD(pb, f"    PNG chunk error: {e}")
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 4. RAW PRINTABLE STRINGS
# ─────────────────────────────────────────────────────────────────────────────

def find_printable_strings(pb, data: bytes) -> list:
    SEP(pb)
    LH(pb, "[4] RAW PRINTABLE STRINGS  —  ASCII >= 6 chars")
    SEP(pb)
    LD(pb, f"  Scanning {len(data):,} bytes for printable ASCII sequences...")
    L(pb)

    shown, seen, collected = 0, set(), []
    for s in re.findall(rb"[ -~]{6,}", data):
        decoded = s.decode("ascii", errors="ignore").strip()
        if decoded and decoded not in seen:
            seen.add(decoded)
            collected.append(decoded)
            LD(pb, f"  · {decoded[:110]}")
            shown += 1
            if shown >= 40:
                LD(pb, "  (stopping at 40 strings)")
                break

    L(pb)
    if collected:
        LD(pb, f"  Total unique strings shown: {len(collected)}")
    else:
        LD(pb, "  ✘ No printable strings found.")
    L(pb)
    return collected

# ─────────────────────────────────────────────────────────────────────────────
# 5. NAME SUGGESTION
# ─────────────────────────────────────────────────────────────────────────────

def _sanitize(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]', "_", name)
    name = name.strip(". ")
    return name[:80] if name else ""


def suggest_name(pb, path: Path, detected_ext, embedded_names, meta) -> tuple:
    SEP(pb)
    LH(pb, "[5] NAME SUGGESTION")
    SEP(pb)

    stem_candidate = None
    ext_candidate  = detected_ext
    reasoning_parts = []
    title_keys = ("dc:title", "Title", "ImageDescription", "TIT2")

    # Priority 1 — metadata title
    LD(pb, "  Priority 1: looking for title in metadata fields...")
    for key in title_keys:
        present = key in meta
        LD(pb, f"    {'✔' if present else '·'} {key}")
        if present and not stem_candidate:
            raw = meta[key].strip()
            if raw and len(raw) >= 2:
                if "." in raw and len(raw.rsplit(".", 1)[1]) <= 5:
                    parts = raw.rsplit(".", 1)
                    stem_candidate = _sanitize(parts[0])
                    if not ext_candidate:
                        ext_candidate = "." + parts[1].lower()
                else:
                    stem_candidate = _sanitize(raw)
                LG(pb, f"    -> stem from '{key}': '{stem_candidate}'")
                reasoning_parts.append(f"stem from metadata '{key}'")
    L(pb)

    # Priority 2 — Artist + Title
    LD(pb, "  Priority 2: ID3 Artist + Title combo...")
    if not stem_candidate and "TPE1" in meta and "Title" in meta:
        artist = meta["TPE1"].strip()
        title  = meta["Title"].strip()
        stem_candidate = _sanitize(f"{artist} - {title}")
        LG(pb, f"    -> '{stem_candidate}'")
        reasoning_parts.append("stem from ID3 Artist + Title")
    else:
        LD(pb, f"    · {'not applicable' if stem_candidate else 'fields not present'}")
    L(pb)

    # Priority 3 — embedded filename
    LD(pb, "  Priority 3: checking embedded filenames...")
    if not stem_candidate and embedded_names:
        for name in embedded_names:
            parts = name.rsplit(".", 1)
            if len(parts) == 2:
                emb_ext = "." + parts[1].lower()
                match = ext_candidate and emb_ext == ext_candidate
                LD(pb, f"    {'✔' if match else '·'} '{name}' (ext {'matches' if match else 'differs'})")
                if match and not stem_candidate:
                    stem_candidate = _sanitize(parts[0])
                    LG(pb, f"    -> stem: '{stem_candidate}'")
                    reasoning_parts.append(f"stem from embedded '{name}' (ext match)")
                    break
        if not stem_candidate and embedded_names:
            first  = embedded_names[0]
            parts  = first.rsplit(".", 1)
            stem_candidate = _sanitize(parts[0])
            if not ext_candidate and len(parts) == 2:
                ext_candidate = "." + parts[1].lower()
            LY(pb, f"    -> using first embedded name: '{stem_candidate}'")
            reasoning_parts.append(f"stem from first embedded name '{first}'")
    else:
        LD(pb, f"    · {'already have stem' if stem_candidate else 'no embedded names found'}")
    L(pb)

    # Priority 4 — keep masked stem
    if not stem_candidate:
        stem_candidate = path.stem
        LY(pb, f"  Priority 4: no name clues — keeping masked stem: '{stem_candidate}'")
        reasoning_parts.append("no name clues — keeping masked stem")

    if not ext_candidate:
        ext_candidate = path.suffix or ".bin"
        LY(pb, f"  Extension: unknown — keeping '{ext_candidate}'")
        reasoning_parts.append(f"extension unknown — keeping current or .bin")
    else:
        LG(pb, f"  Extension: {ext_candidate}  (from magic bytes)")
        reasoning_parts.append(f"extension from magic bytes: {ext_candidate}")

    suggested = stem_candidate + ext_candidate

    has_meta_title = any(k in meta for k in title_keys) or ("TPE1" in meta and "Title" in meta)
    has_emb_match  = any("." + n.rsplit(".",1)[1].lower() == ext_candidate for n in embedded_names if "." in n)

    if detected_ext and has_meta_title:                        confidence = "HIGH"
    elif detected_ext and (has_emb_match or embedded_names):   confidence = "MEDIUM"
    elif detected_ext:                                         confidence = "MEDIUM"
    else:                                                      confidence = "LOW"

    L(pb)
    conf_color = GREEN if confidence == "HIGH" else YELLOW if confidence == "MEDIUM" else RED
    L(pb, f"  Confidence : {confidence}", conf_color)
    L(pb, f"  Suggested  : {suggested}", conf_color)
    L(pb)
    return suggested, confidence, " | ".join(reasoning_parts)

# ─────────────────────────────────────────────────────────────────────────────
# RENAME HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _do_rename(path: Path, new_name: str):
    new_name = new_name.strip()
    if not new_name:
        print(c("  [ERROR] Empty name — skipped.", RED)); return
    if "." not in new_name:
        new_name += path.suffix
    target = path.parent / new_name
    if target.exists():
        print(c(f"  [ERROR] '{new_name}' already exists — skipped.", RED)); return
    try:
        path.rename(target)
        print(c(f"  [OK] Renamed to '{new_name}'", GREEN))
    except Exception as e:
        print(c(f"  [ERROR] {e}", RED))

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY BOX
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(path, mime, ext, names, meta, suggestion, confidence, reasoning, enc):
    W = 60
    cc = GREEN if confidence == "HIGH" else YELLOW if confidence == "MEDIUM" else RED
    print(c("─" * W, BOLD))
    print(c("  ANALYSIS SUMMARY", BOLD))
    print(c("─" * W, BOLD))
    print(c(f"  {'File':<18}: {path.name}", BOLD))
    print(f"  {'Size':<18}: {path.stat().st_size:,} bytes")
    print()
    tr = f"{mime}  ({ext})" if mime else (f"plain text ({enc})" if enc else "unknown")
    print(c(f"  {'[1] Type':<18}: {tr}", GREEN if mime else (YELLOW if enc else RED)))
    print(c(f"  {'[2] Filenames':<18}: {len(names)} candidate(s)" if names else f"  {'[2] Filenames':<18}: none", GREEN if names else DIM))
    print(c(f"  {'[3] Metadata':<18}: {len(meta)} field(s)" if meta else f"  {'[3] Metadata':<18}: none", GREEN if meta else DIM))
    print()
    print(c("─" * W, DIM))
    print(c(f"  {'Confidence':<18}: {confidence}", cc))
    print(c(f"  {'Suggested name':<18}: {suggestion}", cc))
    print(c(f"  {'Reasoning':<18}: {reasoning}", DIM))
    print(c("─" * W, BOLD))
    print()

# ─────────────────────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────────────────────

def report(filepath: str) -> dict:
    path = Path(filepath)
    print()
    print(c("=" * 60, BOLD))
    print(c(f"  FILE: {path.name}", BOLD))
    print(c("=" * 60, BOLD))
    if not path.exists():
        print(c(f"  [ERROR] File not found: {filepath}", RED))
        return {"file": filepath, "error": "not found"}
    size = path.stat().st_size
    print(f"  Size : {size:,} bytes  ({size/1024:.1f} KB)")
    print()

    pb = Progress(size)

    # Step 0 — read
    pb.step(0)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        pb.finish()
        print(c(f"  [ERROR] Cannot read: {e}", RED))
        return {"file": filepath, "error": str(e)}

    # Step 1 — magic bytes
    pb.step(1)
    mime, ext = detect_magic(pb, data)
    enc = None
    if not mime:
        L(pb)
        LH(pb, "  TEXT ENCODING SNIFF")
        enc = sniff_text(pb, data)
        if enc and not ext:
            ext = ".txt"
    L(pb)

    # Step 2 — embedded filenames
    pb.step(2)
    names = find_embedded_names(pb, data)

    # Step 3 — metadata
    pb.step(3)
    meta = extract_metadata(pb, data, mime)

    # Step 4 — printable strings
    pb.step(4)
    find_printable_strings(pb, data)

    # Step 5 — suggestion
    pb.step(5)
    suggestion, confidence, reasoning = suggest_name(pb, path, ext, names, meta)

    pb.finish()

    # Summary
    _print_summary(path, mime, ext, names, meta, suggestion, confidence, reasoning, enc)

    # Rename prompt
    final_name     = path.name
    name_has_stem  = suggestion.rsplit(".", 1)[0] != path.stem
    cc             = GREEN if confidence == "HIGH" else YELLOW

    if confidence in ("HIGH", "MEDIUM") and suggestion != path.name:
        if confidence == "HIGH" or name_has_stem:
            print(c(f"  Rename  '{path.name}'", BOLD))
            print(c(f"       -> '{suggestion}' ?", cc))
            print()
            ans = input("  [y] Rename now   [e] Edit name   [n] Skip: ").strip().lower()
            if ans == "y":
                _do_rename(path, suggestion); final_name = suggestion
            elif ans == "e":
                custom = input(f"  New name [{suggestion}]: ").strip() or suggestion
                _do_rename(path, custom);     final_name = custom
            else:
                print(c("  Skipped.", DIM))
        else:
            ext_only = path.stem + ("." + suggestion.rsplit(".",1)[-1] if "." in suggestion else "")
            print(c(f"  Extension identified — name still masked.", YELLOW))
            print(c(f"  Rename  '{path.name}'  ->  '{ext_only}'  (ext fix only)?", YELLOW))
            print()
            ans = input("  [y] Fix extension   [e] Edit full name   [n] Skip: ").strip().lower()
            if ans == "y":
                _do_rename(path, ext_only);   final_name = ext_only
            elif ans == "e":
                custom = input(f"  New name [{ext_only}]: ").strip() or ext_only
                _do_rename(path, custom);     final_name = custom
            else:
                print(c("  Skipped.", DIM))
        print()

    return {
        "file": path.name, "size": size,
        "mime": mime or ("text" if enc else "unknown"),
        "ext":  ext or "?",
        "names_found": len(names), "meta_found": len(meta),
        "confidence": confidence, "suggestion": suggestion,
        "final_name": final_name, "renamed": final_name != path.name,
    }

# ─────────────────────────────────────────────────────────────────────────────
# SESSION SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def _session_summary(results: list):
    if len(results) <= 1:
        return
    W   = 60
    cw  = 24
    print()
    print(c("=" * W, BOLD))
    print(c("  SESSION SUMMARY", BOLD))
    print(c("=" * W, BOLD))
    print()
    print(c(f"  {'File':<{cw}} {'Type':<10} {'Conf':<8} Suggested", BOLD))
    print(c("  " + "─" * (W-2), DIM))
    highs = mediums = lows = renamed = errors = 0
    for r in results:
        if "error" in r:
            errors += 1
            print(c(f"  {r['file'][:cw]:<{cw}} ERROR", RED))
            continue
        cc = GREEN if r["confidence"] == "HIGH" else YELLOW if r["confidence"] == "MEDIUM" else RED
        mk = c(" ✔", GREEN) if r["renamed"] else ""
        print(c(f"  {r['file'][:cw]:<{cw}} {r['ext'][:9]:<10} ", DIM) +
              c(f"{r['confidence']:<8} ", cc) +
              c(f"{r['suggestion'][:26]}{mk}", cc if r["renamed"] else DIM))
        if r["confidence"] == "HIGH":     highs += 1
        elif r["confidence"] == "MEDIUM": mediums += 1
        else:                             lows += 1
        if r["renamed"]:                  renamed += 1
    print(c("  " + "─" * (W-2), DIM))
    print()
    print(f"  Files : {len(results)}  |  ", end="")
    print(c(f"HIGH: {highs}", GREEN), end="  ")
    print(c(f"MEDIUM: {mediums}", YELLOW), end="  ")
    print(c(f"LOW: {lows}", RED), end="  ")
    if renamed: print(c(f"Renamed: {renamed}", GREEN), end="")
    if errors:  print(c(f"  Errors: {errors}", RED), end="")
    print()
    print()
    print(c("=" * W, BOLD))
    print()

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if sys.platform == "win32":
        os.system("")
    if len(sys.argv) < 2:
        print(f"Usage: python {os.path.basename(__file__)} <file> [file2 ...]")
        sys.exit(1)
    results = []
    try:
        for arg in sys.argv[1:]:
            r = report(arg)
            if r:
                results.append(r)
    except KeyboardInterrupt:
        print("\n\n[Interrupted by user]")
        sys.exit(0)
    _session_summary(results)

if __name__ == "__main__":
    main()