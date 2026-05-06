# Rename Sniffer

**Author:** Cadu Rolim

A Python script that recovers the true name and type of files with missing, wrong, or masked extensions. It analyzes the raw binary content — magic bytes, metadata, embedded strings — to identify what a file really is and suggests a proper name with the correct extension. Nothing is written or renamed unless you explicitly confirm.

## What it does

For each file it runs five analysis stages in verbose mode:

| Stage | What it checks |
|---|---|
| **Magic bytes** | Tests 35+ known file signatures against the raw header |
| **Embedded filenames** | Regex scan over the full binary for `name.ext` patterns |
| **Metadata** | Parses EXIF, PDF info dict, Office XML, OLE, ID3v2, PNG text chunks |
| **Printable strings** | Extracts readable ASCII sequences (min 6 chars) |
| **Suggestion** | Picks the best name + extension with a confidence level |

At the end it prompts you to rename, edit the name, or skip — nothing is changed automatically.

## Supported file types

Images: JPEG, PNG, GIF, BMP, WEBP, ICO, TIFF  
Documents: PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP, EPUB, RTF  
Audio: MP3, FLAC, OGG, WAV, M4A  
Video: MP4, MKV, MOV, M4V, FLV, WMV  
Archives: ZIP, RAR, 7Z, GZ, BZ2, XZ  
Other: EXE, ELF, SQLite, WOFF, WOFF2, XML, HTML, shell scripts

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)
- Windows 10+ (ANSI color enabled automatically)

## Usage

```
python rename_sniff.py <file>
python rename_sniff.py file1 file2 file3
python rename_sniff.py *.bak
```

### Single file

```
python rename_sniff.py unknown_file
```

### Multiple files

```
python rename_sniff.py C:\Downloads\*.tmp
```

When processing multiple files a session summary table is printed at the end.

## Output example

```
============================================================
  FILE: report_final
============================================================
  Size : 142,336 bytes  (139.0 KB)

  ──────────────────────────────────────────────────────
  [1] MAGIC BYTES / FILE HEADER
  ──────────────────────────────────────────────────────
  File header (first 16 bytes): d0 cf 11 e0 a1 b1 1a e1 ...
  ✔ MATCH  MS Office OLE (doc/xls/ppt)      d0 cf 11

  [3] FORMAT METADATA
    ✔ dc:title              : Q3 Financial Report
    ✔ dc:creator            : Jane Smith

  ──────────────────────────────────────────────────────
  Confidence  : HIGH
  Suggested   : Q3 Financial Report.doc
  ──────────────────────────────────────────────────────

  Rename 'report_final' -> 'Q3 Financial Report.doc' ?

  [y] Rename now   [e] Edit name   [n] Skip:
```

## Confidence levels

| Level | Meaning |
|---|---|
| **HIGH** | Magic bytes matched + metadata title found |
| **MEDIUM** | Magic bytes matched, name from embedded filename or no title |
| **LOW** | No magic match — extension and name are guesses |

## Rename behavior

- **y** — rename to the suggested name immediately  
- **e** — open a prompt to type a custom name (suggested name is the default)  
- **n** — skip, no changes made  

If only the extension was identified (name still masked), it offers a lighter option: fix just the extension and keep the original stem.

## Notes

- The script is **read-only during analysis** — it never writes unless you confirm the rename prompt.
- The progress bar runs on `stderr`; findings stream to `stdout`, so you can redirect output cleanly.
- Glob patterns like `*.bak` are expanded by your shell. On Windows PowerShell use quotes if needed: `python rename_sniff.py "C:\path\*.bak"`.
