# QuickSand Version 2.2

**QuickSand Python Package and Command-Line Tool**

QuickSand is a fast, self-contained Python analysis framework for analyzing suspected malware documents and PDFs to identify exploits, obfuscated scripts, embedded executables, and high-risk active content across nested streams, encodings, and compressions.

QuickSand uses **native Python standard-library binary parsers** inside a single module (`src/quicksand/quicksand.py`) paired with **YARA** signatures (`yara-python>=4.3.0` is the only external dependency).

A hosted version is available to try without any installation at [scan.tylabs.com](https://scan.tylabs.com/).

---

## Supported Formats & Capabilities

- **OLE2 Compound Files (`[MS-CFB]`)**: Native parsing of `.doc`, `.xls`, `.ppt`, `.msg`, and HWP documents, including FAT/DIFAT/MiniFAT stream extraction and `[MS-OLEPS]` `SummaryInformation` / `DocumentSummaryInformation` metadata extraction.
- **VBA Macros (`[MS-OVBA]`)**: Native decompression of compressed VBA macro streams (`Macros`, `_VBA_PROJECT_CUR`, `VBA`) while also scanning raw streams to catch VBA stomping / p-code tampering.
- **Excel 4.0 (XLM) Macros (`[MS-XLS]`)**: Native BIFF5/BIFF8 scanner for `BOUNDSHEET` macro sheets, `Auto_Open` / `Auto_Close` built-in labels, `FORMULA` tokens (`EXEC`, `CALL`, `REGISTER`, `CHAR`, `GET.WORKSPACE`), `SST`, and `DCONN` data connections.
- **Encrypted Office Documents (`[MS-OFFCRYPTO]`)**: Built-in detection and in-memory decryption of ECMA-376 Standard Encryption (AES-128/192/256 & CryptoAPI RC4) and Agile Encryption (XML v4.4) using user-supplied passwords and common malware passwords (such as `VelvetSweatshop`).
- **Rich Text Format (RTF)**: Native extraction of `\objdata`, `ods`, and `datastore` hex streams, OLE 1.0 objects (e.g., Equation Editor `Equation.3`), and `OLEPackage` embedded files (with resilience against RTF control-word obfuscation).
- **PDF Documents**: Native stream parser and filter pipeline supporting `/FlateDecode` (including PNG row predictors 10–15), `/ASCIIHexDecode`, `/ASCII85Decode`, `/LZWDecode`, `/RunLengthDecode`, `#xx` hex-escaped filter names, and PDF 1.5+ `/ObjStm` compressed object streams.
- **OpenXML / ZIP Containers**: Extraction and recursive analysis of `.docx`, `.xlsx`, `.pptx`, and embedded archives, relationships (`oleObject`, `aFChunk`, external templates), and ActiveX controls.
- **MIME / MHT / ActiveMime / WordML (`mso`)**: Base64 decoding and zlib inflation of `ActiveMime` headers and embedded payloads.
- **PostScript (`ps`) & OneNote (`.one`)**: Hex payload extraction and embedded script/executable detection.

---

## Parser Hardening & Security

Because all format parsers in `src/quicksand/quicksand.py` are written in memory-safe pure Python with explicit bounds checks, document buffer-overflow exploits (such as Equation Editor stack overflows or RTF `\fonttbl` heap corruption) cannot corrupt memory in QuickSand. In addition, QuickSand enforces strict resource limits against parser Denial-of-Service (DoS) attacks:

- **Decompression & Zip Bomb Protection**: All `zlib`, PDF `/FlateDecode`, `/LZWDecode`, `/RunLengthDecode`, MS-OVBA, and OpenXML ZIP stream reads are capped at **32 MB** (`MAX_DECOMPRESSED_STREAM_SIZE`) with archive entry limits (`MAX_ARCHIVE_ENTRIES = 1024`).
- **Cycle & Depth Guards**: OLE FAT/DIFAT/MiniFAT chains track visited sectors to prevent infinite loops, directory tree walks are depth-bounded, and recursive container analysis is capped at `MAX_NESTING_DEPTH = 10`.
- **Header & Crypto Bounds**: PDF PNG predictor column widths (`<= 65536`), OLE sector shifts (`512` or `4096` bytes), and Agile Encryption KDF `spinCount` (`<= 250,000`) are validated, and `<!DOCTYPE` / `<!ENTITY` declarations are rejected to prevent XML Billion Laughs attacks.

---

## Repository Structure

- `src/quicksand/quicksand.py`: Single-file QuickSand engine, native format parsers, and CLI entry point.
- `src/quicksand/quicksand_exploits.yara`: YARA signatures for Office, RTF, VBA, XLM, OpenXML, and OneNote exploits and warnings.
- `src/quicksand/quicksand_pdf.yara`: YARA signatures for PDF exploits, JavaScript obfuscation, and active content.
- `src/quicksand/quicksand_exe.yara`: YARA signatures for embedded PE/ELF binaries, LNK shortcuts, HTA/SCT scriptlets, and encoded payloads.
- `bin/quicksand`: Command-line wrapper script.
- `quicksand.spec`: PyInstaller specification for building standalone single-file executables (`quicksand.exe`, `quicksand-linux-x86_64`, `quicksand-macos-arm64`).
- `.github/workflows/build-windows-exe.yml`: GitHub Actions workflow for building standalone executables across Windows, Linux, and macOS.
- `.github/workflows/publish-pypi.yml`: GitHub Actions workflow for building and publishing the Python package to PyPI.
- [gcloud/](gcloud/README.md): Optional Google Cloud Run functions.
- [lambda/](lambda/README.md): Optional AWS Lambda functions.

---

## Dependencies

- Python `>= 3.7`
- `yara-python >= 4.3.0`

---

## Installation

### Install from PyPI

```bash
pip3 install quicksand
```

### Upgrade from PyPI

```bash
pip3 install --upgrade quicksand
```

### Install from Source

```bash
git clone https://github.com/tylabs/quicksand.git
cd quicksand
pip3 install .
```

### Building a Standalone Windows Executable (`quicksand.exe`)

When installed via `pip install .` on Windows, `pip` automatically creates a `quicksand.exe` CLI wrapper in your Python `Scripts\` directory.

To build a portable, single-file `dist\quicksand.exe` (which includes Python, `yara-python`, and all `.yara` rule files so no Python installation is required on the target machine):

```powershell
pip install -r requirements.txt pyinstaller
pyinstaller --clean quicksand.spec
```

> **Tip:** The standalone `quicksand.exe` uses its bundled `.yara` rules automatically, or you can place custom `quicksand_exploits.yara`, `quicksand_exe.yara`, or `quicksand_pdf.yara` files in the same folder as `quicksand.exe` to override them without rebuilding.

---

## Command-Line Usage

```text
usage: quicksand [-h] [--version] [-v] [-c] [-y] [-t SECONDS] [-p PASSWORD]
                 [-d DIR] [-f {json,txt}] [-o FILE] [-e FILE] [-x FILE]
                 [-a FILE]
                 document

QuickSand v2.2.0 - Document and PDF malware analysis tool.
Scans nested streams inside Office (OLE2, OpenXML, RTF, VBA, XLM), PDF,
MIME/ActiveMime, PostScript, and OneNote files using YARA signatures.

positional arguments:
  document              path to a document file or directory of documents to
                        scan

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

analysis & extraction options:
  -v, --verbose         enable verbose diagnostic logging during analysis
  -c, --capture         capture decoded stream contents in results
  -y, --yara            include matched YARA string offsets and previews in
                        output
  -t SECONDS, --timeout SECONDS
                        per-file analysis timeout in seconds (default: 0 =
                        unlimited)
  -p PASSWORD, --password PASSWORD
                        password for decrypting protected Office documents
  -d DIR, --dropdir DIR
                        directory to write extracted binary streams to
                        (implies --capture)

output options:
  -f {json,txt}, --format {json,txt}
                        report output format: 'json' or 'txt' (default: json)
  -o FILE, --out FILE   write report output to FILE instead of stdout

custom YARA signature options:
  -e FILE, --exploit FILE
                        custom path to exploit YARA rules (default: bundled
                        quicksand_exploits.yara)
  -x FILE, --exe FILE   custom path to executable YARA rules (default: bundled
                        quicksand_exe.yara)
  -a FILE, --pdf FILE   custom path to PDF YARA rules (default: bundled
                        quicksand_pdf.yara)

examples:
  quicksand suspicious.doc
  quicksand -f txt -y invoice.pdf
  quicksand -p VelvetSweatshop encrypted.xls
  quicksand -d extracted_streams/ -o report.json samples_dir/
```

### Scan a Single Document

```bash
quicksand document.doc
```

### Scan a Directory of Documents and Save Text Report

```bash
quicksand -f txt -o report.txt malware_samples/
```

### Extract Decoded Streams to Disk

```bash
quicksand -d extracted_streams/ suspicious.rtf
```

---

## Python Module Usage

### Scan a Document from Memory (`bytes`)

```python
import pprint
from quicksand import quicksand

with open("document.doc", "rb") as f:
    data = f.read()

qs = quicksand(data, timeout=18, strings=True)
qs.process()
pprint.pprint(qs.results)
```

### Scan a Document by File Path

```python
from quicksand import quicksand

qs = quicksand("file.pdf")
qs.process()
print(qs.results["risk"], qs.results["score"], qs.results["rating"])
```

### Scan All Files in a Directory

```python
from quicksand import quicksand

results = quicksand.readDir("malware_samples/")
```

Returns a dictionary mapping `{filepath: qs.results, ...}`.

### Optional `quicksand(...)` Parameters

- `capture` (`bool`, default `False`): Store decoded stream bytes in `results["streams"]`.
- `strings` (`bool`, default `True`): Include matched YARA string offsets and previews in `results["results"]`.
- `debug` (`bool`, default `False`): Print debug trace messages during parsing.
- `timeout` (`int`, default `0`): Maximum processing time in seconds (`0` for unlimited).
- `password` (`str`, default `None`): Password to try when decrypting password-protected Office documents (tried before the built-in default password list).
- `exploityara`, `execyara`, `pdfyara` (`str`, default `None`): Custom paths to override the bundled YARA rule files.

---

## Scoring & Risk Ratings

Each YARA signature defines metadata classifying the detection (`is_exploit`, `is_warning`, `is_feature`, `is_exe`), a `rank` score weight, and MITRE ATT&CK® technique IDs (`mitre`).

To prevent double-counting when the same content appears in both a raw stream and a decompressed child stream, QuickSand deduplicates each rule's score contribution per document while recording all matching stream locations in `results["results"]`.

| Rating | Risk Label | Criteria |
| :---: | :--- | :--- |
| `0` | `nothing detected` | `score == 0` (only benign or informational `rank = 0` features present) |
| `1` | `risky active content` | Low-to-moderate active content warnings (`1 <= score < 6`) |
| `2` | `high risk active content` / `risk of exploit` | Embedded executable (`execute >= 1`), single low-rank exploit indicator, or cumulative warning `score >= 6` |
| `3` | `high risk of exploit` | Confirmed exploit with `score >= 10`, multiple distinct exploits (`exploit >= 2`), or executable paired with exploit/high warning score |

For more details on interpreting results, see [scan.tylabs.com/howto](https://scan.tylabs.com/howto).

---

## Using QuickSand?

[Let us know](https://tylabs.com) @tylabs

## Issues and Project Home

[QuickSand GitHub](https://github.com/tylabs/quicksand/)
