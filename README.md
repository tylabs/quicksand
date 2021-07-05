# QuickSand.io Version 2

QuickSand.io Python Library and Command Line Tool

QuickSand is a Python-based analysis framework to analyze suspected malware documents to identify exploits in streams of different encodings or compressions. QuickSand supports documents, PDFs, Mime/Email, Postscript and other common formats. A built-in command line tool can process a single document or directory of documents.

QuickSand supports scanning using Yara signatures within the decoded streams of documents and PDFs to identify exploits or high risk active content.

A hosted version is available to try without any installation at [quicksand.io](https://quicksand.io/).


## Files:

- src/quicksand/quicksand.py: Main quicksand class and CLI tool

- src/quicksand/quicksand_exe.yara: Yara rules to detect executables.

- src/quicksand/quicksand_exploits.yara: Yara rules to detect exploits in documents.

- src/quicksand/quicksand_pdf.yara: Yara rules to detect exploits in PDFs.

- bin/quicksand: Command line tool.

- requirements.txt: Python dependencies 

- lambda/Dockerfile for building an Amazon Lambda environment

- lambda/wait.py helper script for building Amazon Lambda environment


### With Thanks to the Creators of:

- pdfreader

- oletools

- cryptography

- zipfile38

- olefile

- yara-python


### Yara-python note:

We recommend you installing yara-python from source as the pip builds on some operating systems might not be fully functional (hash module in particular.)


## Installation from Pypi using pip

```
pip3 install quicksand
```


## Upgrade

```
pip3 install --upgrade quicksand
```


## Command Line Usage

A command line tool for quicksand to process and output json or txt results.

```
usage: quicksand [-h] [-v] [-c] [-y] [-t TIMEOUT] [-e EXPLOIT] [-x EXE] [-a PDF] [-f {json,txt}] [-o OUT] [-p PASSWORD]
                 [-d DROPDIR]
                 document

QuickSand Document and PDF maldoc analysis tool.

positional arguments:
  document              document or directory to scan

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -c, --capture         capture stream content
  -y, --yara            capture yara matched strings
  -t TIMEOUT, --timeout TIMEOUT
                        timeout in seconds
  -e EXPLOIT, --exploit EXPLOIT
                        yara exploit signatures
  -x EXE, --exe EXE     yara executable signatures
  -a PDF, --pdf PDF     yara PDF signatures
  -f {json,txt}, --format {json,txt}
                        output format
  -o OUT, --out OUT     save output to this filename
  -p PASSWORD, --password PASSWORD
                        password to decrypt ole or pdf
  -d DROPDIR, --dropdir DROPDIR
                        save objects to this directory

```

### Process a single file

```
quicksand document.doc
```

### Process a directory of files

```
quicksand malware/
```


## Python Module Usage

### File from memory

```
from quicksand.quicksand import quicksand
import pprint

qs = quicksand(data, timeout=18, strings=True)
qs.process()
pprint.pprint(qs.results)
```

### Filename

```
from quicksand.quicksand import quicksand

qs2 = quicksand("file.doc")
qs2.process()
qs.results
```

### Process a Directory

```
from quicksand.quicksand import quicksand
qs = quicksand.readDir("malware")
qs
```
Returns a dictionary of {filename: `qs_results`,...}.


### Optional initializer values

- capture: True|False return content of extracted streams

- debug: True|False print debugging messages to stdout

- exploityara: Path to exploit yara rules

- execyara: Path to executable yara rules

- pdfyara: PDF Exploits yara rules

- password: Password for encrypted documents/PDFs

- timeout: Timeout processing: 0 for unlimited.


### zlib issues on MacOS

MacOS users may get zlib issues (PDF FlateDecode etc) due to missing OpenSSL headers since MacOs 10.4.

```
zlib.error: Error -3 while decompressing data: unknown compression method
zlib.error: Error -3 while decompressing data: incorrect header check
```

One solution is to install zlib with Brew.sh and reinstall Python 3 using pyenv:

```
export LDFLAGS="-L/usr/local/opt/zlib/lib"
export CPPFLAGS="-I/usr/local/opt/zlib/include"
pyenv install 3.8.5
```


