# QuickSand.io Version 2

QuickSand.io Python Library and Command Line Tool

QuickSand is a Python-based analysis framework to analyze suspected malware documents to identify exploits in streams of different encodings or compressions. QuickSand supports documents, PDFs, Mime/Email, Postscript and other common formats. 

QuickSand supports scanning using Yara signatures within the decoded streams of documents and PDFs to identify exploits or high risk active content.

A hosted version is available to try without any installation at [quicksand.io](https://quicksand.io/).


## Files:

- src/quicksand/quicksand.py: Main quicksand class and CLI tool

- src/quicksand/quicksand_exe.yara: Yara rules to detect executables.

- src/quicksand/quicksand_exploits.yara: Yara rules to detect exploits in documents.

- src/quicksand/quicksand_pdf.yara: Yara rules to detect exploits in PDFs.

- bin/quicksand: Command line tool.

- requirements.txt: pip dependencies 

- lambda/Dockerfile for building an Amazon Lambda environment

- lambda/wait.py helper script for building Amazon Lambda environment



### Python modules

- pdfreader

- oletools

- cryptography

- zipfile38

- olefile

- yara-python


### Yara-python note:

We recommend you installing yara-python from source as the pip builds on some operating systems might not be fully functional (hash module in particular.)

## Install from Pypi

```
pip3 install quicksand
```

## Upgrade

```
pip3 install --upgrade quicksand
```


## Usage CLI

A command line tool for quicksand to process and output json results is included. More features and pretty output will be added soon.


### Single file

```
quicksand document.doc
```

### Directory of Files

```
quicksand malware/
```

## Usage Python Module

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
Returns a dictionary of filename: `qs_results`.


### Extract Streams As Files

```
from quicksand.quicksand import quicksand
import os

qs = quicksand("malware.doc", capture=True, debug=True)
qs.process()
print (qs.results)

if not os.path.isdir("tmp"):
    os.mkdir("tmp")
for item in qs.results['streams']:
    print (item)
    f = open('tmp/' + str(item), 'wb')
    f.write(qs.results['streams'][item])
    f.close()
```

Writes extracted streams to ./tmp.


### Extra Options for Constructor

- capture: True|False return content of extracted streams

- debug: True|False print debugging messages to stdout

- exploityara: Path to exploit yara rules

- execyara: Path to executable yara rules

- pdfyara: PDF Exploits yara rules



### Jupyter Notes

Python might not be able to figure out the path to the yara signatures on it's own in Jupyter. You can either copy the yara files to the working directory with the .ipynb file, or provide the paths at run time:

```
from quicksand.quicksand import quicksand
import os

qs = quicksand("malware/7ab0d0424eb9d655c0ee6d4a23473abf0c875892745336cb17fba7274dfe11a4", capture=True, debug=True, exploityara="/Users/user/Documents/GitHub/jupyter/quicksand/quicksand_exploits.yara", pdfyara="/Users/user/Documents/GitHub/jupyter/quicksand/quicksand_pdf.yara",execyara="/Users/user/Documents/GitHub/jupyter/quicksand_/quicksand_exe.yara" )
qs.process()
print (qs.results)
````


