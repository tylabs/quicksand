"""QuickSand: Document and PDF malware analysis framework using native parsers and YARA."""

from .quicksand import (
    BytesDump,
    keys_string,
    main,
    process_directory,
    process_file,
    quicksand,
    save_streams,
    txt_out,
)

__version__ = quicksand.__version__
__all__ = [
    "quicksand",
    "main",
    "BytesDump",
    "keys_string",
    "txt_out",
    "save_streams",
    "process_file",
    "process_directory",
    "__version__",
]
