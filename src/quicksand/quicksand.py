#!/usr/bin/env python3
"""QuickSand 2: Document and PDF Malware Analysis Framework.

QuickSand analyzes suspected malware documents and PDFs to detect exploits,
active content, obfuscated scripts, and embedded executables across nested
streams, encodings, and compressions.

It uses YARA-Python for signature matching alongside memory-safe, pure-Python
standard-library parsers for:
    - OLE2 Compound Files ([MS-CFB]) and [MS-OLEPS] SummaryInformation metadata
    - VBA Macro compression containers ([MS-OVBA]) and p-code stomping
    - Excel BIFF5/BIFF8 Workbooks and Excel 4.0 (XLM) macro sheets ([MS-XLS])
    - Office document encryption ([MS-OFFCRYPTO] Standard & Agile AES/RC4)
    - Rich Text Format (RTF) OLE 1.0 objects and OLEPackage embedded files
    - PDF streams (/FlateDecode with PNG predictors, /ASCIIHexDecode,
      /ASCII85Decode, /LZWDecode, /RunLengthDecode, and /ObjStm)
    - OpenXML (.docx, .xlsx, .pptx) and ZIP containers
    - MSO / ActiveMime / MIME / WordML and PostScript documents

Copyright (c) 2026 @tylabs (https://github.com/tylabs/quicksand)
License: MIT
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import string
import struct
import sys
import time
import traceback
import xml.etree.ElementTree as ET
import zipfile
import zlib
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yara


# =====================================================================
# Security & Resource Exhaustion Limits (Anti-DoS / Decompression Bomb)
# =====================================================================

MAX_DECOMPRESSED_STREAM_SIZE = 32 * 1024 * 1024  # 32 MB cap per decompressed stream
MAX_ARCHIVE_ENTRIES = 1024                       # Max files scanned inside a single ZIP/OpenXML container
MAX_CARVED_ELEMENTS = 64                         # Max carved sub-streams per container stream
MAX_NESTING_DEPTH = 10                           # Max recursive container analysis depth
MAX_PDF_PREDICTOR_COLUMNS = 65536                # Max PNG predictor row width in bytes
MAX_AGILE_SPIN_COUNT = 250000                    # Max ECMA-376 Agile KDF iterations (standard is 100,000)


# =====================================================================
# Pre-compiled Regular Expressions & Binary Signatures
# =====================================================================

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
OLE_MAGIC_SHORT = b"\xd0\xcf\x11\xe0"
OPENXML_MAGIC = b"\x50\x4b\x03\x04\x14\x00\x06\x00"
OPENXML_MAGIC_SHORT = b"\x50\x4b\x03\x04\x14\x00"
ZIP_MAGIC = b"PK\x03\x04"
ZLIB_HEADER_MAGIC = b"\x00\x00\x78\x9c"
PPT_ATOM_MAGIC = b"\x10\x00\x11\x10"

RE_RTF_HEADER = re.compile(rb"\\\\rt", re.IGNORECASE)
RE_PDF_HEADER = re.compile(rb"%PDF", re.IGNORECASE)
RE_XDP_HEADER = re.compile(rb"ns\.adobe\.com/xdp", re.IGNORECASE)
RE_MIME_HEADER = re.compile(rb"MIME-Version", re.IGNORECASE)
RE_XML_HEADER = re.compile(rb"xml", re.IGNORECASE)

RE_PDF_STRUCTURE = re.compile(
    rb"((\x0a|\x0d|\x20)(\d{1,6})[^\d]{1,3}(\d{1,2})\sobj|(\x0a|\x0d)(xref|trailer)(\x0a|\x0d))"
)
RE_PDF_OBJ_STREAM = re.compile(
    rb"(?:^|[\x0a\x0d\x20])(\d{1,7})\s+(\d{1,5})\s+obj\b((?:(?!endobj\b).)*?)stream(?:\r\n|\n|\r)(.*?)(?:\r\n|\n|\r)?endstream",
    re.DOTALL,
)
RE_PDF_NAME_HEX = re.compile(rb"#([0-9a-fA-F]{2})")
RE_PDF_FILTER_ARRAY = re.compile(rb"/Filter\s*\[([^\]]+)\]", re.DOTALL)
RE_PDF_FILTER_SINGLE = re.compile(rb"/Filter\s*/([A-Za-z0-9#]+)")
RE_PDF_NAME_TOKEN = re.compile(rb"/([A-Za-z0-9#]+)")
RE_PDF_PREDICTOR = re.compile(rb"/Predictor\s+(\d+)")
RE_PDF_COLUMNS = re.compile(rb"/Columns\s+(\d+)")
RE_PDF_EARLYCHANGE = re.compile(rb"/EarlyChange\s+(\d+)")
RE_PDF_OBJSTM_N = re.compile(rb"/N\s+(\d+)")
RE_PDF_OBJSTM_FIRST = re.compile(rb"/First\s+(\d+)")

RE_RTF_BRACE_FIX = re.compile(rb"\d}(\d)")
RE_RTF_ODS_FIX = re.compile(rb"\{ods(\d)")
RE_RTF_ODS_BLOCK = re.compile(rb"\{\\ods([a-zA-Z0-9 \x0a\x0d]{512,})")
RE_RTF_DATASTORE_BLOCK = re.compile(rb"datastore ([a-zA-Z0-9 \x0a\x0d]{512,})")
RE_RTF_WHITESPACE = re.compile(rb"[ \t\x0a\x0d]")
RE_MSO_BASE64 = re.compile(rb"([a-zA-Z0-9/+=\x0a\x0d]{256,})")
RE_PS_HEX_STRING = re.compile(rb"<([0-9a-fA-F\x0a\x0d\x20\x09]{32,})>")
RE_PS_HEX_BLOCK = re.compile(rb"(?:^|[\x0a\x0d\x20\x09])([0-9a-fA-F\x0a\x0d\x20\x09]{64,})(?=$|[\x0a\x0d\x20\x09])")


# =====================================================================
# Pure-Python Cryptographic Primitives (RC4, XOR, AES)
# =====================================================================

DEFAULT_OFFICE_PASSWORDS = [
    "VelvetSweatshop",
    "123456",
    "password",
    "1234",
    "",
]


def _rc4(key: bytes, data: bytes) -> bytes:
    """Pure-Python RC4 stream cipher."""
    s = list(range(256))
    j = 0
    key_len = len(key)
    if key_len == 0:
        return data
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = 0
    j = 0
    out = bytearray(len(data))
    for idx, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[idx] = byte ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


# Pure-Python AES implementation (supports AES-128, AES-192, AES-256 ECB & CBC)
_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_AES_INV_SBOX = [0] * 256
for _idx, _val in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_val] = _idx


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


_MUL9 = [_gmul(i, 9) for i in range(256)]
_MUL11 = [_gmul(i, 11) for i in range(256)]
_MUL13 = [_gmul(i, 13) for i in range(256)]
_MUL14 = [_gmul(i, 14) for i in range(256)]


def _aes_expand_key(key: bytes) -> List[List[int]]:
    nk = len(key) // 4
    nr = nk + 6
    w: List[int] = list(struct.unpack(f">{nk}I", key))
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            rotated = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
            subbed = (
                (_AES_SBOX[(rotated >> 24) & 0xFF] << 24)
                | (_AES_SBOX[(rotated >> 16) & 0xFF] << 16)
                | (_AES_SBOX[(rotated >> 8) & 0xFF] << 8)
                | _AES_SBOX[rotated & 0xFF]
            )
            temp = subbed ^ (rcon << 24)
            rcon = _gmul(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = (
                (_AES_SBOX[(temp >> 24) & 0xFF] << 24)
                | (_AES_SBOX[(temp >> 16) & 0xFF] << 16)
                | (_AES_SBOX[(temp >> 8) & 0xFF] << 8)
                | _AES_SBOX[temp & 0xFF]
            )
        w.append(w[i - nk] ^ temp)
    round_keys: List[List[int]] = []
    for r in range(nr + 1):
        rk_bytes = struct.pack(">4I", *w[r * 4 : (r + 1) * 4])
        round_keys.append(list(rk_bytes))
    return round_keys


def _aes_decrypt_block(block: bytes, round_keys: List[List[int]]) -> bytes:
    nr = len(round_keys) - 1
    s = [block[i] ^ round_keys[nr][i] for i in range(16)]
    for r in range(nr - 1, 0, -1):
        # InvShiftRows + InvSubBytes
        s = [
            _AES_INV_SBOX[s[0]], _AES_INV_SBOX[s[13]], _AES_INV_SBOX[s[10]], _AES_INV_SBOX[s[7]],
            _AES_INV_SBOX[s[4]], _AES_INV_SBOX[s[1]], _AES_INV_SBOX[s[14]], _AES_INV_SBOX[s[11]],
            _AES_INV_SBOX[s[8]], _AES_INV_SBOX[s[5]], _AES_INV_SBOX[s[2]], _AES_INV_SBOX[s[15]],
            _AES_INV_SBOX[s[12]], _AES_INV_SBOX[s[9]], _AES_INV_SBOX[s[6]], _AES_INV_SBOX[s[3]],
        ]
        # AddRoundKey
        rk = round_keys[r]
        for i in range(16):
            s[i] ^= rk[i]
        # InvMixColumns
        for c in range(0, 16, 4):
            a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
            s[c] = _MUL14[a0] ^ _MUL11[a1] ^ _MUL13[a2] ^ _MUL9[a3]
            s[c + 1] = _MUL9[a0] ^ _MUL14[a1] ^ _MUL11[a2] ^ _MUL13[a3]
            s[c + 2] = _MUL13[a0] ^ _MUL9[a1] ^ _MUL14[a2] ^ _MUL11[a3]
            s[c + 3] = _MUL11[a0] ^ _MUL13[a1] ^ _MUL9[a2] ^ _MUL14[a3]
    # Final round
    s = [
        _AES_INV_SBOX[s[0]], _AES_INV_SBOX[s[13]], _AES_INV_SBOX[s[10]], _AES_INV_SBOX[s[7]],
        _AES_INV_SBOX[s[4]], _AES_INV_SBOX[s[1]], _AES_INV_SBOX[s[14]], _AES_INV_SBOX[s[11]],
        _AES_INV_SBOX[s[8]], _AES_INV_SBOX[s[5]], _AES_INV_SBOX[s[2]], _AES_INV_SBOX[s[15]],
        _AES_INV_SBOX[s[12]], _AES_INV_SBOX[s[9]], _AES_INV_SBOX[s[6]], _AES_INV_SBOX[s[3]],
    ]
    rk0 = round_keys[0]
    return bytes(s[i] ^ rk0[i] for i in range(16))


def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    rks = _aes_expand_key(key)
    out = bytearray()
    for offset in range(0, len(data) - (len(data) % 16), 16):
        out.extend(_aes_decrypt_block(data[offset : offset + 16], rks))
    return bytes(out)


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    rks = _aes_expand_key(key)
    out = bytearray()
    prev = iv[:16]
    for offset in range(0, len(data) - (len(data) % 16), 16):
        blk = data[offset : offset + 16]
        dec = _aes_decrypt_block(blk, rks)
        out.extend(dec[i] ^ prev[i] for i in range(16))
        prev = blk
    return bytes(out)


# =====================================================================
# Native [MS-CFB] (OLE2 Compound File Binary) Parser
# =====================================================================

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC


def is_ole_file(data: bytes) -> bool:
    """Return True if data begins with the 8-byte MS-CFB magic signature."""
    return len(data) >= 512 and data[:8] == OLE_MAGIC


class _OleMetadata:
    """Container for OLE SummaryInformation & DocumentSummaryInformation properties."""

    def __init__(self) -> None:
        self.author: Optional[bytes] = None
        self.company: Optional[bytes] = None
        self.last_saved_by: Optional[bytes] = None
        self.title: Optional[bytes] = None
        self.create_time: Optional[datetime.datetime] = None
        self.last_saved_time: Optional[datetime.datetime] = None
        self.bytes: Optional[int] = None


class _OleDirEntry:
    """Represents a 128-byte MS-CFB Directory Entry."""

    def __init__(self, raw: bytes, sid: int, is_v3: bool = True) -> None:
        self.sid = sid
        name_raw = raw[:64]
        name_len = struct.unpack_from("<H", raw, 64)[0]
        if 2 <= name_len <= 64:
            self.name = name_raw[: name_len - 2].decode("utf-16-le", errors="replace")
        else:
            self.name = ""
        self.obj_type = raw[66]
        self.color = raw[67]
        self.left_sibling, self.right_sibling, self.child_id = struct.unpack_from("<III", raw, 68)
        self.clsid_bytes = raw[80:96]
        self.start_sector = struct.unpack_from("<I", raw, 116)[0]
        raw_size = struct.unpack_from("<Q", raw, 120)[0]
        self.size = (raw_size & 0xFFFFFFFF) if is_v3 else raw_size


class _OleFile:
    """Lightweight, bounds-checked pure-Python MS-CFB (OLE2) reader."""

    def __init__(self, data: bytes) -> None:
        if not is_ole_file(data):
            raise ValueError("Not a valid OLE2 Compound File")
        self.data = data
        self.sector_shift = struct.unpack_from("<H", data, 30)[0]
        self.mini_sector_shift = struct.unpack_from("<H", data, 32)[0]
        if self.sector_shift not in (9, 12) or self.mini_sector_shift != 6:
            # Fallback to standard v3 sizes if header fields are non-standard
            self.sector_shift = 9
            self.mini_sector_shift = 6
        self.sector_size = 1 << self.sector_shift
        self.mini_sector_size = 1 << self.mini_sector_shift
        self.is_v3 = self.sector_shift == 9

        (
            self.num_dir_sectors,
            self.num_fat_sectors,
            self.first_dir_sector,
            self.tx_sig,
            self.mini_stream_cutoff_size,
            self.first_minifat_sector,
            self.num_minifat_sectors,
            self.first_difat_sector,
            self.num_difat_sectors,
        ) = struct.unpack_from("<9I", data, 40)

        if self.mini_stream_cutoff_size == 0:
            self.mini_stream_cutoff_size = 4096

        self.max_sectors = max(1, (len(data) // self.sector_size))
        self.fat: List[int] = []
        self.minifat: List[int] = []
        self.dir_entries: List[_OleDirEntry] = []
        self.paths: List[Tuple[List[str], _OleDirEntry]] = []
        self.mini_stream: bytes = b""
        self.max_used_sector: int = 0

        self._load_fat()
        self._load_directory()
        self._load_minifat()

    def _get_sector(self, sector_id: int) -> bytes:
        offset = (sector_id + 1) * self.sector_size
        if offset < 0 or offset >= len(self.data):
            return b""
        if sector_id > self.max_used_sector:
            self.max_used_sector = sector_id
        end = offset + self.sector_size
        chunk = self.data[offset:end]
        if len(chunk) < self.sector_size:
            chunk = chunk + b"\x00" * (self.sector_size - len(chunk))
        return chunk

    def _load_fat(self) -> None:
        difat = list(struct.unpack_from("<109I", self.data, 76))
        difat = [s for s in difat if s not in (FREESECT, ENDOFCHAIN)]

        curr_difat = self.first_difat_sector
        visited_difat: Set[int] = set()
        entries_per_sector = self.sector_size // 4
        while (
            curr_difat not in (FREESECT, ENDOFCHAIN)
            and curr_difat < self.max_sectors
            and curr_difat not in visited_difat
            and len(visited_difat) < 1024
        ):
            visited_difat.add(curr_difat)
            sec = self._get_sector(curr_difat)
            if not sec:
                break
            vals = struct.unpack(f"<{entries_per_sector}I", sec)
            for s in vals[:-1]:
                if s not in (FREESECT, ENDOFCHAIN):
                    difat.append(s)
            curr_difat = vals[-1]

        for fat_sec_id in difat:
            if fat_sec_id >= self.max_sectors:
                continue
            sec = self._get_sector(fat_sec_id)
            if not sec:
                continue
            self.fat.extend(struct.unpack(f"<{entries_per_sector}I", sec))

    def _read_chain(self, start_sector: int, max_size: Optional[int] = None) -> bytes:
        if start_sector in (ENDOFCHAIN, FREESECT) or start_sector >= self.max_sectors:
            return b""
        chunks: List[bytes] = []
        curr = start_sector
        visited: Set[int] = set()
        total = 0
        while (
            curr not in (ENDOFCHAIN, FREESECT, FATSECT, DIFSECT)
            and curr < self.max_sectors
            and curr not in visited
        ):
            visited.add(curr)
            sec = self._get_sector(curr)
            if not sec:
                break
            chunks.append(sec)
            total += len(sec)
            if max_size is not None and total >= max_size:
                break
            if curr < len(self.fat):
                curr = self.fat[curr]
            else:
                break
        raw = b"".join(chunks)
        if max_size is not None and len(raw) > max_size:
            return raw[:max_size]
        return raw

    def _load_directory(self) -> None:
        dir_data = self._read_chain(self.first_dir_sector)
        for i in range(0, len(dir_data) - 127, 128):
            entry = _OleDirEntry(dir_data[i : i + 128], i // 128, is_v3=self.is_v3)
            self.dir_entries.append(entry)

        if not self.dir_entries:
            return

        visited_sids: Set[int] = {0}

        def walk_tree(sid: int, prefix: List[str], depth: int = 0) -> None:
            if (
                sid == 0xFFFFFFFF
                or sid >= len(self.dir_entries)
                or sid in visited_sids
                or depth > 128
            ):
                return
            visited_sids.add(sid)
            entry = self.dir_entries[sid]
            walk_tree(entry.left_sibling, prefix, depth + 1)
            if entry.obj_type == 2 and entry.name:  # Stream
                self.paths.append((prefix + [entry.name], entry))
            elif entry.obj_type == 1 and entry.name:  # Storage
                walk_tree(entry.child_id, prefix + [entry.name], depth + 1)
            walk_tree(entry.right_sibling, prefix, depth + 1)

        root = self.dir_entries[0]
        walk_tree(root.child_id, [], 0)

        # Fallback: if sibling tree pointers were broken/tampered, include unvisited streams
        for entry in self.dir_entries[1:]:
            if entry.sid not in visited_sids and entry.obj_type == 2 and entry.name:
                self.paths.append(([entry.name], entry))

    def _load_minifat(self) -> None:
        if not self.dir_entries:
            return
        root = self.dir_entries[0]
        if root.start_sector not in (ENDOFCHAIN, FREESECT):
            self.mini_stream = self._read_chain(root.start_sector, root.size)
        if self.first_minifat_sector not in (ENDOFCHAIN, FREESECT):
            minifat_bytes = self._read_chain(self.first_minifat_sector)
            count = len(minifat_bytes) // 4
            if count > 0:
                self.minifat = list(struct.unpack(f"<{count}I", minifat_bytes[: count * 4]))

    def _read_mini_chain(self, start_mini_sector: int, size: int) -> bytes:
        if start_mini_sector in (ENDOFCHAIN, FREESECT) or not self.mini_stream:
            return b""
        chunks: List[bytes] = []
        curr = start_mini_sector
        visited: Set[int] = set()
        total = 0
        max_mini = len(self.mini_stream) // self.mini_sector_size
        while (
            curr not in (ENDOFCHAIN, FREESECT)
            and curr <= max_mini
            and curr not in visited
            and total < size
        ):
            visited.add(curr)
            offset = curr * self.mini_sector_size
            chunk = self.mini_stream[offset : offset + self.mini_sector_size]
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if curr < len(self.minifat):
                curr = self.minifat[curr]
            else:
                break
        return b"".join(chunks)[:size]

    def listdir(self, streams: bool = True, storages: bool = False) -> List[List[str]]:
        return [list(path) for path, _ in self.paths]

    def openstream(self, path: Union[List[str], Tuple[str, ...], str]) -> BytesIO:
        target = [path] if isinstance(path, str) else list(path)
        for p, entry in self.paths:
            if p == target:
                return BytesIO(self._read_entry(entry))
        # Case-insensitive fallback
        target_lower = [x.lower() for x in target]
        for p, entry in self.paths:
            if [x.lower() for x in p] == target_lower:
                return BytesIO(self._read_entry(entry))
        raise KeyError(f"OLE stream not found: {path}")

    def _read_entry(self, entry: _OleDirEntry) -> bytes:
        if entry.size == 0:
            return b""
        capped_size = min(entry.size, MAX_DECOMPRESSED_STREAM_SIZE)
        if entry.obj_type != 5 and entry.size < self.mini_stream_cutoff_size and self.mini_stream:
            return self._read_mini_chain(entry.start_sector, capped_size)
        return self._read_chain(entry.start_sector, capped_size)

    def get_metadata(self) -> _OleMetadata:
        meta = _OleMetadata()
        # Parse \x05SummaryInformation
        for p, entry in self.paths:
            name_clean = p[-1].lstrip("\x05").lower()
            if name_clean == "summaryinformation":
                self._parse_property_set(self._read_entry(entry), meta, is_doc_summary=False)
            elif name_clean == "documentsummaryinformation":
                self._parse_property_set(self._read_entry(entry), meta, is_doc_summary=True)
        return meta

    @staticmethod
    def _parse_property_set(raw: bytes, meta: _OleMetadata, is_doc_summary: bool) -> None:
        if len(raw) < 48:
            return
        byte_order, _version, _sys_id = struct.unpack_from("<HHI", raw, 0)
        if byte_order != 0xFFFE:
            return
        num_sections = struct.unpack_from("<I", raw, 24)[0]
        if num_sections < 1:
            return
        sec_offset = struct.unpack_from("<I", raw, 44)[0]
        if sec_offset + 8 > len(raw):
            return
        _sec_size, num_props = struct.unpack_from("<II", raw, sec_offset)
        num_props = min(num_props, 256)
        for i in range(num_props):
            pair_off = sec_offset + 8 + i * 8
            if pair_off + 8 > len(raw):
                break
            prop_id, prop_rel_off = struct.unpack_from("<II", raw, pair_off)
            val_off = sec_offset + prop_rel_off
            if val_off + 8 > len(raw):
                continue
            vt_type = struct.unpack_from("<I", raw, val_off)[0] & 0xFFFF
            val: Any = None
            if vt_type == 0x001E:  # VT_LPSTR
                str_len = struct.unpack_from("<I", raw, val_off + 4)[0]
                if 0 < str_len <= 65536 and val_off + 8 + str_len <= len(raw):
                    val = raw[val_off + 8 : val_off + 8 + str_len].rstrip(b"\x00")
            elif vt_type == 0x001F:  # VT_LPWSTR
                char_len = struct.unpack_from("<I", raw, val_off + 4)[0]
                byte_len = char_len * 2
                if 0 < byte_len <= 131072 and val_off + 8 + byte_len <= len(raw):
                    txt = raw[val_off + 8 : val_off + 8 + byte_len].decode("utf-16-le", errors="replace").rstrip("\x00")
                    val = txt.encode("utf-8", errors="replace")
            elif vt_type in (0x0003, 0x0013):  # VT_I4 / VT_UI4
                val = struct.unpack_from("<I", raw, val_off + 4)[0]
            elif vt_type == 0x0040 and val_off + 12 <= len(raw):  # VT_FILETIME
                ft = struct.unpack_from("<Q", raw, val_off + 4)[0]
                if ft > 0:
                    try:
                        val = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
                    except (OverflowError, ValueError):
                        val = None

            if not is_doc_summary:
                if prop_id == 0x02 and isinstance(val, bytes):
                    meta.title = val
                elif prop_id == 0x04 and isinstance(val, bytes):
                    meta.author = val
                elif prop_id == 0x08 and isinstance(val, bytes):
                    meta.last_saved_by = val
                elif prop_id == 0x0C and isinstance(val, datetime.datetime):
                    meta.create_time = val
                elif prop_id == 0x0D and isinstance(val, datetime.datetime):
                    meta.last_saved_time = val
            else:
                if prop_id == 0x04 and isinstance(val, int):
                    meta.bytes = val
                elif prop_id == 0x0F and isinstance(val, bytes):
                    meta.company = val


# =====================================================================
# Native [MS-OVBA] VBA Macro Stream Decompression
# =====================================================================

def decompress_vba_container(container: bytes, max_output: int = MAX_DECOMPRESSED_STREAM_SIZE) -> bytes:
    """Decompress a single MS-OVBA CompressedContainer starting with 0x01."""
    if not container or container[0] != 0x01:
        return b""
    pos = 1
    out = bytearray()
    n = len(container)
    while pos + 2 <= n and len(out) < max_output:
        header = struct.unpack_from("<H", container, pos)[0]
        pos += 2
        chunk_size = (header & 0x0FFF) + 3
        chunk_sig = (header >> 12) & 0x07
        is_compressed = (header >> 15) & 0x01
        if chunk_sig != 0b011:
            break
        chunk_end = min(n, pos + chunk_size - 2)
        if not is_compressed:
            out.extend(container[pos : min(n, pos + 4096)])
            pos += 4096
            continue
        chunk_start_out = len(out)
        while pos < chunk_end and len(out) < max_output:
            flags = container[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end or len(out) >= max_output:
                    break
                if ((flags >> bit) & 1) == 0:
                    out.append(container[pos])
                    pos += 1
                else:
                    if pos + 2 > chunk_end:
                        pos = chunk_end
                        break
                    token = struct.unpack_from("<H", container, pos)[0]
                    pos += 2
                    decompressed_chunk_len = len(out) - chunk_start_out
                    bit_count = max(4, (decompressed_chunk_len - 1).bit_length())
                    length_mask = 0xFFFF >> bit_count
                    offset_mask = (~length_mask) & 0xFFFF
                    length = (token & length_mask) + 3
                    offset = ((token & offset_mask) >> (16 - bit_count)) + 1
                    copy_src = len(out) - offset
                    if copy_src < 0:
                        break
                    for _ in range(length):
                        if len(out) >= max_output:
                            break
                        out.append(out[copy_src])
                        copy_src += 1
        pos = chunk_end
    return bytes(out)


def decompress_vba_stream(stream_data: bytes) -> bytes:
    """Locate and decompress MS-OVBA compressed macro source inside a VBA stream."""
    if not stream_data:
        return b""
    if stream_data[0] == 0x01:
        dec = decompress_vba_container(stream_data)
        if dec:
            return dec
    # Search for compressed container signature (0x01 followed by a valid chunk header with sig 0b011)
    idx = 0
    n = len(stream_data)
    while idx < n - 3:
        pos = stream_data.find(b"\x01", idx)
        if pos == -1 or pos + 3 > n:
            break
        hdr = struct.unpack_from("<H", stream_data, pos + 1)[0]
        if ((hdr >> 12) & 0x07) == 0b011 and ((hdr >> 15) & 0x01) == 1:
            dec = decompress_vba_container(stream_data[pos:])
            if b"Attribute VB_" in dec or len(dec) > 64:
                return dec
        idx = pos + 1
    return b""


# =====================================================================
# Native Excel BIFF5 / BIFF8 XLM Macro & Record Scanner
# =====================================================================

_XLM_FUNCTIONS = {
    2: "BEEP", 3: "OPEN", 4: "CLOSE", 6: "SAVE", 7: "SAVE.AS", 9: "PRINT",
    12: "GOTO", 13: "HALT", 15: "SET.NAME", 22: "GET.DEF", 24: "GET.DOCUMENT",
    27: "WAIT", 35: "RETURN", 45: "EXEC", 49: "CALL", 51: "REGISTER",
    60: "FORMULA", 65: "FILES", 66: "DIRECTORY", 74: "FOPEN", 75: "FCLOSE",
    76: "FSIZE", 77: "FREADLN", 78: "FREAD", 79: "FWRITELN", 80: "FWRITE",
    89: "CHAR", 96: "RESULT", 107: "GET.WORKSPACE", 108: "GET.WINDOW",
    109: "GET.CELL", 130: "RUN", 148: "EVALUATE", 171: "WHILE", 172: "NEXT",
    185: "GET.WORKBOOK", 252: "REGISTER.ID", 255: "EXTERNAL",
}


def _decode_biff8_unicode(buf: bytes, offset: int, char_count: int) -> Tuple[str, int]:
    """Decode a BIFF8 UnicodeString starting with the 1-byte flags field."""
    if offset >= len(buf) or char_count <= 0:
        return "", offset
    flags = buf[offset]
    pos = offset + 1
    is_16bit = bool(flags & 0x01)
    has_ext = bool(flags & 0x04)
    has_rich = bool(flags & 0x08)
    rich_runs = 0
    ext_size = 0
    if has_rich and pos + 2 <= len(buf):
        rich_runs = struct.unpack_from("<H", buf, pos)[0]
        pos += 2
    if has_ext and pos + 4 <= len(buf):
        ext_size = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
    if is_16bit:
        byte_len = char_count * 2
        text = buf[pos : pos + byte_len].decode("utf-16-le", errors="replace")
        pos += byte_len
    else:
        text = buf[pos : pos + char_count].decode("latin-1", errors="replace")
        pos += char_count
    pos += rich_runs * 4 + ext_size
    return text, pos


def _decode_formula_tokens(rgce: bytes) -> str:
    """Decode basic BIFF8 formula tokens into readable text for XLM macro analysis."""
    pos = 0
    n = len(rgce)
    parts: List[str] = []
    while pos < n:
        ptg = rgce[pos]
        pos += 1
        if ptg == 0x17 and pos < n:  # PtgStr
            cch = rgce[pos]
            txt, pos = _decode_biff8_unicode(rgce, pos + 1, cch)
            parts.append(f'"{txt}"')
        elif ptg == 0x1E and pos + 2 <= n:  # PtgInt
            val = struct.unpack_from("<H", rgce, pos)[0]
            pos += 2
            parts.append(str(val))
        elif ptg == 0x1F and pos + 8 <= n:  # PtgNum
            val = struct.unpack_from("<d", rgce, pos)[0]
            pos += 8
            parts.append(str(val))
        elif ptg in (0x21, 0x41, 0x61) and pos + 2 <= n:  # PtgFunc
            iftab = struct.unpack_from("<H", rgce, pos)[0]
            pos += 2
            parts.append(_XLM_FUNCTIONS.get(iftab, f"FUNC_{iftab}"))
        elif ptg in (0x22, 0x42, 0x62) and pos + 3 <= n:  # PtgFuncVar
            _cparams = rgce[pos]
            iftab = struct.unpack_from("<H", rgce, pos + 1)[0] & 0x7FFF
            pos += 3
            parts.append(_XLM_FUNCTIONS.get(iftab, f"FUNCVAR_{iftab}"))
        elif ptg in (0x23, 0x43, 0x63) and pos + 4 <= n:  # PtgName
            name_idx = struct.unpack_from("<H", rgce, pos)[0]
            pos += 4
            parts.append(f"NAME_{name_idx}")
        elif ptg in (0x24, 0x44, 0x64) and pos + 4 <= n:  # PtgRef
            rw, col = struct.unpack_from("<HH", rgce, pos)
            pos += 4
            parts.append(f"R{rw + 1}C{(col & 0xFF) + 1}")
        elif ptg == 0x13:  # PtgConcat
            parts.append("&")
        else:
            # Skip fixed-size operands or advance
            continue
    return " ".join(parts)


def parse_biff_xlm(stream_name: str, data: bytes) -> List[str]:
    """Native BIFF8 parser for Excel 4.0 (XLM) macro sheets, labels, formulas, and DCONN."""
    lines: List[str] = []
    has_xlm_sheet = False
    pos = 0
    n = len(data)
    visibility_map = {0: "visible", 1: "hidden", 2: "very hidden"}
    sheet_type_map = {
        0x00: "worksheet or dialog sheet",
        0x01: "Excel 4.0 macro sheet",
        0x02: "chart",
        0x06: "Visual Basic module",
    }
    builtin_names = {
        0x00: "Consolidate_Area",
        0x01: "Auto_Open",
        0x02: "Auto_Close",
        0x03: "Extract",
        0x04: "Database",
        0x05: "Criteria",
        0x06: "Print_Area",
        0x07: "Print_Titles",
        0x08: "Recorder",
        0x09: "Data_Form",
        0x0A: "Auto_Activate",
        0x0B: "Auto_Deactivate",
        0x0C: "Sheet_Title",
    }

    while pos + 4 <= n:
        rec_id, rec_len = struct.unpack_from("<HH", data, pos)
        pos += 4
        if pos + rec_len > n:
            break
        rec = data[pos : pos + rec_len]
        pos += rec_len

        if rec_id == 0x0085 and rec_len >= 8:  # BOUNDSHEET
            hs_state = rec[4] & 0x03
            dt = rec[5]
            cch = rec[6]
            sheet_name, _ = _decode_biff8_unicode(rec, 7, cch)
            vis_str = visibility_map.get(hs_state, "unknown")
            type_str = sheet_type_map.get(dt, f"type_{dt}")
            if dt == 0x01:
                has_xlm_sheet = True
            lines.append(f"0085 BOUNDSHEET: Sheet - {vis_str}, {type_str} - {sheet_name}")

        elif rec_id == 0x0018 and rec_len >= 14:  # LBL / NAME
            grbit = struct.unpack_from("<H", rec, 0)[0]
            cch = rec[3]
            cce = struct.unpack_from("<H", rec, 4)[0]
            is_builtin = bool(grbit & 0x0020)
            if is_builtin and cch == 1 and len(rec) >= 16:
                code = rec[15]
                lbl_name = builtin_names.get(code, f"Builtin_{code}")
                end_off = 16
            else:
                lbl_name, end_off = _decode_biff8_unicode(rec, 14, cch)
            rgce = rec[end_off : end_off + cce]
            decoded_f = _decode_formula_tokens(rgce)
            lines.append(f"0018 LABEL: {lbl_name} -> {decoded_f}")

        elif rec_id == 0x0204 and rec_len >= 8:  # LABEL cell
            rw, col = struct.unpack_from("<HH", rec, 0)
            cch = struct.unpack_from("<H", rec, 6)[0]
            txt, _ = _decode_biff8_unicode(rec, 8, cch)
            lines.append(f"0204 LABEL R{rw + 1}C{col + 1}: {txt}")

        elif rec_id == 0x0207 and rec_len >= 3:  # STRING (formula string result)
            cch = struct.unpack_from("<H", rec, 0)[0]
            txt, _ = _decode_biff8_unicode(rec, 2, cch)
            if txt:
                lines.append(f"0207 STRING: {txt}")

        elif rec_id == 0x00FC and rec_len >= 8:  # SST (Shared String Table)
            cst_unique = min(struct.unpack_from("<I", rec, 4)[0], 2048)
            s_off = 8
            for _ in range(cst_unique):
                if s_off + 3 > len(rec):
                    break
                cch = struct.unpack_from("<H", rec, s_off)[0]
                txt, s_off = _decode_biff8_unicode(rec, s_off + 2, cch)
                if txt:
                    lines.append(f"00FC SST: {txt}")

        elif rec_id == 0x0006 and rec_len >= 22:  # FORMULA
            rw, col = struct.unpack_from("<HH", rec, 0)
            cce = struct.unpack_from("<H", rec, 20)[0]
            rgce = rec[22 : 22 + cce]
            decoded_f = _decode_formula_tokens(rgce)
            if decoded_f:
                lines.append(f"0006 FORMULA R{rw + 1}C{col + 1}: {decoded_f}")

        elif rec_id == 0x0876:  # DCONN (Data Connection)
            printable = re.findall(rb"[\x20-\x7e]{4,}", rec.replace(b"\x00", b""))
            decoded_strs = " ".join(s.decode("latin-1", errors="replace") for s in printable)
            lines.append(f"0876 DCONN: {decoded_strs}")

    return lines if has_xlm_sheet else []


# =====================================================================
# Native Office Encryption Detection & Decryption
# =====================================================================

def is_ole_encrypted(ole: _OleFile) -> bool:
    """Detect whether an OLE2 container is an encrypted Office document."""
    stream_names = {p[-1].lower() for p in ole.listdir()}
    if "encryptedpackage" in stream_names and "encryptioninfo" in stream_names:
        return True
    for name in ("workbook", "book"):
        if name in stream_names:
            try:
                data = ole.openstream(name).read()
                pos = 0
                while pos + 4 <= min(len(data), 4096):
                    rec_id, rec_len = struct.unpack_from("<HH", data, pos)
                    if rec_id == 0x002F:  # FILEPASS
                        return True
                    pos += 4 + rec_len
            except Exception:
                pass
    return False


def _decrypt_standard_ecma376(enc_info: bytes, enc_pkg: bytes, password: str) -> Optional[bytes]:
    """Decrypt ECMA-376 Standard Encryption (AES-128/192/256 ECB or CryptoAPI RC4)."""
    if len(enc_info) < 40 or len(enc_pkg) < 8:
        return None
    v_major, v_minor, _flags = struct.unpack_from("<HHI", enc_info, 0)
    if v_minor != 2 or v_major not in (2, 3, 4):
        return None
    hdr_size = struct.unpack_from("<I", enc_info, 8)[0]
    if 12 + hdr_size > len(enc_info):
        return None
    hdr = enc_info[12 : 12 + hdr_size]
    if len(hdr) < 32:
        return None
    _flags, _size_extra, alg_id, alg_id_hash, key_bits, _prov_type, _res1, _res2 = struct.unpack_from("<8I", hdr, 0)
    verifier_off = 12 + hdr_size
    if verifier_off + 40 > len(enc_info):
        return None
    salt_size = struct.unpack_from("<I", enc_info, verifier_off)[0]
    if salt_size != 16:
        return None
    salt = enc_info[verifier_off + 4 : verifier_off + 20]
    enc_verifier = enc_info[verifier_off + 20 : verifier_off + 36]
    verifier_hash_size = struct.unpack_from("<I", enc_info, verifier_off + 36)[0]
    enc_verifier_hash = enc_info[verifier_off + 40 : verifier_off + 40 + 32]

    pw_bytes = password.encode("utf-16-le")
    if alg_id in (0x0000660E, 0x0000660F, 0x00006610):  # AES-128, AES-192, AES-256
        h = hashlib.sha1(salt + pw_bytes).digest()
        for i in range(50000):
            h = hashlib.sha1(struct.pack("<I", i) + h).digest()
        h_final = hashlib.sha1(h + struct.pack("<I", 0)).digest()
        cb_key = key_bits // 8
        x1 = hashlib.sha1(bytes(b ^ 0x36 for b in h_final) + b"\x36" * 44).digest()
        x2 = hashlib.sha1(bytes(b ^ 0x5C for b in h_final) + b"\x5C" * 44).digest()
        key = (x1 + x2)[:cb_key]
        dec_verifier = _aes_ecb_decrypt(key, enc_verifier)
        dec_verifier_hash = _aes_ecb_decrypt(key, enc_verifier_hash)
        if hashlib.sha1(dec_verifier).digest() != dec_verifier_hash[:20]:
            return None
        orig_size = struct.unpack_from("<Q", enc_pkg, 0)[0]
        decrypted = _aes_ecb_decrypt(key, enc_pkg[8:])
        return decrypted[:orig_size]
    return None


def _decrypt_agile_ecma376(enc_info: bytes, enc_pkg: bytes, password: str) -> Optional[bytes]:
    """Decrypt ECMA-376 Agile Encryption (v4.4 XML descriptor)."""
    if len(enc_info) < 16 or len(enc_pkg) < 8:
        return None
    v_major, v_minor = struct.unpack_from("<HH", enc_info, 0)
    if v_major != 4 or v_minor != 4:
        return None
    try:
        xml_bytes = enc_info[8 : 8 + 65536]
        if b"<!DOCTYPE" in xml_bytes.upper() or b"<!ENTITY" in xml_bytes.upper():
            return None
        root = ET.fromstring(xml_bytes.decode("utf-8", errors="ignore"))
        ns = "{http://schemas.microsoft.com/office/2006/encryption}"
        p_ns = "{http://schemas.microsoft.com/office/2006/keyEncryptor/password}"
        key_data = root.find(f"{ns}keyData")
        pw_enc = root.find(f".//{p_ns}encryptedKey")
        if key_data is None or pw_enc is None:
            return None

        spin_count = int(pw_enc.attrib["spinCount"])
        if spin_count < 0 or spin_count > MAX_AGILE_SPIN_COUNT:
            return None
        pw_salt = base64.b64decode(pw_enc.attrib["saltValue"])
        hash_alg = pw_enc.attrib.get("hashAlgorithm", "SHA512").upper()
        key_bits = int(pw_enc.attrib["keyBits"])
        if key_bits not in (128, 192, 256):
            return None
        enc_verifier_input = base64.b64decode(pw_enc.attrib["encryptedVerifierHashInput"])
        enc_verifier_value = base64.b64decode(pw_enc.attrib["encryptedVerifierHashValue"])
        enc_key_value = base64.b64decode(pw_enc.attrib["encryptedKeyValue"])

        hash_fn = hashlib.sha512 if "512" in hash_alg else (hashlib.sha384 if "384" in hash_alg else hashlib.sha1)
        h = hash_fn(pw_salt + password.encode("utf-16-le")).digest()
        for i in range(spin_count):
            h = hash_fn(struct.pack("<I", i) + h).digest()

        def derive_key(block_key: bytes) -> bytes:
            dk = hash_fn(h + block_key).digest()
            cb = key_bits // 8
            if len(dk) < cb:
                dk = dk + b"\x36" * (cb - len(dk))
            return dk[:cb]

        k_ver_in = derive_key(b"\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79")
        k_ver_val = derive_key(b"\xd7\xaa\x0f\x6d\x30\x61\x34\x4e")
        k_key_val = derive_key(b"\x14\x6e\x0b\xe7\xab\xac\xd0\xd6")

        ver_in = _aes_cbc_decrypt(k_ver_in, pw_salt[:16], enc_verifier_input)
        ver_val = _aes_cbc_decrypt(k_ver_val, pw_salt[:16], enc_verifier_value)
        calc_hash = hash_fn(ver_in).digest()
        if ver_val[: len(calc_hash)] != calc_hash:
            return None

        secret_key = _aes_cbc_decrypt(k_key_val, pw_salt[:16], enc_key_value)
        kd_salt = base64.b64decode(key_data.attrib["saltValue"])
        kd_block_size = int(key_data.attrib.get("blockSize", "16"))
        kd_hash_alg = key_data.attrib.get("hashAlgorithm", "SHA512").upper()
        kd_hash_fn = hashlib.sha512 if "512" in kd_hash_alg else (hashlib.sha384 if "384" in kd_hash_alg else hashlib.sha1)

        orig_size = struct.unpack_from("<Q", enc_pkg, 0)[0]
        payload = enc_pkg[8:]
        out = bytearray()
        for seg_idx, offset in enumerate(range(0, len(payload), 4096)):
            chunk = payload[offset : offset + 4096]
            if len(chunk) % 16 != 0:
                chunk = chunk + b"\x00" * (16 - (len(chunk) % 16))
            iv = kd_hash_fn(kd_salt + struct.pack("<I", seg_idx)).digest()[:kd_block_size]
            out.extend(_aes_cbc_decrypt(secret_key, iv, chunk))
        return bytes(out[:orig_size])
    except Exception:
        return None


def decrypt_ole_document(ole: _OleFile, password: Optional[str] = None) -> Optional[bytes]:
    """Attempt to decrypt an encrypted Office OLE container using supplied and default passwords."""
    passwords: List[str] = []
    if password is not None:
        passwords.append(password)
    for pw in DEFAULT_OFFICE_PASSWORDS:
        if pw not in passwords:
            passwords.append(pw)

    stream_names = {p[-1].lower(): p for p in ole.listdir()}
    if "encryptioninfo" in stream_names and "encryptedpackage" in stream_names:
        enc_info = ole.openstream(stream_names["encryptioninfo"]).read()
        enc_pkg = ole.openstream(stream_names["encryptedpackage"]).read()
        for pw in passwords:
            res = _decrypt_standard_ecma376(enc_info, enc_pkg, pw)
            if res is not None:
                return res
            res = _decrypt_agile_ecma376(enc_info, enc_pkg, pw)
            if res is not None:
                return res
    return None


# =====================================================================
# Native RTF & OLE1.0 / OLEPackage Object Parser
# =====================================================================

KNOWN_CLSIDS: Dict[str, str] = {
    "0002CE02-0000-0000-C000-000000000046": "Equation.3 (Microsoft Equation Editor 3.0 - CVE-2017-11882 / CVE-2018-0802)",
    "0002CE03-0000-0000-C000-000000000046": "Equation.2",
    "0003000C-0000-0000-C000-000000000046": "Package (OLE Package Object)",
    "00000300-0000-0000-C000-000000000046": "StdOleLink",
    "D27CDB6E-AE6D-11CF-96B8-444553540000": "ShockwaveFlash.ShockwaveFlash",
    "F20DA720-C02F-11CE-927B-0800095AE340": "OLE Package",
}


def _format_guid(raw16: bytes) -> Optional[str]:
    if len(raw16) != 16 or raw16 == b"\x00" * 16:
        return None
    d1, d2, d3 = struct.unpack_from("<IHH", raw16, 0)
    d4 = raw16[8:10].hex().upper()
    d5 = raw16[10:16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"


class _RtfObject:
    """Represents a decoded RTF embedded object (compatible with oletools.rtfobj.RtfObject)."""

    def __init__(self, start: int, end: int, rawdata: bytes) -> None:
        self.start = start
        self.end = end
        self.rawdata = rawdata
        self.format_id: Optional[int] = None
        self.class_name: Optional[str] = None
        self.oledata: Optional[bytes] = None
        self.is_package: bool = False
        self.olepkgdata: Optional[bytes] = None
        self.filename: Optional[str] = None
        self.src_path: Optional[str] = None
        self.temp_path: Optional[str] = None
        self.clsid: Optional[str] = None
        self.clsid_desc: Optional[str] = None

        self._parse_ole10()

    @staticmethod
    def _read_cstring(buf: bytes, pos: int) -> Tuple[str, int]:
        end = buf.find(b"\x00", pos)
        if end == -1:
            return "", len(buf)
        return buf[pos:end].decode("latin-1", errors="replace"), end + 1

    @staticmethod
    def _read_len_ansi(buf: bytes, pos: int) -> Tuple[str, int]:
        if pos + 4 > len(buf):
            return "", len(buf)
        size = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        if size == 0 or size > 65536 or pos + size > len(buf):
            return "", pos
        s = buf[pos : pos + size].rstrip(b"\x00").decode("latin-1", errors="replace")
        return s, pos + size

    @staticmethod
    def _read_len_utf16(buf: bytes, pos: int) -> Tuple[str, int]:
        if pos + 4 > len(buf):
            return "", len(buf)
        chars = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        byte_len = chars * 2
        if chars == 0 or byte_len > 131072 or pos + byte_len > len(buf):
            return "", pos
        s = buf[pos : pos + byte_len].decode("utf-16-le", errors="replace").rstrip("\x00")
        return s, pos + byte_len

    def _parse_ole10(self) -> None:
        buf = self.rawdata
        if len(buf) < 12:
            return
        _ole_ver, fmt_id = struct.unpack_from("<II", buf, 0)
        if fmt_id not in (1, 2):
            # Check if rawdata starts directly with OLE2 header
            if is_ole_file(buf):
                self.oledata = buf
                self._extract_clsid(buf)
            return

        self.format_id = fmt_id
        pos = 8
        self.class_name, pos = self._read_len_ansi(buf, pos)
        _topic_name, pos = self._read_len_ansi(buf, pos)
        _item_name, pos = self._read_len_ansi(buf, pos)

        if fmt_id == 2 and pos + 4 <= len(buf):
            data_size = struct.unpack_from("<I", buf, pos)[0]
            pos += 4
            self.oledata = buf[pos : pos + data_size]
            if self.class_name and self.class_name.lower() == "package":
                self._parse_package(self.oledata)
            else:
                self._extract_clsid(self.oledata)

    def _extract_clsid(self, data: bytes) -> None:
        if is_ole_file(data):
            try:
                ole = _OleFile(data)
                if ole.dir_entries:
                    guid = _format_guid(ole.dir_entries[0].clsid_bytes)
                    if guid:
                        self.clsid = guid
                        self.clsid_desc = KNOWN_CLSIDS.get(guid, "")
            except Exception:
                pass

    def _parse_package(self, pkg: bytes) -> None:
        if len(pkg) < 10:
            return
        header = struct.unpack_from("<H", pkg, 0)[0]
        if header != 2:
            return
        pos = 2
        self.filename, pos = self._read_cstring(pkg, pos)
        self.src_path, pos = self._read_cstring(pkg, pos)
        if pos + 4 > len(pkg):
            return
        utype = struct.unpack_from("<I", pkg, pos)[0]
        pos += 4
        if utype != 3:
            return
        self.temp_path, pos = self._read_len_ansi(pkg, pos)
        if pos + 4 > len(pkg):
            return
        pkg_size = struct.unpack_from("<I", pkg, pos)[0]
        pos += 4
        if pkg_size > len(pkg) - pos:
            pkg_size = len(pkg) - pos
        self.olepkgdata = pkg[pos : pos + pkg_size]
        pos += pkg_size
        self.is_package = True
        self.clsid = "0003000C-0000-0000-C000-000000000046"
        self.clsid_desc = KNOWN_CLSIDS[self.clsid]

        # Optional trailing UTF-16LE paths
        if pos + 12 <= len(pkg):
            u_temp, pos = self._read_len_utf16(pkg, pos)
            u_file, pos = self._read_len_utf16(pkg, pos)
            u_src, pos = self._read_len_utf16(pkg, pos)
            if u_temp:
                self.temp_path = u_temp
            if u_file:
                self.filename = u_file
            if u_src:
                self.src_path = u_src


class _RtfObjParser:
    """Native RTF parser that locates \\objdata hex streams and constructs _RtfObject instances."""

    _RE_OBJDATA = re.compile(rb"\\objdata\b", re.IGNORECASE)

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.objects: List[_RtfObject] = []

    def parse(self) -> None:
        data = self.data
        n = len(data)
        for m in self._RE_OBJDATA.finditer(data):
            start = m.end()
            pos = start
            # Skip optional single space after control word
            if pos < n and data[pos] == 0x20:
                pos += 1
            hex_chars = bytearray()
            depth = 0
            while pos < n:
                ch = data[pos]
                if ch == 0x7B:  # '{'
                    depth += 1
                    pos += 1
                elif ch == 0x7D:  # '}'
                    if depth == 0:
                        break
                    depth -= 1
                    pos += 1
                elif ch == 0x5C:  # '\\' control word inside hex data (RTF obfuscation)
                    pos += 1
                    if pos < n and data[pos] in b"\\{}*~_-:":
                        pos += 1
                    elif pos + 2 <= n and data[pos : pos + 2] == b"bin":
                        # Skip \binN control word
                        pos += 2
                        while pos < n and (0x30 <= data[pos] <= 0x39 or data[pos] == 0x2D):
                            pos += 1
                        if pos < n and data[pos] == 0x20:
                            pos += 1
                    else:
                        while pos < n and ((0x41 <= data[pos] <= 0x5A) or (0x61 <= data[pos] <= 0x7A)):
                            pos += 1
                        while pos < n and (0x30 <= data[pos] <= 0x39 or data[pos] == 0x2D):
                            pos += 1
                        if pos < n and data[pos] == 0x20:
                            pos += 1
                elif (
                    (0x30 <= ch <= 0x39)
                    or (0x41 <= ch <= 0x46)
                    or (0x61 <= ch <= 0x66)
                ):
                    hex_chars.append(ch)
                    pos += 1
                else:
                    pos += 1

            if len(hex_chars) >= 16:
                if len(hex_chars) % 2 == 1:
                    hex_chars.pop()
                try:
                    raw = binascii.unhexlify(hex_chars)
                    self.objects.append(_RtfObject(start, pos, raw))
                except Exception:
                    pass


# =====================================================================
# Native PDF Stream Decoder & Object Parser
# =====================================================================

def _unescape_pdf_name(name: bytes) -> str:
    """Resolve #xx hex escapes inside PDF name tokens (e.g., /Fl#61teDecode -> FlateDecode)."""
    resolved = RE_PDF_NAME_HEX.sub(lambda m: bytes([int(m.group(1), 16)]), name)
    return resolved.decode("latin-1", errors="replace")


def _pdf_ascii_hex_decode(data: bytes) -> bytes:
    end = data.find(b">")
    if end != -1:
        data = data[:end]
    cleaned = re.sub(rb"[^0-9a-fA-F]", b"", data)
    if len(cleaned) % 2 == 1:
        cleaned += b"0"
    return binascii.unhexlify(cleaned)


def _pdf_ascii85_decode(data: bytes) -> bytes:
    data = data.strip()
    if data.startswith(b"<~"):
        data = data[2:]
    end = data.find(b"~>")
    if end != -1:
        data = data[:end]
    try:
        return base64.a85decode(data, adobe=False, ignorechars=b" \t\r\n\x00\x0c")
    except Exception:
        # Manual resilient ASCII85 decode for truncated streams
        out = bytearray()
        group: List[int] = []
        for b in data:
            if b in b" \t\r\n\x00\x0c":
                continue
            if b == 0x7A and not group:  # 'z' -> 4 zero bytes
                out.extend(b"\x00\x00\x00\x00")
            elif 33 <= b <= 117:
                group.append(b - 33)
                if len(group) == 5:
                    val = 0
                    for g in group:
                        val = val * 85 + g
                    out.extend(struct.pack(">I", val & 0xFFFFFFFF))
                    group.clear()
        if len(group) >= 2:
            rem = len(group) - 1
            while len(group) < 5:
                group.append(84)
            val = 0
            for g in group:
                val = val * 85 + g
            out.extend(struct.pack(">I", val & 0xFFFFFFFF)[:rem])
        return bytes(out)


def _pdf_run_length_decode(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n and len(out) < MAX_DECOMPRESSED_STREAM_SIZE:
        length = data[pos]
        pos += 1
        if length == 128:
            break
        elif length < 128:
            count = length + 1
            out.extend(data[pos : pos + count])
            pos += count
        else:
            count = 257 - length
            if pos < n:
                out.extend(bytes([data[pos]]) * count)
                pos += 1
    return bytes(out[:MAX_DECOMPRESSED_STREAM_SIZE])


def _pdf_lzw_decode(data: bytes, early_change: int = 1) -> bytes:
    """Pure-Python PDF LZW stream decoder (MSB-first variable bit width 9..12)."""
    table: Dict[int, bytes] = {i: bytes([i]) for i in range(256)}
    next_code = 258
    code_size = 9
    bit_buf = 0
    bit_count = 0
    pos = 0
    n = len(data)
    out = bytearray()
    prev_entry: Optional[bytes] = None

    def get_next_code() -> Optional[int]:
        nonlocal bit_buf, bit_count, pos
        while bit_count < code_size and pos < n:
            bit_buf = (bit_buf << 8) | data[pos]
            bit_count += 8
            pos += 1
        if bit_count < code_size:
            return None
        shift = bit_count - code_size
        code = (bit_buf >> shift) & ((1 << code_size) - 1)
        bit_count -= code_size
        bit_buf &= (1 << bit_count) - 1
        return code

    while len(out) < MAX_DECOMPRESSED_STREAM_SIZE:
        code = get_next_code()
        if code is None or code == 257:  # EOD
            break
        if code == 256:  # Clear table
            table = {i: bytes([i]) for i in range(256)}
            next_code = 258
            code_size = 9
            prev_entry = None
            continue
        if code in table:
            entry = table[code]
        elif code == next_code and prev_entry is not None:
            entry = prev_entry + prev_entry[:1]
        else:
            break
        out.extend(entry)
        if prev_entry is not None and next_code < 4096:
            table[next_code] = prev_entry + entry[:1]
            next_code += 1
            limit = (1 << code_size) - early_change
            if next_code >= limit and code_size < 12:
                code_size += 1
        prev_entry = entry

    return bytes(out[:MAX_DECOMPRESSED_STREAM_SIZE])


def _pdf_apply_png_predictor(data: bytes, predictor: int, columns: int) -> bytes:
    """Undo PNG row predictors (10..15) commonly used in PDF /FlateDecode XRef & ObjStm streams."""
    if predictor < 10 or columns <= 0 or columns > MAX_PDF_PREDICTOR_COLUMNS:
        return data
    row_len = columns + 1
    if len(data) < row_len:
        return data
    out = bytearray()
    prev_row = bytearray(columns)
    for offset in range(0, len(data) - (len(data) % row_len), row_len):
        filter_type = data[offset]
        row = bytearray(data[offset + 1 : offset + row_len])
        if filter_type == 1:  # Sub
            for i in range(1, columns):
                row[i] = (row[i] + row[i - 1]) & 0xFF
        elif filter_type == 2:  # Up
            for i in range(columns):
                row[i] = (row[i] + prev_row[i]) & 0xFF
        elif filter_type == 3:  # Average
            for i in range(columns):
                left = row[i - 1] if i > 0 else 0
                row[i] = (row[i] + ((left + prev_row[i]) >> 1)) & 0xFF
        elif filter_type == 4:  # Paeth
            for i in range(columns):
                a = row[i - 1] if i > 0 else 0
                b = prev_row[i]
                c = prev_row[i - 1] if i > 0 else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                row[i] = (row[i] + pr) & 0xFF
        out.extend(row)
        prev_row = row
    return bytes(out)


def _pdf_flate_decode(data: bytes) -> bytes:
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        for trim in (data, data.lstrip(b"\r\n ")):
            try:
                dobj = zlib.decompressobj(wbits)
                dec = dobj.decompress(trim, MAX_DECOMPRESSED_STREAM_SIZE)
                dec += dobj.flush( max(0, MAX_DECOMPRESSED_STREAM_SIZE - len(dec)) )
                if dec:
                    return dec
            except Exception:
                pass
    return data


def decode_pdf_stream(dict_bytes: bytes, raw_stream: bytes) -> Optional[bytes]:
    """Decode a PDF stream according to its dictionary /Filter and /DecodeParms."""
    filters: List[str] = []
    m_arr = RE_PDF_FILTER_ARRAY.search(dict_bytes)
    if m_arr:
        filters = [_unescape_pdf_name(tok) for tok in RE_PDF_NAME_TOKEN.findall(m_arr.group(1))]
    else:
        m_single = RE_PDF_FILTER_SINGLE.search(dict_bytes)
        if m_single:
            filters = [_unescape_pdf_name(m_single.group(1))]

    if not filters:
        return None

    predictor = 1
    columns = 1
    early_change = 1
    m_pred = RE_PDF_PREDICTOR.search(dict_bytes)
    if m_pred:
        predictor = int(m_pred.group(1))
    m_cols = RE_PDF_COLUMNS.search(dict_bytes)
    if m_cols:
        columns = int(m_cols.group(1))
    m_ec = RE_PDF_EARLYCHANGE.search(dict_bytes)
    if m_ec:
        early_change = int(m_ec.group(1))

    curr = raw_stream
    for f in filters:
        fl = f.lower()
        if fl in ("flatedecode", "fl"):
            curr = _pdf_flate_decode(curr)
            if predictor >= 10:
                curr = _pdf_apply_png_predictor(curr, predictor, columns)
        elif fl in ("asciihexdecode", "ahx"):
            curr = _pdf_ascii_hex_decode(curr)
        elif fl in ("ascii85decode", "a85"):
            curr = _pdf_ascii85_decode(curr)
        elif fl in ("lzwdecode", "lzw"):
            curr = _pdf_lzw_decode(curr, early_change=early_change)
            if predictor >= 10:
                curr = _pdf_apply_png_predictor(curr, predictor, columns)
        elif fl in ("runlengthdecode", "rl"):
            curr = _pdf_run_length_decode(curr)

    return curr


def _resolve_default_yara_path(filename: str) -> str:
    """Resolve bundled YARA rule paths across standard installs and frozen Windows executables."""
    candidates: List[Path] = []
    if getattr(sys, "frozen", False):
        # 1. Allow overriding rules by placing .yara files alongside quicksand.exe
        exe_dir = Path(sys.executable).resolve().parent
        candidates.append(exe_dir / filename)
        candidates.append(exe_dir / "quicksand" / filename)
        # 2. PyInstaller _MEIPASS temp extraction directory
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            meipass_dir = Path(meipass)
            candidates.append(meipass_dir / "quicksand" / filename)
            candidates.append(meipass_dir / filename)

    try:
        module_dir = Path(__file__).resolve().parent
        candidates.append(module_dir / filename)
    except Exception:
        pass

    candidates.append(Path.cwd() / filename)

    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue

    return str(candidates[0]) if candidates else filename


# =====================================================================
# Main QuickSand Class
# =====================================================================

class quicksand:
    """Analyze documents and PDFs for exploits, active content, and embedded executables.

    Attributes:
        results (Dict[str, Any]): Dictionary populated during analysis containing
            file hashes, detected format, risk rating, score, structural hashes,
            per-stream YARA rule matches, and (when ``capture=True``) extracted
            stream bytes.
        structure (str): Comma-delimited representation of the document's nested
            container and stream hierarchy.
        capture (bool): Whether extracted binary streams are stored in
            ``results["streams"]``.
        strings (bool): Whether matched YARA string offsets and previews are
            included in rule hit entries.
        debug (bool): Whether timestamped debug messages are printed to stdout.
        timeout (int): Maximum analysis duration in seconds (``0`` for unlimited).
        password (Optional[str]): Optional password for decrypting protected
            Office documents.

    Example:
        >>> from quicksand import quicksand
        >>> qs = quicksand("suspicious.doc", capture=True, strings=True)
        >>> qs.process()
        >>> print(qs.results["risk"], qs.results["score"])
    """

    __version__ = "2.2.0"
    __author__ = "tylabs.com"
    __copyright__ = "Copyright 2026, @tylabs"
    __license__ = "MIT"

    _yara_cache: Dict[Tuple[str, float], Any] = {}

    exploityara = _resolve_default_yara_path("quicksand_exploits.yara")
    execyara = _resolve_default_yara_path("quicksand_exe.yara")
    pdfyara = _resolve_default_yara_path("quicksand_pdf.yara")

    @classmethod
    def _compile_yara_cached(cls, filepath: str) -> Any:
        """Compile a YARA rule file with in-memory caching keyed by ``(filepath, mtime)``.

        Args:
            filepath: Path to the ``.yara`` source file on disk.

        Returns:
            Compiled ``yara.Rules`` object.
        """
        try:
            mtime = os.path.getmtime(filepath)
        except OSError:
            mtime = 0.0
        cache_key = (filepath, mtime)
        compiled = cls._yara_cache.get(cache_key)
        if compiled is None:
            compiled = yara.compile(filepath=filepath)
            cls._yara_cache[cache_key] = compiled
        return compiled

    def msg(self, message: Any) -> None:
        """Print a timestamped debug message to stdout when ``debug=True``.

        Args:
            message: Diagnostic message or object to log.
        """
        if self.debug:
            print(f"{time.time()}: {message}")

    def readFile(self, filename: Union[str, Path]) -> bytes:
        """Read a file from disk and return its raw bytes.

        Args:
            filename: Filesystem path to read.

        Returns:
            Raw file contents as ``bytes``, or ``b""`` if the file cannot be read.
        """
        try:
            with open(filename, "rb") as f:
                return f.read()
        except Exception:
            self.msg("ERROR: file not found")
            return b""

    @staticmethod
    def readDir(
        directory: Union[str, Path],
        capture: bool = False,
        strings: bool = True,
        debug: bool = False,
        timeout: int = 0,
        exploityara: Optional[str] = None,
        execyara: Optional[str] = None,
        pdfyara: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Analyze all regular files in a directory (non-recursive).

        Args:
            directory: Path to the directory containing documents to scan.
            capture: If ``True``, store extracted streams in ``results["streams"]``.
            strings: If ``True``, include matched YARA string offsets and previews.
            debug: If ``True``, print diagnostic trace output to stdout.
            timeout: Per-file processing timeout in seconds (``0`` for unlimited).
            exploityara: Optional path to a custom exploit YARA rules file.
            execyara: Optional path to a custom executable YARA rules file.
            pdfyara: Optional path to a custom PDF YARA rules file.
            password: Optional password for decrypting protected Office documents.

        Returns:
            Dictionary mapping each file's path string to its ``qs.results`` dictionary.
        """
        out: Dict[str, Dict[str, Any]] = {}
        try:
            dir_path = Path(directory)
            for file_path in sorted(dir_path.iterdir()):
                if file_path.is_file():
                    q = quicksand(
                        str(file_path),
                        capture=capture,
                        strings=strings,
                        debug=debug,
                        timeout=timeout,
                        exploityara=exploityara,
                        execyara=execyara,
                        pdfyara=pdfyara,
                        password=password,
                    )
                    q.process()
                    out[str(file_path)] = q.results
        except Exception as e:
            print(f"Error processing directory {directory}: {e}")
        return out

    def mapStructure(self, parent: Any, loc: Any) -> None:
        """Legacy hook retained for backwards compatibility."""
        return None

    def __init__(
        self,
        data: Union[str, Path, bytes],
        capture: bool = False,
        strings: bool = True,
        debug: bool = False,
        timeout: int = 0,
        exploityara: Optional[str] = None,
        execyara: Optional[str] = None,
        pdfyara: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """Initialize a QuickSand document analyzer instance.

        Args:
            data: File path (``str`` or ``Path``) or raw document ``bytes`` to analyze.
            capture: If ``True``, store decoded stream bytes in ``results["streams"]``.
            strings: If ``True``, record matched YARA string offsets and previews.
            debug: If ``True``, print verbose debug messages during analysis.
            timeout: Maximum time in seconds allowed for ``process()`` (``0`` = no limit).
            exploityara: Optional override path for ``quicksand_exploits.yara``.
            execyara: Optional override path for ``quicksand_exe.yara``.
            pdfyara: Optional override path for ``quicksand_pdf.yara``.
            password: Optional password to try when decrypting encrypted Office files.
        """
        self.results: Dict[str, Any] = {"results": {}}
        self.structure = ""
        self.capture = capture
        self.strings = strings
        self.debug = debug
        self.password = password
        self.results["score"] = 0
        self.results["warning"] = 0
        self.results["exploit"] = 0
        self.results["execute"] = 0
        self.results["feature"] = 0
        self.results["packages"] = []
        self.timeout = timeout
        self._matched_rules: Set[str] = set()
        self._depth: int = 0

        if self.capture:
            self.results["streams"] = {}

        if isinstance(data, (str, Path)) and Path(data).is_file():
            self.results["filename"] = str(data)
            self.data = self.readFile(data)
        elif isinstance(data, bytes):
            self.results["filename"] = None
            self.data = data
        else:
            self.results["filename"] = str(data) if isinstance(data, (str, Path)) else None
            self.data = data.encode("utf-8", errors="replace") if isinstance(data, str) else b""

        if exploityara is not None:
            self.exploityara = exploityara
        if execyara is not None:
            self.execyara = execyara
        if pdfyara is not None:
            self.pdfyara = pdfyara

        self.exploitrules = self._compile_yara_cached(self.exploityara)
        self.execrules = self._compile_yara_cached(self.execyara)
        self.pdfrules = self._compile_yara_cached(self.pdfyara)

    def _is_timed_out(self) -> bool:
        """Check whether processing has exceeded the configured ``self.timeout``.

        Returns:
            ``True`` if a non-zero timeout is configured and has elapsed, else ``False``.
        """
        if self.timeout > 0 and "started" in self.results:
            if time.time() - self.results["started"] > self.timeout:
                self.results["skip"] = 1
                return True
        return False

    def format_yara_strings(self, match_strings: List) -> str:
        """Format YARA ``StringMatch`` objects or legacy ``(offset, identifier, data)`` tuples.

        Args:
            match_strings: List of ``yara.StringMatch`` objects (YARA >= 4.3) or tuples.

        Returns:
            Newline-separated human-readable string of matched identifiers, offsets, and data.
        """
        if not match_strings:
            return ""

        result: List[str] = []
        for match in match_strings:
            if hasattr(match, "identifier") and hasattr(match, "instances"):
                identifier = match.identifier
                for instance in match.instances:
                    if hasattr(instance, "matched_data") and hasattr(instance, "offset"):
                        offset = instance.offset
                        data = instance.matched_data
                        try:
                            string_data = data.decode("utf-8", errors="replace")
                        except (UnicodeDecodeError, AttributeError):
                            string_data = data.hex() if data else "[empty]"
                        result.append(f"{identifier} at offset {offset}: {string_data}")
            elif isinstance(match, tuple) and len(match) >= 3:
                identifier, offset, data = match[:3]
                try:
                    string_data = data.decode("utf-8", errors="replace")
                except (UnicodeDecodeError, AttributeError):
                    string_data = data.hex() if data else "[empty]"
                result.append(f"{identifier} at offset {offset}: {string_data}")
            else:
                try:
                    result.append(f"Match data: {str(match)}")
                except Exception:
                    result.append("Unprocessable match data")

        return "\n".join(result)

    @staticmethod
    def carve(item: bytes, separator: bytes) -> List[bytes]:
        """Carve sub-streams out of ``item`` at each occurrence of ``separator``.

        Args:
            item: Binary buffer to search.
            separator: Magic header byte sequence to split on.

        Returns:
            List of carved byte slices (each prefixed with ``separator``), capped at
            ``MAX_CARVED_ELEMENTS``.
        """
        parts = item.split(separator, MAX_CARVED_ELEMENTS + 1)
        return [separator + e for e in parts[: MAX_CARVED_ELEMENTS + 1] if e]

    def _scan_rules(self, rules: Any, item: bytes, loc: str, rule_type: str) -> None:
        """Scan binary data with a compiled YARA ruleset and record deduplicated findings.

        Args:
            rules: Compiled ``yara.Rules`` instance.
            item: Binary stream content to scan.
            loc: Stream location label (e.g., ``"root-pdf_4_0"``).
            rule_type: Rule category label (``"exploit"``, ``"execute"``, or ``"pdf"``).
        """
        if not item:
            return
        loc_str = str(loc)
        matches = rules.match(data=item)
        if not matches:
            return

        for match in matches:
            meta = getattr(match, "meta", {}) or {}
            desc = meta.get("desc", "")
            mitre = meta.get("mitre", "")
            rank = meta.get("rank")

            # Deduplicate score and category counters per unique rule across parent/child streams
            if match.rule not in self._matched_rules:
                self._matched_rules.add(match.rule)
                if meta.get("is_exe") is True:
                    self.results["execute"] += 1
                if meta.get("is_exploit") is True:
                    self.results["exploit"] += 1
                if meta.get("is_warning") is True:
                    self.results["warning"] += 1
                if meta.get("is_feature") is True:
                    self.results["feature"] += 1

                if rank is not None:
                    try:
                        self.results["score"] += int(rank)
                    except (ValueError, TypeError):
                        pass

            if self.strings:
                if isinstance(match.strings, list):
                    formatted_strings = self.format_yara_strings(match.strings)
                else:
                    formatted_strings = str(match.strings)
                entry = {
                    "rule": match.rule,
                    "desc": desc,
                    "strings": formatted_strings,
                    "type": rule_type,
                    "mitre": mitre,
                }
            else:
                entry = {
                    "rule": match.rule,
                    "desc": desc,
                    "type": rule_type,
                    "mitre": mitre,
                }

            self.results["results"].setdefault(loc_str, []).append(entry)
            if rule_type == "exploit":
                self.msg(f"YARA EXPLOIT: {loc_str}:{match.rule}")

    def scan_exploit(self, item: bytes, loc: str) -> None:
        """Scan ``item`` against the document exploit YARA ruleset.

        Args:
            item: Binary buffer to scan.
            loc: Stream location identifier.
        """
        self._scan_rules(self.exploitrules, item, loc, "exploit")

    def scan_exec(self, item: bytes, loc: str) -> None:
        """Scan ``item`` against the executable YARA ruleset.

        Args:
            item: Binary buffer to scan.
            loc: Stream location identifier.
        """
        self._scan_rules(self.execrules, item, loc, "execute")

    def scan_pdf(self, item: bytes, loc: str) -> None:
        """Scan ``item`` against the PDF exploit YARA ruleset.

        Args:
            item: Binary buffer to scan.
            loc: Stream location identifier.
        """
        self._scan_rules(self.pdfrules, item, loc, "pdf")

    def analyse_pdf(self, doc: bytes, loc: str) -> None:
        """Analyze a PDF document and decode all compressed/filtered object streams natively.

        Args:
            doc: Raw PDF bytes.
            loc: Stream location identifier.
        """
        try:
            self.scan_pdf(doc, str(loc))

            for block in RE_PDF_STRUCTURE.findall(doc):
                if len(block[2]) != 0:
                    try:
                        num = int(block[2])
                        gen = int(block[3])
                        self.msg(f"obj {num} {gen}")
                        self.structure += f"{num}-{gen},"
                    except ValueError:
                        self.msg(f"Error parsing numeric token in PDF object: {block[2]}")
                else:
                    token = block[5].decode("utf-8", errors="replace")
                    self.structure += token + ","
                    self.msg(f"obj {token}")

            for m in RE_PDF_OBJ_STREAM.finditer(doc):
                if self._is_timed_out():
                    break
                try:
                    num = int(m.group(1))
                    gen = int(m.group(2))
                except ValueError:
                    continue

                dict_bytes = m.group(3)
                raw_stream = m.group(4)
                self.msg(f"stream {num} {gen}")

                decoded = decode_pdf_stream(dict_bytes, raw_stream)
                if decoded is not None:
                    pdf_object_loc = f"{loc}-pdf_{num}_{gen}"
                    self.scan_pdf(decoded, pdf_object_loc)
                    if self.capture:
                        self.results["streams"][pdf_object_loc] = decoded

                    # If this is a PDF 1.5+ /ObjStm compressed object stream, scan inner objects
                    if b"/ObjStm" in dict_bytes:
                        m_first = RE_PDF_OBJSTM_FIRST.search(dict_bytes)
                        if m_first:
                            first_off = int(m_first.group(1))
                            if 0 < first_off < len(decoded):
                                inner_body = decoded[first_off:]
                                self.scan_pdf(inner_body, f"{pdf_object_loc}_objstm")
                elif raw_stream:
                    # Unfiltered stream
                    pdf_object_loc = f"{loc}-pdf_{num}_{gen}"
                    self.scan_pdf(raw_stream, pdf_object_loc)
                    if self.capture:
                        self.results["streams"][pdf_object_loc] = raw_stream

        except Exception as e:
            _, _, exc_traceback = sys.exc_info()
            line_number = exc_traceback.tb_lineno if exc_traceback else 0
            self.msg(f"Error parsing PDF on line {line_number} due to {e}")
            self.results["results"].setdefault(str(loc), []).append(
                {
                    "rule": "pdf_malformed",
                    "desc": f"WARNING: PDF is malformed. Error parsing PDF on line {line_number} due to {e}",
                    "strings": "",
                    "type": "structure",
                }
            )

    analyze_pdf = analyse_pdf

    def analyse_openxml(self, doc: bytes, loc: str) -> Union[str, Exception]:
        """Extract and analyze streams inside an OpenXML / ZIP archive."""
        try:
            filebytes = BytesIO(doc)
            with zipfile.ZipFile(filebytes, allowZip64=True) as myzipfile:
                for name in myzipfile.namelist()[:MAX_ARCHIVE_ENTRIES]:
                    if self._is_timed_out():
                        break
                    with myzipfile.open(name) as zf:
                        subdata = zf.read(MAX_DECOMPRESSED_STREAM_SIZE)
                    if len(subdata) > 10:
                        stream_loc = f"{loc}-{name}"
                        self.analyze(subdata, stream_loc)
                        if self.capture:
                            self.results["streams"][stream_loc] = subdata
        except Exception as e:
            return e
        return "ok"

    analyze_openxml = analyse_openxml

    def rtf_block(self, block: bytes, loc: str) -> None:
        """Decode an RTF hex block and scan/carve embedded OLE or OpenXML objects."""
        try:
            cleaned = RE_RTF_WHITESPACE.sub(b"", block)
            if len(cleaned) % 2 == 1:
                cleaned = cleaned[:-1]
            obj = bytes.fromhex(cleaned.decode("ascii"))
        except Exception:
            obj = block

        self.msg(f"RTF obj size {len(obj)}")
        if self.capture:
            self.results["streams"][loc] = obj

        self.scan_exploit(obj, str(loc))
        self.scan_exec(obj, str(loc))

        # Carve embedded OLE2 documents
        if OLE_MAGIC_SHORT in obj:
            self.msg(f"{loc} has embedded ole doc")
            elements = self.carve(obj, OLE_MAGIC_SHORT)
            if elements:
                elements.pop(0)
            self.msg(f"There may be this many ole: {len(elements)}")

            directory = 0
            for i, elem in enumerate(elements):
                newloc = f"ole{i}"
                self.structure += f"{newloc},"

                r = self.analyse_ole(elem, f"{loc}-{newloc}")
                if self.capture:
                    self.results["streams"][f"{loc}{newloc}"] = elem

                if "negative" in str(r) and len(elements) > 1:
                    self.msg(f"range {directory} {i}")
                    joined = b"".join(elements[directory : i + 1])
                    r = self.analyse_ole(joined, f"{loc}-oleg{directory}-{i}")
                    if self.capture:
                        self.results["streams"][f"{loc}-oler{directory}-{i}"] = joined
                    directory = i + 1
                elif self.capture:
                    self.results["streams"][f"{loc}-olea-{i}"] = elem

        # Carve embedded OpenXML ZIP archives
        if OPENXML_MAGIC in obj:
            self.msg("has embedded openxml doc")
            elements = self.carve(obj, OPENXML_MAGIC)
            if elements:
                elements.pop(0)

            directory = 0
            for i, elem in enumerate(elements):
                self.msg(elem[:64])
                self.msg(" -element 1 ")
                newloc = f"openxml{i}"
                self.structure += f"{newloc},"
                r = self.analyse_openxml(elem, f"{loc}-{newloc}")
                if self.capture:
                    self.results["streams"][f"{loc}{newloc}"] = elem

                if "negative" in str(r) and len(elements) > 1:
                    self.msg(f"range {directory} {i}")
                    joined = b"".join(elements[directory : i + 1])
                    r = self.analyse_openxml(joined, f"{loc}-openxmlg{directory}-{i}")
                    if self.capture:
                        self.results["streams"][f"{loc}-openxmlr{directory}-{i}"] = joined
                    directory = i + 1
                elif self.capture:
                    self.results["streams"][f"{loc}-openxmla{i}"] = elem

    def analyse_rtf(self, doc: bytes, loc: str) -> None:
        """Analyze RTF document and extract embedded OLE1.0, OLEPackage, ODS, and datastore streams."""
        self.msg(doc[:100])
        self.scan_exploit(doc, str(loc))

        doc = RE_RTF_BRACE_FIX.sub(rb"}\1", doc)
        doc = RE_RTF_ODS_FIX.sub(rb"{ods \1", doc)
        self.msg(doc[:100])

        try:
            for ds, block in enumerate(RE_RTF_ODS_BLOCK.findall(doc)):
                self.msg(f"RTF ODS size {len(block)}")
                self.structure += f"rtfods@{ds},"
                self.rtf_block(block, f"{loc}-rtfods@{ds}")

            for ds, block in enumerate(RE_RTF_DATASTORE_BLOCK.findall(doc)):
                self.msg(f"RTF datastore size {len(block)}")
                self.structure += f"rtfdatastore@{ds},"
                self.rtf_block(block, f"{loc}-rtfdatastore@{ds}")

            rt = _RtfObjParser(doc)
            rt.parse()
            for obj in rt.objects:
                if self._is_timed_out():
                    break
                orig_len = obj.end - obj.start
                self.msg(f"RTF object size {orig_len}")
                self.msg(obj.rawdata[:100].hex())
                self.structure += "hexobj,"

                if obj.is_package:
                    self.msg("CLASS PACKAGE")
                    self.msg(obj.filename)
                    self.structure += str(obj.filename).replace(",", "") + ","
                    self.results["packages"].append(
                        {
                            "loc": obj.start,
                            "filename": obj.filename,
                            "src_path": obj.src_path,
                            "temp_path": obj.temp_path,
                        }
                    )

                if obj.clsid is not None:
                    self.msg(obj.clsid)
                    self.msg(obj.clsid_desc)
                    self.scan_exploit(obj.rawdata, f"{loc}-rtfcls@{obj.start}_{obj.clsid}")

                if obj.olepkgdata is not None:
                    self.msg("PACKAGE DATA")
                    self.structure += f"rtfpkg@{obj.start},"
                    pkg_loc = f"{loc}-rtfpkg@{obj.start}"
                    self.scan_exploit(obj.olepkgdata, pkg_loc)
                    self.scan_exec(obj.olepkgdata, pkg_loc)
                    if self.capture:
                        self.results["streams"][pkg_loc] = obj.olepkgdata
                elif obj.oledata is not None:
                    self.msg("RTFOLE DATA")
                    self.structure += f"rtfobjole@{obj.start},"
                    ole_loc = f"{loc}-rtfobjole@{obj.start}"
                    self.analyze(obj.oledata, ole_loc)
                    if self.capture:
                        self.results["streams"][ole_loc] = obj.oledata
                else:
                    self.rtf_block(obj.rawdata, f"{loc}-rtfobj@{obj.start}")

        except Exception as e:
            self.msg(e)
            self.msg(traceback.format_exc())

    analyze_rtf = analyse_rtf

    @staticmethod
    def explode_gfinflate(item: bytes) -> bytes:
        """Attempt raw deflate decompression across offsets 0..53 (bounded against decompression bombs)."""
        for i in range(0, min(54, len(item))):
            try:
                dobj = zlib.decompressobj(-zlib.MAX_WBITS)
                dec = dobj.decompress(item[i:], MAX_DECOMPRESSED_STREAM_SIZE)
                dec += dobj.flush(max(0, MAX_DECOMPRESSED_STREAM_SIZE - len(dec)))
                if dec and not dobj.unconsumed_tail:
                    return dec
            except Exception:
                pass
        return b""

    @staticmethod
    def explode_gzuncompress(item: bytes) -> bytes:
        """Attempt zlib decompression across offsets 0..53 (e.g. ActiveMime, bounded against decompression bombs)."""
        for i in range(0, min(54, len(item))):
            try:
                dobj = zlib.decompressobj()
                dec = dobj.decompress(item[i:], MAX_DECOMPRESSED_STREAM_SIZE)
                dec += dobj.flush(max(0, MAX_DECOMPRESSED_STREAM_SIZE - len(dec)))
                if dec:
                    return dec
            except Exception:
                pass
        return b""

    def analyse_mso(self, doc: bytes, loc: str) -> None:
        """Analyze MSO / XML / MIME documents and decode embedded Base64 & ActiveMime streams."""
        self.scan_exploit(doc, str(loc))
        self.scan_exec(doc, str(loc))

        for raw_block in RE_MSO_BASE64.findall(doc):
            if self._is_timed_out():
                break
            # If the regex captured across a MIME header blank line (\r\n\r\n or \n\n), take the body after the blank line
            block = re.split(rb"(?:\r\n\r\n|\n\n)", raw_block)[-1].strip()
            if len(block) < 64:
                continue

            is_mso_prefix = block[:3] == b"mso"
            b64_payload = block[3:].strip() if is_mso_prefix else block
            try:
                decoded = base64.decodebytes(b64_payload)
            except Exception:
                try:
                    cleaned = re.sub(rb"[^A-Za-z0-9+/=]", b"", b64_payload)
                    pad = (-len(cleaned)) % 4
                    if pad:
                        cleaned += b"=" * pad
                    decoded = base64.b64decode(cleaned)
                except Exception:
                    continue

            am_idx = decoded.find(b"ActiveMime", 0, 64)
            if am_idx != -1:
                dc = self.explode_gzuncompress(decoded[am_idx + 10 :])
                suffix = "-mso-activemime" if is_mso_prefix else "-b64-activemime"
                stream_loc = f"{loc}{suffix}"
                self.analyze(dc, stream_loc)
                if self.capture:
                    self.results["streams"][stream_loc] = dc
            else:
                suffix = "-mso" if is_mso_prefix else "-b64"
                stream_loc = f"{loc}{suffix}"
                self.analyze(decoded, stream_loc)
                if self.capture:
                    self.results["streams"][stream_loc] = decoded

    analyze_mso = analyse_mso

    def analyse_ps(self, doc: bytes, loc: str) -> None:
        """Analyze PostScript documents and decode hex-encoded payloads."""
        self.scan_exploit(doc, str(loc))
        self.scan_exec(doc, str(loc))

        candidates = RE_PS_HEX_STRING.findall(doc) + RE_PS_HEX_BLOCK.findall(doc)
        i = 0
        for block in candidates:
            if self._is_timed_out():
                break
            cleaned = re.sub(rb"[^0-9a-fA-F]", b"", block)
            if len(cleaned) < 32:
                continue
            if len(cleaned) % 2 == 1:
                cleaned = cleaned[:-1]
            try:
                obj = bytes.fromhex(cleaned.decode("ascii"))
            except ValueError:
                continue
            self.scan_exploit(obj, str(loc))
            self.scan_exec(obj, str(loc))
            stream_loc = f"{loc}-pshex{i}"
            self.analyze(obj, stream_loc)
            if self.capture:
                self.results["streams"][stream_loc] = obj
            i += 1

    analyze_ps = analyse_ps

    def dobiff(self, excel_stream: str, data: bytes) -> List[str]:
        """Scan an Excel BIFF8 Workbook/Book stream for Excel 4.0 (XLM) macros."""
        try:
            xlm_macros = parse_biff_xlm(excel_stream, data)
            if xlm_macros:
                self.msg("Found XLM macros")
            return xlm_macros
        except Exception as e:
            self.msg(f"Error parsing BIFF stream {excel_stream}: {e}")
            return []

    def analyse_ole(self, doc: bytes, loc: str) -> Optional[Union[str, Exception]]:
        """Analyze an OLE2 Compound File, extract metadata, decrypt if protected, and scan streams."""
        self.scan_exploit(doc, str(loc))
        self.scan_exec(doc, str(loc))
        hwp = b"HWP Document" in doc

        try:
            ole = _OleFile(doc)

            # Check and attempt decryption in-memory
            if is_ole_encrypted(ole):
                try:
                    self.msg("ole file is encrypted")
                    decrypted_doc = decrypt_ole_document(ole, password=self.password)
                    if decrypted_doc is not None:
                        self.msg("ole file decrypted")
                        myloc = f"{loc}-oledecrypted"
                        self.structure += "oledecrypted"
                        self.analyze(decrypted_doc, myloc)
                        return "ok"
                except Exception as e:
                    self.msg(e)
                    self.msg(traceback.format_exc())

            meta = _OleMetadata()
            try:
                meta = ole.get_metadata()
                if loc == "root":
                    if meta.author is not None:
                        self.results["ole_author"] = meta.author.decode("utf-8", errors="replace")
                    if meta.company is not None:
                        self.results["ole_company"] = meta.company.decode("utf-8", errors="replace")
                    if meta.last_saved_by is not None:
                        self.results["ole_last_saved_by"] = meta.last_saved_by.decode("utf-8", errors="replace")
                    if meta.title is not None:
                        self.results["ole_title"] = meta.title.decode("utf-8", errors="replace")
                    if meta.create_time is not None:
                        self.results["ole_create_time"] = str(meta.create_time)
                    if meta.last_saved_time is not None:
                        self.results["ole_last_saved_time"] = str(meta.last_saved_time)
            except Exception as e:
                self.msg(e)
                self.msg("issue with metadata")

            if meta.bytes is not None:
                extra = len(doc) - meta.bytes
                if extra > 1000:
                    self.results["results"].setdefault(str(loc), []).append(
                        {
                            "rule": "olefile_end",
                            "desc": f"WARNING: outside end of OLE structure has {extra} bytes",
                            "strings": "",
                            "type": "structure",
                        }
                    )

            for stream_idx, name in enumerate(ole.listdir(streams=True, storages=False)):
                if self._is_timed_out():
                    break
                self.msg(f"OLE Stream {name}")
                name0 = name[0] if isinstance(name, list) and name else str(name)
                try:
                    stream = ole.openstream(name)
                    s = stream.read()

                    if isinstance(name, list):
                        joined_name = "-".join(name)
                        myloc = f"{loc}-stream-{joined_name}"
                        self.structure += f"stream-{joined_name},"
                    else:
                        myloc = f"{loc}-stream-{name}"
                        self.structure += f"stream-{name},"

                    if hwp:
                        unc = self.explode_gfinflate(s)
                        if len(unc) > len(s):
                            self.msg("DECOMPRESSED ZLIB STREAM")
                            s = unc

                    # Check for VBA macro streams in Word ('Macros'), Excel ('_VBA_PROJECT_CUR'), or any 'VBA' storage
                    is_vba_stream = (
                        name0 in ("Macros", "_VBA_PROJECT_CUR", "VBA")
                        or (isinstance(name, list) and any(part.upper() == "VBA" for part in name))
                    )
                    if is_vba_stream:
                        try:
                            unc = decompress_vba_stream(s)
                            if len(unc) > 0:
                                self.msg("DECOMPRESSED Macro success")
                                # Scan raw stream first (catches p-code stomping) before replacing with decompressed source
                                self.scan_exploit(s, f"{myloc}-raw")
                                self.scan_exec(s, f"{myloc}-raw")
                                s = unc
                        except Exception:
                            pass

                    if OPENXML_MAGIC in s:
                        elements = self.carve(s, OPENXML_MAGIC)
                        if elements:
                            elements.pop(0)
                        directory = 0
                        for i, elem in enumerate(elements):
                            r = self.analyse_openxml(elem, f"{loc}-{name0}-openxml{i}")
                            if "negative" in str(r):
                                joined = b"".join(elements[directory : i + 1])
                                r = self.analyse_openxml(joined, f"{loc}-{name0}-openxml{directory}-{i}")
                                directory = i + 1
                                if self.capture:
                                    self.results["streams"][f"{loc}-{name0}-openxml{directory}-{i}"] = joined
                            elif self.capture:
                                self.results["streams"][f"{loc}-{name0}-openxml{i}"] = elem

                    if ZLIB_HEADER_MAGIC in s:
                        elements = self.carve(s, ZLIB_HEADER_MAGIC)
                        if elements:
                            elements.pop(0)
                        for element in elements:
                            dc = self.explode_gzuncompress(element)
                            gz_loc = f"{loc}-{name0}-gzinflate"
                            self.analyze(dc, gz_loc)
                            if self.capture:
                                self.results["streams"][gz_loc] = dc

                    if PPT_ATOM_MAGIC in s:
                        elements = self.carve(s, PPT_ATOM_MAGIC)
                        if elements:
                            elements.pop(0)
                        for element in elements:
                            try:
                                dc = self.explode_gfinflate(element)
                                atom_loc = f"{loc}-{name0}-atom"
                                self.analyze(dc, atom_loc)
                                if self.capture:
                                    self.results["streams"][atom_loc] = dc
                            except Exception as e:
                                self.msg(e)

                    try:
                        if len(s) > 100 and is_ole_file(s):
                            nested_loc = f"{loc}-{name0}-ole{stream_idx}"
                            self.analyse_ole(s, nested_loc)
                            if self.capture:
                                self.results["streams"][nested_loc] = s
                    except Exception:
                        pass

                    self.scan_exploit(s, myloc)
                    self.scan_exec(s, myloc)
                    if self.capture:
                        self.results["streams"][str(myloc)] = s

                    if name0 in ("Workbook", "Book"):
                        self.msg("Excel workbook calling BIFF")
                        macro = self.dobiff(name0, s)
                        if macro and len(macro) > 1:
                            macro_text = "\n".join(macro).encode("utf-8", errors="replace")
                            biff_loc = f"{myloc}-biff"
                            self.scan_exploit(macro_text, biff_loc)
                            if self.capture:
                                self.results["streams"][biff_loc] = macro_text

                except Exception as e:
                    self.msg(e)
                    self.msg(f"stream corrupted {name0}")

        except Exception as e:
            self.msg(e)
            self.msg("ole failed to parse")
            self.msg(traceback.format_exc())
            return e

        if OPENXML_MAGIC in doc:
            elements = self.carve(doc, OPENXML_MAGIC)
            if elements:
                elements.pop(0)
            directory = 0
            for i, elem in enumerate(elements):
                r = self.analyse_openxml(elem, f"{loc}-openxml{i}")
                if "negative" in str(r):
                    joined = b"".join(elements[directory : i + 1])
                    r = self.analyse_openxml(joined, f"{loc}openxml-{directory}-{i}")
                    directory = i + 1
                    if self.capture:
                        self.results["streams"][f"{loc}openxml-{directory}-{i}"] = joined
                elif self.capture:
                    self.results["streams"][f"{loc}-openxml{i}"] = elem

        return "ok"

    analyze_ole = analyse_ole

    def metadata(self) -> None:
        """Populate ``self.results`` with cryptographic hashes, file size, header hex, and timestamps."""
        self.results["md5"] = hashlib.md5(self.data).hexdigest()
        self.results["sha1"] = hashlib.sha1(self.data).hexdigest()
        self.results["sha256"] = hashlib.sha256(self.data).hexdigest()
        self.results["sha512"] = hashlib.sha512(self.data).hexdigest()
        self.results["size"] = len(self.data)
        self.results["started"] = time.time()
        self.results["version"] = self.__version__
        try:
            self.results["quicksand_exploits.yara"] = os.path.getmtime(self.exploityara)
            self.results["quicksand_exe.yara"] = os.path.getmtime(self.execyara)
            self.results["quicksand_pdf.yara"] = os.path.getmtime(self.pdfyara)
        except OSError:
            self.results["quicksand_exploits.yara"] = 0
            self.results["quicksand_exe.yara"] = 0
            self.results["quicksand_pdf.yara"] = 0
        self.results["header"] = self.data[0:16].hex()

    @staticmethod
    def sum_string(item: str) -> str:
        """Map a structural token to a single ASCII letter based on its character ordinal sum."""
        val = sum(ord(i) for i in item)
        return string.ascii_letters[int(val % len(string.ascii_letters))]

    def fuzz_structure(self) -> str:
        """Compute the ``struzzy`` fuzzy similarity string from ``self.structure``."""
        return "".join(self.sum_string(element) for element in self.structure.split(",") if element)

    def process(self) -> None:
        """Run full document analysis, compute risk ratings and structural hashes, and finalize ``results``."""
        self.metadata()
        self.analyze(self.data, "root")

        self.results["risk"] = "nothing detected"
        self.results["rating"] = 0

        score = self.results["score"]
        exploits = self.results["exploit"]
        executes = self.results["execute"]

        if score > 0:
            self.results["risk"] = "risky active content"
            self.results["rating"] = 1

        if score >= 6 or (executes >= 1 and score >= 5):
            self.results["risk"] = "high risk active content"
            self.results["rating"] = 2

        if exploits == 1 and score < 10 and executes == 0:
            self.results["risk"] = "risk of exploit"
            self.results["rating"] = 2

        if (
            (exploits >= 1 and score >= 10)
            or exploits >= 2
            or (executes >= 1 and (exploits >= 1 or score >= 10))
        ):
            self.results["risk"] = "high risk of exploit"
            self.results["rating"] = 3

        self.structure = self.structure.rstrip(",")
        self.results["structhash"] = hashlib.md5(self.structure.encode("utf-8")).hexdigest()
        self.results["structure"] = self.structure
        self.results["structhash_version"] = "1.0.3"
        self.results["structhash_elements"] = (self.structure.count(",") + 1) if self.structure else 0
        self.results["struzzy"] = self.fuzz_structure()

        self.results["finished"] = time.time()
        self.results["elapsed"] = self.results["finished"] - self.results["started"]

    def analyze(self, doc: bytes, loc: str) -> None:
        """Detect the format of ``doc`` and dispatch to the corresponding format analyzer.

        Args:
            doc: Raw document or stream bytes to analyze.
            loc: Hierarchical stream location identifier (e.g. ``"root"`` or ``"root-stream-Macros"``).
        """
        if self._is_timed_out() or self._depth > MAX_NESTING_DEPTH:
            return
        self._depth += 1
        try:
            doc_type = self.check_header(doc)
            self.msg(f"{doc_type} SCAN {loc}")
            self.structure += f"{doc_type}:{loc},"

            if loc == "root":
                self.results["type"] = doc_type

            if doc_type == "ole":
                self.analyse_ole(doc, loc)
            elif doc_type == "openxml":
                self.analyse_openxml(doc, loc)
            elif doc_type == "rtf":
                self.analyse_rtf(doc, loc)
            elif doc_type == "mso":
                self.analyse_mso(doc, loc)
            elif doc_type == "pdf":
                self.analyse_pdf(doc, loc)
            elif doc_type == "ps":
                self.analyse_ps(doc, loc)
            else:
                self.scan_exploit(doc, loc)
                self.scan_exec(doc, loc)
        finally:
            self._depth -= 1

    analyse = analyze

    @staticmethod
    def check_header(doc: bytes) -> str:
        """Identify the document container format from its header bytes.

        Args:
            doc: Raw document or stream bytes.

        Returns:
            Format identifier string: ``"rtf"``, ``"ole"``, ``"openxml"``,
            ``"zip"``, ``"pdf"``, ``"xdp"``, ``"mso"``, ``"ps"``, or ``"data"``.
        """
        if not doc:
            return "data"
        head256 = doc[:256]
        head1024 = doc[:1024]
        if RE_RTF_HEADER.search(head256) or doc.startswith(b"{\\rt"):
            return "rtf"
        elif doc[:4] == OLE_MAGIC_SHORT:
            return "ole"
        elif OPENXML_MAGIC_SHORT in doc:
            return "openxml"
        elif doc[:2] == b"PK":
            return "zip"
        elif RE_PDF_HEADER.search(head1024):
            return "pdf"
        elif RE_XDP_HEADER.search(head1024):
            return "xdp"
        elif RE_MIME_HEADER.search(head256):
            return "mso"
        elif RE_XML_HEADER.search(head256):
            return "mso"
        elif doc[:4] == b"%!PS":
            return "ps"
        else:
            return "data"

    checkHeader = check_header


# =====================================================================
# Command-Line Interface (CLI) & Windows Executable Entry Point
# =====================================================================


class BytesDump(json.JSONEncoder):
    """JSON encoder that safely serializes raw ``bytes`` objects to UTF-8 strings."""

    def default(self, obj: Any) -> Any:
        """Convert ``bytes`` to UTF-8 string (replacing invalid sequences) for JSON output."""
        if isinstance(obj, bytes):
            return obj.decode(errors="replace")
        return json.JSONEncoder.default(self, obj)


def keys_string(d: Any) -> Any:
    """Recursively convert ``bytes`` keys inside dictionaries and sequences to strings.

    Args:
        d: Arbitrary dictionary, list, tuple, set, or scalar value.

    Returns:
        Data structure with all dictionary keys normalized to ``str``.
    """
    if not isinstance(d, dict):
        if isinstance(d, (tuple, list, set)):
            return [keys_string(x) for x in d]
        return d

    rval: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(k, bytes):
            k = k.decode(errors="replace")
        if isinstance(v, dict):
            v = keys_string(v)
        elif isinstance(v, (tuple, list, set)):
            v = [keys_string(x) for x in v]
        rval[str(k)] = v
    return rval


def txt_out(results: Dict[str, Any]) -> str:
    """Format a QuickSand ``results`` dictionary as a human-readable text report.

    Args:
        results: Completed ``qs.results`` dictionary.

    Returns:
        Formatted multi-line text report string.
    """
    out = f"QuickSand Results {results['version']}\n\nMETADATA\n\n"
    out += f"{'filename':<20}: {results['filename']}\n"
    out += f"{'type':<20}: {results['type']}\n"
    out += f"{'md5':<20}: {results['md5']}\n"
    out += f"{'sha1':<20}: {results['sha1']}\n"
    out += f"{'sha256':<20}: {results['sha256']}\n"
    out += f"{'size':<20}: {results['size']}\n\n"
    out += f"{'started':<20}: {results['started']}\n"
    out += f"{'finished':<20}: {results['finished']}\n"
    out += f"{'elapsed':<20}: {results['elapsed']}\n"
    out += f"\n\nSIMILARITY {results['structhash_version']}\n\n"
    out += f"{'structhash':<20}: {results['structhash']}\n"
    out += f"{'struzzy':<20}: {results['struzzy']}\n"
    out += f"{'header':<20}: {results['header']}\n"
    out += "\n\nRESULT\n\n"
    out += f"{'risk':<20}: {results['risk']}\n"
    out += f"{'score':<20}: {results['score']}\n\n"
    out += json.dumps(keys_string(results["results"]), cls=BytesDump, sort_keys=True, indent=4) + "\n"
    return out


def save_streams(streams: Dict[str, bytes], output_dir: Path, prefix: str = "") -> None:
    """Write extracted stream bytes to sanitized filenames inside ``output_dir``.

    Args:
        streams: Mapping of stream location names to raw stream ``bytes``.
        output_dir: Destination directory ``Path``.
        prefix: Optional filename prefix (e.g., ``"<md5>_"`` when scanning a directory).
    """
    for item, content in streams.items():
        safe_name = re.sub(r"[^a-zA-Z0-9-_]", "_", str(item))
        file_path = output_dir / f"{prefix}{safe_name}"
        with open(file_path, "wb") as f:
            f.write(content if isinstance(content, bytes) else str(content).encode("utf-8", errors="replace"))


def process_file(file_path: str, args: argparse.Namespace) -> None:
    """Analyze a single file from the CLI and write/print the formatted report.

    Args:
        file_path: Path to the document file to analyze.
        args: Parsed CLI ``argparse.Namespace``.
    """
    qs = quicksand(
        file_path,
        debug=args.verbose,
        capture=args.capture,
        strings=args.yara,
        timeout=args.timeout,
        exploityara=args.exploit,
        execyara=args.exe,
        pdfyara=args.pdf,
        password=args.password,
    )
    qs.process()

    if args.dropdir:
        drop_dir = Path(args.dropdir)
        if not drop_dir.exists():
            drop_dir.mkdir(parents=True, exist_ok=True)
            print(f"Creating directory {args.dropdir}")

        if drop_dir.is_dir():
            save_streams(qs.results.get("streams", {}), drop_dir)
        else:
            print(f"Unable to write to {args.dropdir}")

    if args.out:
        with open(args.out, "w", encoding="utf-8", errors="replace") as outfile:
            if args.format == "json":
                json.dump(keys_string(qs.results), outfile, cls=BytesDump, sort_keys=True, indent=4)
            else:
                outfile.write(txt_out(qs.results))
    else:
        if args.format == "json":
            print(json.dumps(keys_string(qs.results), cls=BytesDump, sort_keys=True, indent=4))
        else:
            print(txt_out(qs.results))


def process_directory(dir_path: str, args: argparse.Namespace) -> None:
    """Analyze all files in a directory from the CLI and write/print the formatted report.

    Args:
        dir_path: Path to the directory of documents to analyze.
        args: Parsed CLI ``argparse.Namespace``.
    """
    results = quicksand.readDir(
        dir_path,
        debug=args.verbose,
        capture=args.capture,
        strings=args.yara,
        timeout=args.timeout,
        exploityara=args.exploit,
        execyara=args.exe,
        pdfyara=args.pdf,
        password=args.password,
    )

    if args.dropdir:
        drop_dir = Path(args.dropdir)
        if not drop_dir.exists():
            drop_dir.mkdir(parents=True, exist_ok=True)
            print(f"Creating directory {args.dropdir}")

        if drop_dir.is_dir():
            for _doc_path, doc_results in results.items():
                if "streams" in doc_results:
                    prefix = f"{doc_results['md5']}_"
                    save_streams(doc_results["streams"], drop_dir, prefix)
        else:
            print(f"Unable to write to {args.dropdir}")

    if args.out:
        with open(args.out, "w", encoding="utf-8", errors="replace") as outfile:
            if args.format == "json":
                json.dump(keys_string(results), outfile, cls=BytesDump, sort_keys=True, indent=4)
            else:
                for _doc_path, doc_results in results.items():
                    outfile.write(txt_out(doc_results))
    else:
        if args.format == "json":
            print(json.dumps(keys_string(results), cls=BytesDump, sort_keys=True, indent=4))
        else:
            for _doc_path, doc_results in results.items():
                print(txt_out(doc_results))
                print("\n\n")


def main(args: Optional[List[str]] = None) -> argparse.Namespace:
    """QuickSand CLI entry point (cross-platform & Windows executable compatible).

    Args:
        args: Optional argument list to parse (defaults to ``sys.argv[1:]``).

    Returns:
        Parsed ``argparse.Namespace`` object.
    """
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    epilog = (
        "examples:\n"
        "  quicksand suspicious.doc\n"
        "  quicksand -f txt -y invoice.pdf\n"
        "  quicksand -p VelvetSweatshop encrypted.xls\n"
        "  quicksand -d extracted_streams/ -o report.json samples_dir/\n"
    )
    parser = argparse.ArgumentParser(
        prog="quicksand",
        description=(
            f"QuickSand v{quicksand.__version__} - Document and PDF malware analysis tool.\n"
            "Scans nested streams inside Office (OLE2, OpenXML, RTF, VBA, XLM), PDF,\n"
            "MIME/ActiveMime, PostScript, and OneNote files using YARA signatures."
        ),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "document",
        type=str,
        help="path to a document file or directory of documents to scan",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {quicksand.__version__}",
    )

    scan_group = parser.add_argument_group("analysis & extraction options")
    scan_group.add_argument(
        "-v", "--verbose",
        help="enable verbose diagnostic logging during analysis",
        action="store_true",
    )
    scan_group.add_argument(
        "-c", "--capture",
        help="capture decoded stream contents in results",
        action="store_true",
    )
    scan_group.add_argument(
        "-y", "--yara",
        help="include matched YARA string offsets and previews in output",
        action="store_true",
    )
    scan_group.add_argument(
        "-t", "--timeout",
        help="per-file analysis timeout in seconds (default: 0 = unlimited)",
        default=0,
        type=int,
        metavar="SECONDS",
    )
    scan_group.add_argument(
        "-p", "--password",
        help="password for decrypting protected Office documents",
        default=None,
        type=str,
        metavar="PASSWORD",
    )
    scan_group.add_argument(
        "-d", "--dropdir",
        help="directory to write extracted binary streams to (implies --capture)",
        default=None,
        type=str,
        metavar="DIR",
    )

    out_group = parser.add_argument_group("output options")
    out_group.add_argument(
        "-f", "--format",
        help="report output format: 'json' or 'txt' (default: json)",
        type=str,
        choices=["json", "txt"],
        default="json",
    )
    out_group.add_argument(
        "-o", "--out",
        help="write report output to FILE instead of stdout",
        default=None,
        type=str,
        metavar="FILE",
    )

    rules_group = parser.add_argument_group("custom YARA signature options")
    rules_group.add_argument(
        "-e", "--exploit",
        help="custom path to exploit YARA rules (default: bundled quicksand_exploits.yara)",
        default=None,
        type=str,
        metavar="FILE",
    )
    rules_group.add_argument(
        "-x", "--exe",
        help="custom path to executable YARA rules (default: bundled quicksand_exe.yara)",
        default=None,
        type=str,
        metavar="FILE",
    )
    rules_group.add_argument(
        "-a", "--pdf",
        help="custom path to PDF YARA rules (default: bundled quicksand_pdf.yara)",
        default=None,
        type=str,
        metavar="FILE",
    )

    parsed_args = parser.parse_args(args)

    if parsed_args.dropdir:
        parsed_args.capture = True

    input_path = Path(parsed_args.document)
    if input_path.is_file():
        process_file(str(input_path), parsed_args)
    elif input_path.is_dir():
        process_directory(str(input_path), parsed_args)
    else:
        print(f"Error: '{parsed_args.document}' is not a valid file or directory")
        sys.exit(1)

    return parsed_args


if __name__ == "__main__":
    main()

