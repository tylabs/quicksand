import base64
import hashlib
import hmac
import importlib
import inspect
import io
import json
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from quicksand import quicksand as qs_cls

qm = importlib.import_module("quicksand.quicksand")


def test_pdf_flatedecode_and_tounicode_preserved():
    cmap_stream = (
        b"/CIDInit /ProcSet findresource begin\n"
        b"12 dict begin\n"
        b"begincmap\n"
        b"1 beginbfchar\n"
        b"<01> <0048>\n"
        b"<02> <0069>\n"
        b"endbfchar\n"
        b"endcmap\n"
    )
    page_stream = b"BT /F1 12 Tf <0102> Tj ( world) Tj ET"
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Font /Name /F1 /ToUnicode 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Filter /FlateDecode >>\nstream\r\n"
        + zlib.compress(cmap_stream)
        + b"\r\nendstream\nendobj\n"
        b"3 0 obj\n<< /Filter /FlateDecode >>\nstream\n"
        + zlib.compress(page_stream)
        + b"\nendstream\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )
    q = qs_cls(pdf, capture=True, timeout=5)
    q.process()
    assert q.results["type"] == "pdf"
    streams = q.results["streams"]
    assert streams["root-pdf_2_0"] == cmap_stream
    assert streams["root-pdf_3_0"] == page_stream
    assert b"Hi world" in streams["root-pdf_text"]


def test_pdf_unclosed_tokens_linear_time():
    """Unclosed PDF object/stream/CMap/BT markers must scan in linear O(N) time."""
    repeated_objs = b"%PDF-1.5\n" + (b"1 0 obj << /Type /Annot >>\n" * 6000)
    t0 = time.perf_counter()
    q = qs_cls(repeated_objs, capture=False, timeout=5)
    q.process()
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.5

    # Unclosed CMap and BT markers inside decoded streams
    unclosed_cmap = b"begincmap " + (b"beginbfchar <01> <0041> " * 4000)
    unclosed_bt = (b"BT (hello) Tj " * 4000) + b"ET"
    t1 = time.perf_counter()
    txt = qm.reconstruct_pdf_text(repeated_objs, {1: unclosed_cmap, 2: unclosed_bt})
    assert (time.perf_counter() - t1) < 1.0
    assert b"hello" in txt


def test_pdf_filter_chain_capped():
    raw = b"Hello chained flate"
    comp = raw
    for _ in range(qm.MAX_PDF_FILTERS + 4):
        comp = zlib.compress(comp)
    filters = b" ".join([b"/FlateDecode"] * (qm.MAX_PDF_FILTERS + 4))
    dict_bytes = b"<< /Filter [" + filters + b"] >>"
    out = qm.decode_pdf_stream(dict_bytes, comp)
    assert out is not None
    # Because filter execution is capped at MAX_PDF_FILTERS, full 12-deep chain stops safely
    assert out != raw


def test_archive_extraction_and_capture_budgets_enforced():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for idx in range(20):
            zf.writestr(f"doc_{idx}.xml", ("<r>" + ("A" * 16384) + "</r>").encode("ascii"))
    archive_bytes = buf.getvalue()

    q = qs_cls(
        archive_bytes,
        capture=True,
        max_total_bytes=64 * 1024,
        max_captured_bytes=32 * 1024,
        timeout=5,
    )
    q.process()
    total_captured = sum(len(v) for v in q.results.get("streams", {}).values())
    assert total_captured <= 32 * 1024
    assert q.results.get("capture_truncated") == 1
    assert q.results.get("skip") == 1


def test_aes_crypto_and_pure_python_fallback_parity(monkeypatch):
    key = bytes(range(32))
    iv = bytes(range(16))
    ciphertext = bytes((i * 7 + 3) & 0xFF for i in range(64))

    monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", False)
    ecb_py = qm._aes_ecb_decrypt(key, ciphertext)
    cbc_py = qm._aes_cbc_decrypt(key, iv, ciphertext)

    if getattr(qm, "_CryptoCipher", None) is not None:
        monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", True)
        ecb_fast = qm._aes_ecb_decrypt(key, ciphertext)
        cbc_fast = qm._aes_cbc_decrypt(key, iv, ciphertext)
        assert ecb_fast == ecb_py
        assert cbc_fast == cbc_py

    # Round-trip check for pure-Python AES ECB
    rks = qm._aes_expand_key(key)
    re_enc = b"".join(qm._aes_encrypt_block(ecb_py[i : i + 16], rks) for i in range(0, len(ecb_py), 16))
    assert re_enc == ciphertext

    # Expired deadline aborts immediately
    expired = time.time() - 10.0
    assert qm._aes_cbc_decrypt(key, iv, ciphertext, deadline=expired) == b""


def test_postscript_hex_blocks_non_backtracking():
    ps_doc = b"%!PS\n " + (b"a" * 80000) + b"Z\n" + b"48656c6c6f20576f726c64" * 4 + b"\n"
    t0 = time.perf_counter()
    blocks = qm.quicksand._extract_ps_hex_blocks(ps_doc)
    assert (time.perf_counter() - t0) < 0.5
    assert len(blocks) == 1
    assert b"48656c6c6f" in blocks[0]


def test_rtf_objdata_monotonic_and_deadline_safe():
    rtf_doc = b"{\\rtf1" + (b"\\objdata " * 2000) + b"4142434445464748494a4b4c4d4e4f50}"
    t0 = time.perf_counter()
    parser = qm._RtfObjParser(rtf_doc, deadline=time.time() + 5.0)
    parser.parse()
    assert (time.perf_counter() - t0) < 0.5
    assert len(parser.objects) == 1


def test_save_streams_sanitizes_and_truncates_long_names():
    long_key = "../" * 40 + "nested_stream_" + ("x" * 300)
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        qm.save_streams({long_key: b"stream_bytes"}, out_dir, prefix="../../pref_")
        saved = list(out_dir.iterdir())
        assert len(saved) == 1
        assert saved[0].parent == out_dir
        assert len(saved[0].name) <= 230
        assert saved[0].read_bytes() == b"stream_bytes"


def _build_cart_bytes(
    payload: bytes,
    opt_header: dict = None,
    opt_footer: dict = None,
    key_override: bytes = None,
) -> bytes:
    """Construct a spec-compliant CybercentreCanada CaRT v1 container."""
    arc4_key = key_override if key_override is not None else qm.CART_DEFAULT_KEY
    header_key_field = (b"\x00" * 16) if key_override is not None else arc4_key

    opt_header_crypt = b""
    if opt_header:
        raw_hdr = json.dumps(opt_header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        opt_header_crypt = qm._rc4(arc4_key, raw_hdr)

    mandatory_header = struct.pack(
        "<4shQ16sQ",
        b"CART",
        1,
        0,
        header_key_field,
        len(opt_header_crypt),
    )

    comp_payload = zlib.compress(payload, zlib.Z_BEST_SPEED)
    crypt_payload = qm._rc4(arc4_key, comp_payload)

    footer_dict = dict(opt_footer or {})
    footer_dict.setdefault("md5", hashlib.md5(payload).hexdigest())
    footer_dict.setdefault("sha1", hashlib.sha1(payload).hexdigest())
    footer_dict.setdefault("sha256", hashlib.sha256(payload).hexdigest())
    footer_dict.setdefault("length", str(len(payload)))
    raw_ftr = json.dumps(footer_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    opt_footer_crypt = qm._rc4(arc4_key, raw_ftr)

    opt_footer_pos = len(mandatory_header) + len(opt_header_crypt) + len(crypt_payload)
    mandatory_footer = struct.pack(
        "<4sQQQ",
        b"TRAC",
        0,
        opt_footer_pos,
        len(opt_footer_crypt),
    )
    return mandatory_header + opt_header_crypt + crypt_payload + opt_footer_crypt + mandatory_footer


def _build_winzip_aes_zip(
    entries: list,
    password: str,
    strength: int = 3,
    ae_version: int = 2,
    compress: bool = True,
) -> bytes:
    """Build a spec-compliant WinZip AE-1/AE-2 (compression method 99) ZIP archive.

    ``entries`` is a list of ``(filename, raw_bytes)`` tuples.
    """
    salt_len = {1: 8, 2: 12, 3: 16}[strength]
    key_len = {1: 16, 2: 24, 3: 32}[strength]
    actual_method = 8 if compress else 0

    local_chunks = []
    central_chunks = []
    offset = 0

    for idx, (fname, raw_data) in enumerate(entries):
        fname_bytes = fname.encode("utf-8")
        salt = bytes(((idx + 1) * 17 + i * 13) & 0xFF for i in range(salt_len))
        dk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 1000, 2 * key_len + 2)
        aes_key = dk[:key_len]
        auth_key = dk[key_len : 2 * key_len]
        pwd_verify = dk[2 * key_len : 2 * key_len + 2]

        if compress:
            cobj = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
            comp_data = cobj.compress(raw_data) + cobj.flush()
        else:
            comp_data = raw_data

        ciphertext = qm._aes_ctr_le_crypt(aes_key, comp_data, start_counter=1)
        assert ciphertext is not None
        mac10 = hmac.new(auth_key, ciphertext, hashlib.sha1).digest()[:10]
        enc_body = salt + pwd_verify + ciphertext + mac10

        crc_val = (zlib.crc32(raw_data) & 0xFFFFFFFF) if ae_version == 1 else 0
        extra_9901 = struct.pack("<HH H2sBH", 0x9901, 7, ae_version, b"AE", strength, actual_method)

        local_hdr = struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            51,          # version needed (5.1 for AES)
            0x0001,      # GP bit 0 = encrypted
            99,          # compression method = WinZip AES
            0,
            0,
            crc_val,
            len(enc_body),
            len(raw_data),
            len(fname_bytes),
            len(extra_9901),
        )
        local_record = local_hdr + fname_bytes + extra_9901 + enc_body
        local_chunks.append(local_record)

        central_hdr = struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            51,
            51,
            0x0001,
            99,
            0,
            0,
            crc_val,
            len(enc_body),
            len(raw_data),
            len(fname_bytes),
            len(extra_9901),
            0,
            0,
            0,
            0,
            offset,
        )
        central_chunks.append(central_hdr + fname_bytes + extra_9901)
        offset += len(local_record)

    cd_bytes = b"".join(central_chunks)
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        len(entries),
        len(entries),
        len(cd_bytes),
        offset,
        0,
    )
    return b"".join(local_chunks) + cd_bytes + eocd


def _build_zipcrypto_zip(entries: list, password: str) -> bytes:
    """Build a cross-platform PKWARE ZipCrypto encrypted ZIP archive in pure Python."""
    crc_table = [0] * 256
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        crc_table[n] = c

    def _crc32_byte(crc_val: int, b: int) -> int:
        return crc_table[(crc_val ^ b) & 0xFF] ^ (crc_val >> 8)

    def _zipcrypto_encrypt(pw_bytes: bytes, plaintext: bytes, crc_val: int) -> bytes:
        k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

        def _update_keys(byte_val: int) -> None:
            nonlocal k0, k1, k2
            k0 = _crc32_byte(k0, byte_val)
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k2 = _crc32_byte(k2, (k1 >> 24) & 0xFF)

        for b in pw_bytes:
            _update_keys(b)

        # 12-byte encryption header; last byte must equal (CRC >> 24) & 0xFF when GP bit 3 is unset
        header_plain = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, (crc_val >> 24) & 0xFF])
        out = bytearray()
        for b in header_plain + plaintext:
            temp = (k2 | 2) & 0xFFFF
            keystream_byte = ((temp * (temp ^ 1)) >> 8) & 0xFF
            out.append(b ^ keystream_byte)
            _update_keys(b)
        return bytes(out)

    pw_bytes = password.encode("utf-8")
    local_chunks = []
    central_chunks = []
    offset = 0
    for fname, raw_data in entries:
        fname_bytes = fname.encode("utf-8")
        crc_val = zlib.crc32(raw_data) & 0xFFFFFFFF
        cobj = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
        comp_data = cobj.compress(raw_data) + cobj.flush()
        enc_body = _zipcrypto_encrypt(pw_bytes, comp_data, crc_val)

        local_hdr = struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            0x0001,  # GP bit 0 = encrypted
            8,       # ZIP_DEFLATED
            0,
            0,
            crc_val,
            len(enc_body),
            len(raw_data),
            len(fname_bytes),
            0,
        )
        local_record = local_hdr + fname_bytes + enc_body
        local_chunks.append(local_record)

        central_hdr = struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            20,
            20,
            0x0001,
            8,
            0,
            0,
            crc_val,
            len(enc_body),
            len(raw_data),
            len(fname_bytes),
            0,
            0,
            0,
            0,
            0,
            offset,
        )
        central_chunks.append(central_hdr + fname_bytes)
        offset += len(local_record)

    cd_bytes = b"".join(central_chunks)
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        len(entries),
        len(entries),
        len(cd_bytes),
        offset,
        0,
    )
    return b"".join(local_chunks) + cd_bytes + eocd


def test_aes_encrypt_and_ctr_parity(monkeypatch):
    for key_len in (16, 24, 32):
        key = bytes((i * 11 + 5) & 0xFF for i in range(key_len))
        rks = qm._aes_expand_key(key)
        blk = bytes(range(16))
        enc = qm._aes_encrypt_block(blk, rks)
        assert qm._aes_decrypt_block(enc, rks) == blk

        payload = bytes((i * 29 + 7) & 0xFF for i in range(1500))
        monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", False)
        ctr_py = qm._aes_ctr_le_crypt(key, payload, start_counter=1)
        if getattr(qm, "_CryptoCipher", None) is not None:
            monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", True)
            ctr_fast = qm._aes_ctr_le_crypt(key, payload, start_counter=1)
            assert ctr_fast == ctr_py
        # Applying CTR again restores plaintext
        assert qm._aes_ctr_le_crypt(key, ctr_py, start_counter=1) == payload


def test_cart_default_and_custom_keys_and_locked_warning():
    inner_pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n"
        b"%%EOF\n"
    )
    # 1. Standard default-key CaRT file
    cart_std = _build_cart_bytes(inner_pdf, opt_header={"name": "lure.pdf", "tlp": "AMBER"})
    q1 = qs_cls(cart_std, capture=True, timeout=5)
    q1.process()
    assert q1.results["type"] == "cart"
    assert q1.results["cart"]["name"] == "lure.pdf"
    assert q1.results["cart"]["payload_sha256"] == hashlib.sha256(inner_pdf).hexdigest()
    assert q1.results["streams"]["root-cart-lure.pdf"] == inner_pdf
    assert any("pdf" in k or "cart" in k for k in q1.results["results"])
    report_txt = qm.txt_out(q1.results)
    assert "cart_name" in report_txt
    assert hashlib.sha256(inner_pdf).hexdigest() in report_txt

    # 2. Custom-key CaRT using built-in 'infected1' password (auto-unlocked without -p)
    cart_inf1 = _build_cart_bytes(
        inner_pdf,
        opt_header={"name": "auto.pdf"},
        key_override=b"infected1\x00\x00\x00\x00\x00\x00\x00",
    )
    q2 = qs_cls(cart_inf1, capture=True, timeout=5)
    q2.process()
    assert q2.results["type"] == "cart"
    assert not q2.results.get("encrypted_unreadable")
    assert q2.results["streams"]["root-cart-auto.pdf"] == inner_pdf

    # 3. Custom-key CaRT using `cart -k <base64>` style key passed via password=
    raw_custom_key = b"MyCustomKey123"
    padded_custom_key = raw_custom_key + b"\x00" * (16 - len(raw_custom_key))
    b64_key = base64.b64encode(raw_custom_key).decode("ascii")
    cart_b64 = _build_cart_bytes(
        inner_pdf,
        opt_header={"name": "b64.pdf"},
        key_override=padded_custom_key,
    )
    q3_locked = qs_cls(cart_b64, capture=True, timeout=5)
    q3_locked.process()
    assert q3_locked.results.get("encrypted_unreadable") is True
    assert q3_locked.results["score"] >= 1
    assert any(
        hit["rule"] == "archive_encrypted_unreadable"
        for hits in q3_locked.results["results"].values()
        for hit in hits
    )

    q3_unlocked = qs_cls(cart_b64, capture=True, password=b64_key, timeout=5)
    q3_unlocked.process()
    assert not q3_unlocked.results.get("encrypted_unreadable")
    assert q3_unlocked.results["streams"]["root-cart-b64.pdf"] == inner_pdf

    # 4. Decompression bomb inside CaRT stops cleanly at max_total_bytes
    bomb_cart = _build_cart_bytes(b"A" * (256 * 1024), opt_header={"name": "bomb.bin"})
    q_bomb = qs_cls(bomb_cart, capture=True, max_total_bytes=32 * 1024, timeout=5)
    q_bomb.process()
    assert q_bomb.results.get("skip") == 1
    assert len(q_bomb.results["streams"].get("root-cart-bomb.bin", b"")) <= 32 * 1024


def test_zipcrypto_and_winzip_aes_passwords_and_nested_containers(monkeypatch):
    sample_pdf = (
        b"%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /Launch /Win << /F (cmd.exe) >> >> >>\nendobj\n%%EOF"
    )
    # 1. Legacy PKWARE ZipCrypto archive built in pure Python (works on Windows, Linux, and macOS)
    zipcrypto_bytes = _build_zipcrypto_zip([("payload.pdf", sample_pdf)], password="infected1")

    q_zc = qs_cls(zipcrypto_bytes, capture=True, timeout=5)
    q_zc.process()
    assert q_zc.results.get("archive_decrypted") is True
    assert not q_zc.results.get("encrypted_unreadable")
    assert q_zc.results["streams"]["root-payload.pdf"] == sample_pdf
    assert q_zc.results["archive_entries"][0]["sha256"] == hashlib.sha256(sample_pdf).hexdigest()
    assert q_zc.results["archive_entries"][0]["decrypted"] is True

    # 2. WinZip AES-256 (AE-2, deflated) & AES-128 (AE-1, stored) under available crypto backends
    aes256_zip = _build_winzip_aes_zip(
        [("doc1.pdf", sample_pdf), ("nested.cart", _build_cart_bytes(sample_pdf, {"name": "inner.pdf"}))],
        password="infected1",
        strength=3,
        ae_version=2,
        compress=True,
    )
    crypto_modes = (True, False) if getattr(qm, "_CryptoCipher", None) is not None else (False,)
    for use_crypto in crypto_modes:
        monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", use_crypto)
        q_aes = qs_cls(aes256_zip, capture=True, timeout=5)
        q_aes.process()
        assert q_aes.results.get("archive_decrypted") is True
        assert q_aes.results["streams"]["root-doc1.pdf"] == sample_pdf
        assert q_aes.results["streams"]["root-nested.cart-cart-inner.pdf"] == sample_pdf

    aes128_custom = _build_winzip_aes_zip(
        [("secret.pdf", sample_pdf)],
        password="CustomAnalystsPassword!99",
        strength=1,
        ae_version=1,
        compress=False,
    )
    # Without password -> surfaces archive_encrypted_unreadable warning
    q_locked = qs_cls(aes128_custom, capture=True, timeout=5)
    q_locked.process()
    assert q_locked.results.get("encrypted_unreadable") is True
    assert q_locked.results["rating"] >= 1
    assert q_locked.results["archive_entries"][0]["decrypted"] is False
    assert any(
        hit["rule"] == "archive_encrypted_unreadable"
        for hits in q_locked.results["results"].values()
        for hit in hits
    )

    # With password -> unlocks and scans inner payload
    q_custom = qs_cls(aes128_custom, capture=True, password="CustomAnalystsPassword!99", timeout=5)
    q_custom.process()
    assert q_custom.results.get("archive_decrypted") is True
    assert not q_custom.results.get("encrypted_unreadable")
    assert q_custom.results["streams"]["root-secret.pdf"] == sample_pdf

    # 3. WinZip AES bomb capped by max_total_bytes (and standalone skip fails closed with rating >= 1)
    aes_bomb = _build_winzip_aes_zip(
        [("huge.xml", b"<x>" + (b"B" * 200000) + b"</x>")],
        password="infected",
        strength=3,
        compress=True,
    )
    q_aes_bomb = qs_cls(aes_bomb, capture=True, max_total_bytes=32 * 1024, timeout=5)
    q_aes_bomb.process()
    assert q_aes_bomb.results.get("skip") == 1
    assert q_aes_bomb.results["rating"] >= 1


def test_bundled_yara_rules_zero_compiler_warnings():
    import yara

    rules_dir = SRC_DIR / "quicksand"
    for rule_file in ("quicksand_exploits.yara", "quicksand_pdf.yara", "quicksand_exe.yara"):
        compiled = yara.compile(filepath=str(rules_dir / rule_file), error_on_warning=True)
        assert getattr(compiled, "warnings", []) == []


def test_yara_error_fail_closed_without_aborting_scan():
    import yara

    class _RaisingRules:
        def match(self, data=b"", timeout=None):
            raise yara.Error("internal error: 30")

    q = qs_cls(b"Hello benign buffer", capture=False, timeout=5)
    q.exploitrules = _RaisingRules()
    q.process()
    assert q.results.get("skip") == 1
    assert q.results["warning"] >= 1
    assert q.results["rating"] >= 1
    assert any(
        hit["rule"] == "yara_match_limit_exceeded"
        for hits in q.results["results"].values()
        for hit in hits
    )


def test_format_yara_strings_caps_instances_and_preview_len():
    class _FakeInst:
        def __init__(self, offset, data):
            self.offset = offset
            self.matched_data = data

    class _FakeMatch:
        def __init__(self, ident, instances):
            self.identifier = ident
            self.instances = instances

    q = qs_cls(b"x", capture=False)
    many_instances = [_FakeInst(i * 10, b"A" * 600) for i in range(200)]
    formatted = q.format_yara_strings([_FakeMatch("$s1", many_instances)])
    lines = formatted.splitlines()
    assert len(lines) == qm.MAX_YARA_MATCH_INSTANCES
    assert all(len(line) <= qm.MAX_YARA_STRING_PREVIEW + 64 for line in lines)
    assert lines[0].endswith("...")


def test_xdp_wrapper_unpacks_embedded_pdf_chunk():
    inner_pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n"
        b"%%EOF\n"
    )
    xdp_doc = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">\n'
        b"<pdf xmlns=\"http://ns.adobe.com/xdp/pdf/\"><document><chunk>"
        + base64.b64encode(inner_pdf)
        + b"</chunk></document></pdf></xdp:xdp>"
    )
    q = qs_cls(xdp_doc, capture=True, timeout=5)
    q.process()
    assert q.results["type"] == "xdp"
    assert q.results["streams"].get("root-xdp_chunk") == inner_pdf
    assert q.results["score"] > 0
    assert any("xdp_chunk" in k for k in q.results["results"])


def test_rtf_olepackage_recursively_analyzes_embedded_pdf():
    inner_pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n"
        b"%%EOF\n"
    )
    # Construct OLE1.0 Format 2 ("Package") containing an OLEPackage body wrapping inner_pdf
    pkg_body = (
        struct.pack("<H", 2)
        + b"lure.pdf\x00"
        + b"C:\\temp\\lure.pdf\x00"
        + struct.pack("<I", 3)
        + struct.pack("<I", len(b"C:\\temp\\lure.pdf\x00"))
        + b"C:\\temp\\lure.pdf\x00"
        + struct.pack("<I", len(inner_pdf))
        + inner_pdf
    )
    cls_bytes = b"Package\x00"
    ole10 = (
        struct.pack("<II", 0x0501, 2)
        + struct.pack("<I", len(cls_bytes))
        + cls_bytes
        + struct.pack("<II", 0, 0)
        + struct.pack("<I", len(pkg_body))
        + pkg_body
    )
    rtf_doc = b"{\\rtf1{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata " + ole10.hex().encode("ascii") + b"}}}"
    q = qs_cls(rtf_doc, capture=True, timeout=5)
    q.process()
    assert q.results["type"] == "rtf"
    assert len(q.results["packages"]) == 1
    assert any("rtfpkg@" in k for k in q.results["results"])
    assert q.results["score"] > 0


def test_openxml_prioritizes_active_streams_ahead_of_large_decoys():
    active_rels = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Relationships><Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
        b'Target="https://example.invalid/payload.htm" TargetMode="External"/></Relationships>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types></Types>")
        # Front-load large zero-filled decoy streams ahead of word/_rels/document.xml.rels
        zf.writestr("media/000_decoy1.bin", b"\x00" * 120000)
        zf.writestr("media/000_decoy2.bin", b"\x00" * 120000)
        zf.writestr("word/_rels/document.xml.rels", active_rels)
    docx_bytes = buf.getvalue()

    q = qs_cls(docx_bytes, capture=True, max_total_bytes=32 * 1024, timeout=5)
    q.process()
    assert "root-word/_rels/document.xml.rels" in q.results["streams"]
    assert q.results.get("skip") == 1
    assert q.results["score"] > 0


def test_encrypted_zip_kdf_throttling_caps_brute_force_entries(monkeypatch):
    entries = [(f"file_{i:02d}.txt", b"secret content") for i in range(16)]
    locked_zip = _build_winzip_aes_zip(entries, password="UnknowableStrongPassword!2026", strength=3)

    pbkdf2_calls = 0
    orig_pbkdf2 = hashlib.pbkdf2_hmac

    def _counting_pbkdf2(*args, **kwargs):
        nonlocal pbkdf2_calls
        pbkdf2_calls += 1
        return orig_pbkdf2(*args, **kwargs)

    monkeypatch.setattr(hashlib, "pbkdf2_hmac", _counting_pbkdf2)
    q = qs_cls(locked_zip, capture=False, timeout=5)
    q.process()
    assert q.results.get("encrypted_unreadable") is True
    assert len(q.results["archive_entries"]) == 16
    # Only the first MAX_FAILED_ZIP_KDF_ENTRIES entries run PBKDF2 across DEFAULT_ARCHIVE_PASSWORDS
    max_expected = qm.MAX_FAILED_ZIP_KDF_ENTRIES * len(qm.DEFAULT_ARCHIVE_PASSWORDS)
    assert pbkdf2_calls <= max_expected


def test_cli_readdir_skips_symlinks_cwd_yara_ignored_and_long_str_safe():
    import os

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scan_dir = root / "scan"
        scan_dir.mkdir()
        outside = root / "outside_secret.txt"
        outside.write_bytes(b"secret host file")
        regular = scan_dir / "regular.txt"
        regular.write_bytes(b"hello world")
        symlink_file = scan_dir / "linked.txt"
        symlink_created = False
        try:
            symlink_file.symlink_to(outside)
            symlink_created = True
        except (OSError, NotImplementedError):
            # Unprivileged Windows runners without SeCreateSymbolicLinkPrivilege
            pass

        # Plant a bogus empty quicksand_exploits.yara in cwd and ensure _resolve_default_yara_path ignores cwd
        evil_yara = root / "quicksand_exploits.yara"
        evil_yara.write_text("rule empty_override { condition: false }\n", encoding="utf-8")
        old_cwd = os.getcwd()
        try:
            os.chdir(str(root))
            resolved = Path(qm._resolve_default_yara_path("quicksand_exploits.yara")).resolve()
            assert resolved != evil_yara.resolve()
        finally:
            os.chdir(old_cwd)

        dir_results = qs_cls.readDir(scan_dir)
        assert str(regular) in dir_results
        if symlink_created:
            assert str(symlink_file) not in dir_results

    # Passing a string > 255 bytes must never raise OSError(ENAMETOOLONG)
    q_long = qs_cls("A" * 2048)
    q_long.process()
    assert q_long.results["size"] == 2048


def test_pdf_png_predictor_and_vba_respect_expired_deadline():
    expired = time.time() - 5.0
    # 64 rows of PNG Paeth predictor (filter byte 4 + 1024 columns)
    predictor_input = (b"\x04" + (b"\x01" * 1024)) * 64
    out_pred = qm._pdf_apply_png_predictor(predictor_input, predictor=14, columns=1024, deadline=expired)
    assert out_pred == b""

    # Fake VBA stream full of 0x01 bytes with expired deadline
    vba_blob = b"\x00" + (b"\x01\x10\xb0" * 500)
    assert qm.decompress_vba_stream(vba_blob, deadline=expired) == b""


# =====================================================================
# Cloud Run, Subprocess Isolation, Decompression Caps & XSS Audit Tests
# =====================================================================

GCLOUD_FUNC_DIR = Path(__file__).resolve().parents[1] / "gcloud" / "function"
if str(GCLOUD_FUNC_DIR) not in sys.path:
    sys.path.insert(0, str(GCLOUD_FUNC_DIR))


def _load_cloud_run_main():
    return importlib.import_module("main")


def _hung_worker_ignoring_sigalrm(out_queue, *_args):
    import signal as _sig

    if hasattr(_sig, "SIGALRM"):
        _sig.signal(_sig.SIGALRM, _sig.SIG_IGN)
    time.sleep(30)


def _large_payload_worker(out_queue, *_args):
    # 512 KB serialized report (>8x typical 64 KB OS pipe buffer) to verify no Queue/join deadlock
    big_json = json.dumps({"padding": "X" * (512 * 1024), "rating": 0, "score": 0})
    out_queue.put(("ok", big_json, False))


class _FakeRequest:
    def __init__(
        self,
        method="GET",
        path="/health",
        args=None,
        headers=None,
        body=b"",
        remote_addr="198.51.100.10",
    ):
        import urllib.parse

        self.method = method
        self.path = path
        self.args = dict(args or {})
        self.headers = dict(headers or {})
        self._body = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.remote_addr = remote_addr
        self.query_string = urllib.parse.urlencode(self.args).encode("utf-8")
        self.host = self.headers.get("Host", "evil-attacker.example.com")

    def get_data(self, cache=True):
        return self._body


class _FakeBlob:
    def __init__(self, store, name, kms_key_name=None):
        from datetime import datetime, timezone

        self._store = store
        self.name = name
        self.kms_key_name = kms_key_name
        self.size = len(store[name]["data"]) if name in store else None
        self.metadata = dict(store[name].get("metadata") or {}) if name in store else {}
        self.updated = store[name].get("updated", datetime.now(timezone.utc)) if name in store else None
        self.last_signed_kwargs = None

    def reload(self):
        if self.name not in self._store:
            raise Exception("404 Not Found: secret-internal-bucket-name/new/missing")
        entry = self._store[self.name]
        self.size = len(entry["data"])
        self.metadata = dict(entry.get("metadata") or {})
        self.updated = entry.get("updated")

    def download_as_bytes(self):
        if self.name not in self._store:
            raise Exception("404 Not Found: secret-internal-bucket-name/" + self.name)
        return self._store[self.name]["data"]

    def upload_from_string(self, data, content_type="application/json"):
        from datetime import datetime, timezone

        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        self._store[self.name] = {
            "data": raw,
            "content_type": content_type,
            "metadata": dict(self.metadata or {}),
            "updated": datetime.now(timezone.utc),
            "kms_key_name": self.kms_key_name,
        }

    def generate_signed_url(self, **kwargs):
        self.last_signed_kwargs = kwargs
        self._store.setdefault("_signed_calls", []).append((self.name, kwargs))
        return f"https://storage.googleapis.com/signed/{self.name}?v=4"


class _FakeBucket:
    def __init__(self, store):
        self._store = store

    def blob(self, name, kms_key_name=None):
        return _FakeBlob(self._store, name, kms_key_name=kms_key_name)

    def get_blob(self, name):
        if name not in self._store:
            return None
        return _FakeBlob(self._store, name)


class _FakeStorageClient:
    def __init__(self, store):
        self._store = store

    def bucket(self, _bucket_name):
        return _FakeBucket(self._store)


def _resp_json(resp_tuple):
    resp, status = resp_tuple if isinstance(resp_tuple, tuple) else (resp_tuple, resp_tuple.status_code)
    text = resp.get_data(as_text=True)
    return status, json.loads(text), text


def test_cloud_run_oidc_and_hmac_auth_hardening(monkeypatch):
    crm = _load_cloud_run_main()
    monkeypatch.setattr(crm, "project_id", "qs-prod-proj")
    monkeypatch.setenv("QS_URL", "https://quicksand.example.com/analyze")
    monkeypatch.setenv("K_SERVICE", "quicksand-combined")
    monkeypatch.setenv("QS_REQUIRE_AUTH", "0")  # Must be IGNORED when K_SERVICE is set!
    monkeypatch.setenv("QS_HMAC_SECRET", "super-secret-dev-key")

    # 1. Unauthenticated call is blocked even though QS_REQUIRE_AUTH=0 because K_SERVICE is set
    unauth_req = _FakeRequest(method="GET", path="/search", args={"query": "a" * 64})
    status, body, _ = _resp_json(crm.quicksand_combined(unauth_req))
    assert status == 401

    # 2. HMAC fallback is strictly rejected when K_SERVICE is set (even with valid signature)
    ts_now = str(int(time.time()))
    canon = f"{ts_now}.GET./search?query={'a' * 64}.".encode("utf-8")
    valid_hmac = hmac.new(b"super-secret-dev-key", canon, hashlib.sha256).hexdigest()
    hmac_cloud_req = _FakeRequest(
        method="GET",
        path="/search",
        args={"query": "a" * 64},
        headers={"X-QS-Timestamp": ts_now, "X-QS-Signature": valid_hmac},
    )
    status_hc, _, _ = _resp_json(crm.quicksand_combined(hmac_cloud_req))
    assert status_hc == 401

    # 3. OIDC issuer, audience, Host-header spoofing, and caller service account checks
    claims_box = {}

    def _fake_verify_oauth2(token, _req):
        if token == "bad-token":
            raise ValueError("Token expired")
        return dict(claims_box)

    monkeypatch.setattr(crm.google_id_token, "verify_oauth2_token", _fake_verify_oauth2)
    store = {}
    monkeypatch.setattr(crm, "qs_bucket_name", "my-private-qs-bucket")
    monkeypatch.setattr(crm, "storage_client", _FakeStorageClient(store))

    # Valid project SA + valid QS_URL origin/path & Cloud Run {K_SERVICE}-*.run.app audiences
    for valid_aud in (
        "https://quicksand.example.com",
        "https://quicksand.example.com/search",
        "https://quicksand-combined-xyz987-uc.a.run.app",
        "https://quicksand-combined-12345.us-central1.run.app/analyze",
    ):
        for valid_iss in ("https://accounts.google.com", "accounts.google.com"):
            claims_box.clear()
            claims_box.update(
                {
                    "iss": valid_iss,
                    "aud": valid_aud,
                    "email": "caller-sa@qs-prod-proj.iam.gserviceaccount.com",
                    "email_verified": True,
                }
            )
            req_ok = _FakeRequest(
                method="GET",
                path="/search",
                args={"query": "b" * 64},
                headers={"Authorization": "Bearer good-token", "Host": "attacker.evil"},
            )
            st_ok, _, _ = _resp_json(crm.quicksand_combined(req_ok))
            assert st_ok == 404  # Passed auth -> reached handle_search (404 not found)

    # Disallowed audience (even if matching spoofed Host header!) -> 401
    claims_box.update({"aud": "https://attacker.evil/search"})
    req_bad_aud = _FakeRequest(
        method="GET",
        path="/search",
        args={"query": "b" * 64},
        headers={"Authorization": "Bearer good-token", "Host": "attacker.evil"},
    )
    st_aud, _, _ = _resp_json(crm.quicksand_combined(req_bad_aud))
    assert st_aud == 401

    # Invalid issuer -> 401
    claims_box.update({"iss": "https://evil-idp.com", "aud": "https://quicksand.example.com"})
    st_iss, _, _ = _resp_json(crm.quicksand_combined(req_bad_aud))
    assert st_iss == 401

    # Personal email or cross-project SA or unverified email -> 403
    for bad_principal in (
        {"email": "user@gmail.com", "email_verified": True},
        {"email": "tyler@tylabs.com", "email_verified": True},
        {"email": "caller@other-project.iam.gserviceaccount.com", "email_verified": True},
        {"email": "caller-sa@qs-prod-proj.iam.gserviceaccount.com", "email_verified": False},
    ):
        claims_box.clear()
        claims_box.update(
            {
                "iss": "https://accounts.google.com",
                "aud": "https://quicksand.example.com",
                **bad_principal,
            }
        )
        st_p, _, _ = _resp_json(crm.quicksand_combined(req_bad_aud))
        assert st_p == 403

    # 4. Local-dev HMAC (K_SERVICE unset): bound to {ts}.{METHOD}.{path_and_query}.{body}
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.setenv("QS_REQUIRE_AUTH", "1")
    body_bytes = b'{"hello":"world"}'
    ts_dev = str(int(time.time()))
    dev_canon = f"{ts_dev}.POST./search?query={'c' * 64}.".encode("utf-8") + body_bytes
    dev_sig = hmac.new(b"super-secret-dev-key", dev_canon, hashlib.sha256).hexdigest()

    dev_req = _FakeRequest(
        method="POST",
        path="/search",
        args={"query": "c" * 64},
        headers={"X-QS-Timestamp": ts_dev, "X-QS-Signature": f"sha256={dev_sig}"},
        body=body_bytes,
    )
    st_dev_ok, _, _ = _resp_json(crm.quicksand_combined(dev_req))
    assert st_dev_ok == 404  # Authenticated!

    # Tampering method, query, or body invalidates HMAC -> 401
    tampered_body_req = _FakeRequest(
        method="POST",
        path="/search",
        args={"query": "c" * 64},
        headers={"X-QS-Timestamp": ts_dev, "X-QS-Signature": dev_sig},
        body=b'{"hello":"tampered"}',
    )
    st_tamp, _, _ = _resp_json(crm.quicksand_combined(tampered_body_req))
    assert st_tamp == 401


def test_subprocess_hard_timeout_and_large_pipe_no_deadlock(monkeypatch):
    crm = _load_cloud_run_main()

    # 1. Hung worker ignoring SIGALRM is killed cleanly by hard timeout -> returns ("timeout", ...)
    t0 = time.monotonic()
    status_to, rt_to, _ = crm.run_quicksand_isolated(
        b"dummy",
        file_uuid="hang-test",
        hard_timeout_sec=0.8,
        worker_fn=_hung_worker_ignoring_sigalrm,
    )
    elapsed = time.monotonic() - t0
    assert status_to == "timeout"
    assert rt_to is None
    assert elapsed < 12.0

    # 2. Large (>512 KB) IPC payload drains Queue before proc.join() without deadlocking
    status_lg, rt_lg, _ = crm.run_quicksand_isolated(
        b"dummy",
        file_uuid="large-pipe-test",
        hard_timeout_sec=15.0,
        worker_fn=_large_payload_worker,
    )
    assert status_lg == "ok"
    assert rt_lg is not None and len(rt_lg) > 512 * 1024

    # 3. End-to-end /analyze returns HTTP 504 on worker timeout and caches SHA-256/SHA-512 only on success
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.setenv("QS_REQUIRE_AUTH", "0")
    store = {
        "new/doc-123": {
            "data": b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n",
            "metadata": {"original-filename": "../../invoice.pdf\r\n", "ip": "203.0.113.7"},
        }
    }
    monkeypatch.setattr(crm, "qs_bucket_name", "confidential-bucket-id")
    monkeypatch.setattr(crm, "storage_client", _FakeStorageClient(store))

    req_an = _FakeRequest(method="GET", path="/analyze", args={"uuid": "doc-123"})
    st_an, body_an, _ = _resp_json(crm.quicksand_combined(req_an))
    assert st_an == 200
    assert body_an["filename"] == "invoice.pdf"
    # Informational md5 & sha1 remain inside JSON body
    assert len(body_an["md5"]) == 32
    assert len(body_an["sha1"]) == 40
    sha256_hex = body_an["sha256"]
    sha512_hex = body_an["sha512"]

    # Cache keys: ONLY sha256 and sha512 exist; NO md5 or sha1 objects!
    assert f"report/{sha256_hex}.json" in store
    assert f"report/{sha512_hex}.json" in store
    assert f"report/{body_an['md5']}.json" not in store
    assert f"report/{body_an['sha1']}.json" not in store

    # SHA-512 cache object is a lightweight _alias_sha256 pointer resolved by /search
    alias_doc = json.loads(store[f"report/{sha512_hex}.json"]["data"].decode("utf-8"))
    assert alias_doc == {"_alias_sha256": sha256_hex}

    # /search resolves both 64-char SHA-256 and 128-char SHA-512, and rejects 32-char MD5 & 40-char SHA-1
    for valid_q in (sha256_hex, sha512_hex):
        st_s, body_s, _ = _resp_json(crm.quicksand_combined(_FakeRequest("GET", "/search", args={"query": valid_q})))
        assert st_s == 200
        assert body_s["sha256"] == sha256_hex

    for weak_q in (body_an["md5"], body_an["sha1"]):
        st_w, _, _ = _resp_json(crm.quicksand_combined(_FakeRequest("GET", "/search", args={"query": weak_q})))
        assert st_w == 400

    # Poisoned _alias_sha256 pointing to MD5 or another alias is refused
    bad_sha512 = "f" * 128
    store[f"report/{bad_sha512}.json"] = {
        "data": json.dumps({"_alias_sha256": body_an["md5"]}).encode("utf-8")
    }
    st_p, _, _ = _resp_json(crm.quicksand_combined(_FakeRequest("GET", "/search", args={"query": bad_sha512})))
    assert st_p == 404

    # Verify /analyze returns HTTP 504 when isolated worker exceeds hard timeout
    monkeypatch.setattr(crm, "run_quicksand_isolated", lambda *a, **kw: ("timeout", None, False))
    st_504, body_504, _ = _resp_json(
        crm.quicksand_combined(_FakeRequest("GET", "/analyze", args={"uuid": "doc-123", "rerun": "1"}))
    )
    assert st_504 == 504
    assert body_504["error"] == "timeout"


def test_upload_signing_xff_header_sanitization_and_error_hygiene(monkeypatch):
    crm = _load_cloud_run_main()
    store = {}
    monkeypatch.setattr(crm, "qs_bucket_name", "top-secret-prod-bucket-99")
    monkeypatch.setattr(crm, "storage_client", _FakeStorageClient(store))

    class _DummyCreds:
        valid = True
        expired = False
        token = "ya29.dummy"
        service_account_email = "signer@qs-prod-proj.iam.gserviceaccount.com"

    monkeypatch.setattr(crm, "credentials", _DummyCreds())
    monkeypatch.setattr(crm, "project_id", "qs-prod-proj")
    monkeypatch.setenv("QS_URL", "https://quicksand.example.com/analyze")
    monkeypatch.setenv("K_SERVICE", "quicksand-combined")
    monkeypatch.setattr(
        crm.google_id_token,
        "verify_oauth2_token",
        lambda _tok, _req: {
            "iss": "https://accounts.google.com",
            "aud": "https://quicksand.example.com",
            "email": "caller@qs-prod-proj.iam.gserviceaccount.com",
            "email_verified": True,
        },
    )

    # Behind Cloud Run GFE, parts[-2] is selected from X-Forwarded-For and non-IP chars stripped
    up_req = _FakeRequest(
        method="GET",
        path="/upload",
        args={
            "filename": "..\\..\\evil_dir/mal\x00\r\n\x7fware.docm",
            "contentType": "application/msword\r\nX-Injected: 1",
            "maxBytes": "1048576",
        },
        headers={
            "Authorization": "Bearer valid",
            "X-Forwarded-For": "10.9.8.7, 203.0.113.55<script>, 34.107.200.1",
        },
    )
    st_up, body_up, raw_up = _resp_json(crm.quicksand_combined(up_req))
    assert st_up == 200
    assert body_up["meta"]["submitter_ip"] == "203.0.113.55"
    assert body_up["meta"]["original_filename"] == "malware.docm"
    assert body_up["meta"]["content_length_range"] == "0,1048576"

    _, signed_kwargs = store["_signed_calls"][-1]
    signed_headers = signed_kwargs["headers"]
    assert signed_headers["x-goog-meta-ip"] == "203.0.113.55"
    assert signed_headers["x-goog-meta-original-filename"] == "malware.docm"
    assert signed_headers["x-goog-content-length-range"] == "0,1048576"
    assert "\r" not in signed_headers["content-type"] and "\n" not in signed_headers["content-type"]
    assert "top-secret-prod-bucket-99" not in raw_up

    # Verify 404 and 500 error responses never leak bucket name or raw Python exception strings
    miss_req = _FakeRequest(
        method="GET",
        path="/analyze",
        args={"uuid": "missing-file-id"},
        headers={"Authorization": "Bearer valid"},
    )
    st_404, _, raw_404 = _resp_json(crm.quicksand_combined(miss_req))
    assert st_404 == 404
    assert "top-secret-prod-bucket-99" not in raw_404
    assert "secret-internal-bucket-name" not in raw_404

    class _ExplodingClient:
        def bucket(self, _name):
            raise RuntimeError("GCS internal failure on gs://top-secret-prod-bucket-99/key")

    monkeypatch.setattr(crm, "storage_client", _ExplodingClient())
    st_500, _, raw_500 = _resp_json(crm.quicksand_combined(up_req))
    assert st_500 == 500
    assert "top-secret-prod-bucket-99" not in raw_500
    assert "GCS internal failure" not in raw_500


def test_core_worker_thread_timeout_and_decompression_bomb_caps():
    import gzip
    import threading

    # 1. Running QuickSand with timeout>0 inside a worker thread must NEVER raise ValueError
    thread_err = []
    thread_res = {}

    def _thread_runner():
        try:
            q = qs_cls(
                b"%PDF-1.5\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n%%EOF",
                timeout=3,
            )
            q.process()
            thread_res.update(q.results)
        except BaseException as exc:
            thread_err.append(exc)

    t = threading.Thread(target=_thread_runner)
    t.start()
    t.join(timeout=5.0)
    assert not thread_err, f"Unexpected exception in worker thread: {thread_err}"
    assert thread_res.get("score", 0) > 0

    # 2. _bounded_zlib_decompress & _pdf_flate_decode strictly cap multi-MB bombs without flush() blowup
    bomb_raw = b"Z" * (4 * 1024 * 1024)
    bomb_z = zlib.compress(bomb_raw, zlib.Z_BEST_SPEED)
    dec_slice, was_trunc = qm._bounded_zlib_decompress(bomb_z, max_output=8192)
    assert len(dec_slice) == 8192
    assert was_trunc is True
    assert len(qm._pdf_flate_decode(bomb_z, max_output=4096)) == 4096

    # 3. GZIP container bomb is unpacked and capped strictly at max_total_bytes
    gz_bomb = gzip.compress(b"%PDF-1.4\n" + (b"A" * (512 * 1024)))
    q_gz = qs_cls(gz_bomb, capture=True, max_total_bytes=16384, timeout=5)
    q_gz.process()
    assert q_gz.results.get("skip") == 1
    assert len(q_gz.results["streams"].get("root-gunzip", b"")) <= 16384

    # 4. ZIP LZMA entry declaring 1 GB dictionary size is blocked before liblzma allocation
    lzma_hdr = struct.pack("<BBHBI", 9, 20, 5, 0x5D, 0x40000000) + b"\x00" * 16
    fname = b"bomb.bin"
    lh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 63, 0, 14, 0, 0, 0, len(lzma_hdr), 100, len(fname), 0)
    cd = struct.pack(
        "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 63, 63, 0, 14, 0, 0, 0, len(lzma_hdr), 100, len(fname), 0, 0, 0, 0, 0, 0
    )
    eocd = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(cd) + len(fname), len(lh) + len(fname) + len(lzma_hdr), 0
    )
    q_lzma = qs_cls(lh + fname + lzma_hdr + cd + fname + eocd, capture=False, timeout=5)
    q_lzma.process()
    assert q_lzma.results.get("skip") == 1
    assert any(
        hit["rule"] == "zip_lzma_dict_exceeded"
        for hits in q_lzma.results["results"].values()
        for hit in hits
    )

    # 5. MS Cabinet (.cab) declared uncompressed size bomb & MSZIP extraction are capped
    cab_payload = b"MZ" + (b"\x90" * 4096)
    raw_deflate = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
    ck_block = b"CK" + raw_deflate.compress(cab_payload) + raw_deflate.flush()
    cab_fname = b"dropper.exe\x00"
    coff_files = 36 + 8
    coff_data = coff_files + 16 + len(cab_fname)
    cfdata = struct.pack("<IHH", 0, len(ck_block), len(cab_payload)) + ck_block
    cab_total_len = coff_data + len(cfdata)
    cfheader = struct.pack(
        "<4sIIIIIBBHHHHH",
        b"MSCF",
        0,
        cab_total_len,
        0,
        coff_files,
        0,
        3,
        1,
        1,
        1,
        0,
        0,
        0,
    )
    cffolder = struct.pack("<IHH", coff_data, 1, 1)  # TCOMP_TYPE_MSZIP = 1
    cffile = struct.pack("<IIHHHH", 50 * 1024 * 1024, 0, 0, 0, 0, 0x20) + cab_fname  # claims 50 MB
    cab_bytes = cfheader + cffolder + cffile + cfdata
    q_cab = qs_cls(cab_bytes, capture=True, max_total_bytes=2048, timeout=5)
    q_cab.process()
    assert q_cab.results.get("skip") == 1
    assert b"dropper.exe" in q_cab.results["streams"].get("root-cab_filenames", b"")

    # 6. XML Billion Laughs smuggling invalid UTF-8 bytes (<!DOC\xffTYPE / <!ENT\xffITY) is blocked
    smuggled_xml = (
        b'<?xml version="1.0"?>'
        b'<!DOC\xffTYPE lolz [<!ENT\xffITY lol "lol"><!ENT\xffITY lol2 "&lol;&lol;">]>'
        b"<encryption>&lol2;</encryption>"
    )
    assert qm._safe_parse_xml_bytes(smuggled_xml) is None


def test_dockerfiles_requirements_and_frontend_xss_hardening():
    repo_root = Path(__file__).resolve().parents[1]

    # 1. Verify Dockerfiles create & switch to non-root UID 10001 with /sbin/nologin
    for df_rel in ("gcloud/function/Dockerfile", "lambda/Dockerfile"):
        df_text = (repo_root / df_rel).read_text(encoding="utf-8")
        assert "10001" in df_text, f"{df_rel} missing UID 10001"
        assert "/sbin/nologin" in df_text, f"{df_rel} missing /sbin/nologin"
        assert "USER 10001" in df_text, f"{df_rel} missing USER 10001"

    # 2. Verify requirements.txt files pin upper & lower version bounds
    for req_rel in ("requirements.txt", "gcloud/function/requirements.txt"):
        lines = [
            ln.strip()
            for ln in (repo_root / req_rel).read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        assert lines, f"{req_rel} is empty"
        for req_line in lines:
            assert ">=" in req_line and "<" in req_line, f"Unbounded dependency in {req_rel}: {req_line}"

    # 3. Verify frontend quicksand.js files escape all untrusted fields & link /search by SHA-256 (not MD5)
    for js_rel in ("gcloud/frontend/js/quicksand.js", "lambda/html_js/js/quicksand.js"):
        js_text = (repo_root / js_rel).read_text(encoding="utf-8")
        assert "function escapeHtml(" in js_text
        assert "function safeHref(" in js_text
        assert "r['md5'] || \"\") + \"\\\">json" not in js_text
        assert "r['sha256']" in js_text
        for must_escape in (
            "escapeHtml(baseName(r['filename']))",
            "escapeHtml(r['type'])",
            "escapeHtml(hit[\"rule\"])",
            "escapeHtml(hit[\"desc\"])",
            "escapeHtml(techId)",
            "escapeHtml(technique)",
            "escapeHtml(identifier)",
            "escapeHtml(data)",
        ):
            assert must_escape in js_text, f"{js_rel} missing {must_escape}"


class _SimpleMonkeyPatch:
    def __init__(self):
        self._undo = []
        self._env_undo = []

    def setattr(self, obj, name, value):
        orig = getattr(obj, name)
        self._undo.append((obj, name, orig))
        setattr(obj, name, value)

    def setenv(self, name, value):
        import os

        had = name in os.environ
        orig = os.environ.get(name)
        self._env_undo.append((name, had, orig))
        os.environ[name] = str(value)

    def delenv(self, name, raising=True):
        import os

        had = name in os.environ
        orig = os.environ.get(name)
        if not had and raising:
            raise KeyError(name)
        self._env_undo.append((name, had, orig))
        os.environ.pop(name, None)

    def restore(self):
        import os

        for obj, name, orig in reversed(self._undo):
            setattr(obj, name, orig)
        self._undo.clear()
        for name, had, orig in reversed(self._env_undo):
            if had:
                os.environ[name] = orig
            else:
                os.environ.pop(name, None)
        self._env_undo.clear()


if __name__ == "__main__":
    ran = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            mp = _SimpleMonkeyPatch()
            try:
                if "monkeypatch" in inspect.signature(fn).parameters:
                    fn(mp)
                else:
                    fn()
                print(f"PASS: {name}")
                ran += 1
            finally:
                mp.restore()
    print(f"All {ran} test functions passed.")
