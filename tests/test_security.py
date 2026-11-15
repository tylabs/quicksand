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

    monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", True)
    ecb_fast = qm._aes_ecb_decrypt(key, ciphertext)
    cbc_fast = qm._aes_cbc_decrypt(key, iv, ciphertext)

    monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", False)
    ecb_py = qm._aes_ecb_decrypt(key, ciphertext)
    cbc_py = qm._aes_cbc_decrypt(key, iv, ciphertext)

    assert ecb_fast == ecb_py
    assert cbc_fast == cbc_py

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


def test_aes_encrypt_and_ctr_parity(monkeypatch):
    for key_len in (16, 24, 32):
        key = bytes((i * 11 + 5) & 0xFF for i in range(key_len))
        rks = qm._aes_expand_key(key)
        blk = bytes(range(16))
        enc = qm._aes_encrypt_block(blk, rks)
        assert qm._aes_decrypt_block(enc, rks) == blk

        payload = bytes((i * 29 + 7) & 0xFF for i in range(1500))
        monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", True)
        ctr_fast = qm._aes_ctr_le_crypt(key, payload, start_counter=1)
        monkeypatch.setattr(qm, "_HAS_CRYPTOGRAPHY", False)
        ctr_py = qm._aes_ctr_le_crypt(key, payload, start_counter=1)
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
    # 1. Legacy PKWARE ZipCrypto archive created via system `zip -P infected1`
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        inner_file = tmp_path / "payload.pdf"
        inner_file.write_bytes(sample_pdf)
        zip_out = tmp_path / "protected_zipcrypto.zip"
        subprocess.run(
            ["zip", "-q", "-P", "infected1", str(zip_out), "payload.pdf"],
            cwd=str(tmp_path),
            check=True,
        )
        zipcrypto_bytes = zip_out.read_bytes()

    q_zc = qs_cls(zipcrypto_bytes, capture=True, timeout=5)
    q_zc.process()
    assert q_zc.results.get("archive_decrypted") is True
    assert not q_zc.results.get("encrypted_unreadable")
    assert q_zc.results["streams"]["root-payload.pdf"] == sample_pdf
    assert q_zc.results["archive_entries"][0]["sha256"] == hashlib.sha256(sample_pdf).hexdigest()
    assert q_zc.results["archive_entries"][0]["decrypted"] is True

    # 2. WinZip AES-256 (AE-2, deflated) & AES-128 (AE-1, stored) under both crypto backends
    aes256_zip = _build_winzip_aes_zip(
        [("doc1.pdf", sample_pdf), ("nested.cart", _build_cart_bytes(sample_pdf, {"name": "inner.pdf"}))],
        password="infected1",
        strength=3,
        ae_version=2,
        compress=True,
    )
    for use_crypto in (True, False):
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

    # 3. WinZip AES bomb capped by max_total_bytes
    aes_bomb = _build_winzip_aes_zip(
        [("huge.xml", b"<x>" + (b"B" * 200000) + b"</x>")],
        password="infected",
        strength=3,
        compress=True,
    )
    q_aes_bomb = qs_cls(aes_bomb, capture=True, max_total_bytes=32 * 1024, timeout=5)
    q_aes_bomb.process()
    assert q_aes_bomb.results.get("skip") == 1


class _SimpleMonkeyPatch:
    def __init__(self):
        self._undo = []

    def setattr(self, obj, name, value):
        orig = getattr(obj, name)
        self._undo.append((obj, name, orig))
        setattr(obj, name, value)

    def restore(self):
        for obj, name, orig in reversed(self._undo):
            setattr(obj, name, orig)
        self._undo.clear()


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
