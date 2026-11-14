import importlib
import io
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
