### QuickSand 2: Python3 Version Copyright (c) 2021-2026 @tylabs
### Lambda function for AWS to process a document with quicksand

from datetime import datetime, timedelta
import hashlib
import json
import multiprocessing as mp
import os
import queue
import re
import sys
import time
import traceback

import boto3
import botocore
import config

MAX_UPLOAD_BYTES = int(os.environ.get("QS_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
HARD_TIMEOUT_SEC = max(1.0, float(os.environ.get("QS_HARD_TIMEOUT_SEC", "25")))
RE_SHA256 = re.compile(r"^[a-f0-9]{64}$")
RE_SHA512 = re.compile(r"^[a-f0-9]{128}$")
RE_STRONG_HASH = re.compile(r"^(?:[a-f0-9]{64}|[a-f0-9]{128})$")

try:
    from quicksand.quicksand import BytesDump, keys_string, quicksand
except ImportError:
    from quicksand import quicksand

    class BytesDump(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, bytes):
                return obj.decode(errors="replace")
            return super().default(obj)

    def keys_string(d):
        if not isinstance(d, dict):
            if isinstance(d, (tuple, list, set)):
                return [keys_string(x) for x in d]
            return d
        rval = {}
        for k, v in d.items():
            if isinstance(k, bytes):
                k = k.decode(errors="replace")
            if isinstance(v, dict):
                v = keys_string(v)
            elif isinstance(v, (tuple, list, set)):
                v = [keys_string(x) for x in v]
            rval[str(k)] = v
        return rval


def _sanitize_filename(raw_filename):
    if not raw_filename:
        return ""
    cleaned = re.sub(r"[\x00-\x1f\x7f\r\n]", "", str(raw_filename))
    base = re.split(r"[/\\]", cleaned)[-1].replace("/", "").replace("\\", "").strip()
    if not base or base in (".", ".."):
        return ""
    return base[:255]


def getFile(file_uuid):
    print(f"{time.time()} download file: {file_uuid}")
    try:
        obj = config.boto_s3.get_object(Bucket=config.qs_bucket, Key="new/" + file_uuid)
        content_len = obj.get("ContentLength")
        if isinstance(content_len, int) and content_len > MAX_UPLOAD_BYTES:
            print(f"Error: S3 object {file_uuid} size {content_len} exceeds MAX_UPLOAD_BYTES ({MAX_UPLOAD_BYTES})")
            return None, "oversize"
        raw = obj["Body"].read(MAX_UPLOAD_BYTES + 1)
        if len(raw) > MAX_UPLOAD_BYTES:
            print(f"Error: S3 stream {file_uuid} exceeded MAX_UPLOAD_BYTES ({MAX_UPLOAD_BYTES})")
            return None, "oversize"
        data = raw
    except Exception as e:
        print(f"Error downloading file {file_uuid}: {e}")
        return None, ""

    filename = ""
    meta = obj.get("Metadata") or {}
    if meta:
        raw_fn = (
            meta.get("filename")
            or meta.get("original-filename")
            or meta.get("original_filename")
            or ""
        )
        filename = _sanitize_filename(raw_fn)
    print(f"{time.time()} got file")
    return data, filename


def cacheReport(sha256, sha512, data):
    sha256_norm = (sha256 or "").strip().lower()
    sha512_norm = (sha512 or "").strip().lower()
    if not RE_SHA256.fullmatch(sha256_norm):
        return
    try:
        config.boto_s3.put_object(
            Bucket=config.qs_bucket,
            Key=f"report/{sha256_norm}.json",
            Body=data,
            ContentType="application/json",
        )
        print(f"{time.time()} cached report: {sha256_norm} (sha256)")
        if RE_SHA512.fullmatch(sha512_norm):
            config.boto_s3.put_object(
                Bucket=config.qs_bucket,
                Key=f"report/{sha512_norm}.json",
                Body=json.dumps({"_alias_sha256": sha256_norm}),
                ContentType="application/json",
            )
            print(f"{time.time()} cached SHA-512 alias pointer: {sha512_norm}")
    except Exception as e:
        print(f"Error caching report {sha256_norm}: {e}")


def checkReportRecent(hash_val):
    norm = (hash_val or "").strip().lower()
    if not RE_STRONG_HASH.fullmatch(norm):
        return False
    try:
        last_date_time = datetime.now() - timedelta(days=6)
        config.boto_s3.head_object(
            Bucket=config.qs_bucket,
            Key=f"report/{norm}.json",
            IfModifiedSince=last_date_time,
        )
        return True
    except Exception:
        return False


def getReport(hash_val):
    norm = (hash_val or "").strip().lower()
    if not RE_STRONG_HASH.fullmatch(norm):
        return None
    print(f"{time.time()} download report: {norm}")
    try:
        obj = config.boto_s3.get_object(
            Bucket=config.qs_bucket,
            Key=f"report/{norm}.json",
        )
        data = obj["Body"].read().decode("utf-8")
        try:
            parsed = json.loads(data)
        except Exception:
            parsed = None
        if isinstance(parsed, dict) and "_alias_sha256" in parsed:
            alias_target = str(parsed.get("_alias_sha256") or "").strip().lower()
            if not RE_SHA256.fullmatch(alias_target):
                return None
            target_obj = config.boto_s3.get_object(
                Bucket=config.qs_bucket,
                Key=f"report/{alias_target}.json",
            )
            target_data = target_obj["Body"].read().decode("utf-8")
            target_parsed = json.loads(target_data)
            if isinstance(target_parsed, dict) and "_alias_sha256" in target_parsed:
                return None
            return target_data
        print(f"{time.time()} got report: {norm}")
        return data
    except Exception as e:
        print(f"Error getting report {norm}: {e}")
        return None


def _lambda_worker(
    out_queue,
    data,
    password,
    inner_timeout,
    filename,
    file_uuid,
    md5,
    sha1,
    sha256,
    sha512,
):
    try:
        qs = quicksand(
            data,
            timeout=inner_timeout,
            strings=True,
            capture=False,
            password=password,
            max_total_bytes=64 * 1024 * 1024,
        )
        qs.process()
        qs.results["filename"] = filename
        qs.results["uuid"] = file_uuid
        qs.results.setdefault("md5", md5)
        qs.results.setdefault("sha1", sha1)
        qs.results.setdefault("sha256", sha256)
        qs.results.setdefault("sha512", sha512)
        qs.results.setdefault("size", len(data))

        processed_results = keys_string(qs.results)
        rt = json.dumps(processed_results, cls=BytesDump)
        out_queue.put(("ok", rt, bool(qs.results.get("encrypted_unreadable"))))
    except Exception as e:
        print(f"Worker exception analyzing {file_uuid}: {e}")
        traceback.print_exc()
        try:
            out_queue.put(("error", "", False))
        except Exception:
            pass


def _run_isolated(data, password, filename, file_uuid, md5, sha1, sha256, sha512):
    available = mp.get_all_start_methods()
    ctx = (
        mp.get_context("fork")
        if (sys.platform.startswith("linux") and "fork" in available)
        else mp.get_context("spawn")
    )
    effective_hard = max(0.5, float(os.environ.get("QS_HARD_TIMEOUT_SEC", str(HARD_TIMEOUT_SEC))))
    inner_timeout = max(1, min(18, int(max(1.0, effective_hard - 4.0))))

    out_q = ctx.Queue(maxsize=1)
    proc = ctx.Process(
        target=_lambda_worker,
        args=(out_q, data, password, inner_timeout, filename, file_uuid, md5, sha1, sha256, sha512),
        daemon=True,
    )
    deadline = time.monotonic() + effective_hard
    res = None
    try:
        proc.start()
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                break
            try:
                res = out_q.get(timeout=min(0.2, rem))
                break
            except queue.Empty:
                if not proc.is_alive():
                    try:
                        res = out_q.get_nowait()
                    except queue.Empty:
                        pass
                    break
        if res is None:
            if proc.is_alive() or time.monotonic() >= deadline:
                try:
                    proc.kill()
                except Exception:
                    pass
                proc.join(timeout=2.0)
                return "timeout", None, False
            proc.join(timeout=1.0)
            return "error", None, False
        proc.join(timeout=2.0)
        return res
    finally:
        if proc.is_alive():
            try:
                proc.kill()
            except Exception:
                pass
            proc.join(timeout=1.0)
        try:
            out_q.close()
            out_q.cancel_join_thread()
        except Exception:
            pass


def lambda_handler(event, context):
    params = (event or {}).get("queryStringParameters") or {}
    file_uuid = (params.get("uuid") or "").strip()
    rerun_arg = str(params.get("rerun") or "").lower()
    rerun = rerun_arg in ("1", "true")
    raw_password = params.get("password")
    password = raw_password[:256] if isinstance(raw_password, str) and raw_password != "" else None

    if not file_uuid:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "uuid is missing"}),
        }

    if len(file_uuid) > 128 or not re.fullmatch(r"[a-zA-Z0-9._-]+", file_uuid) or ".." in file_uuid:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "invalid uuid parameter"}),
        }

    try:
        print("getting uuid=" + str(file_uuid))
        data, filename = getFile(file_uuid)
        if data is None:
            if filename == "oversize":
                return {
                    "statusCode": 413,
                    "body": json.dumps({"error": "uploaded file exceeds maximum allowed size", "uuid": str(file_uuid)}),
                }
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "file not found", "uuid": str(file_uuid)}),
            }

        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()

        if not rerun and password is None and checkReportRecent(sha256):
            print("getting cached report for " + str(sha256))
            report = getReport(sha256)
            if report:
                try:
                    cached_obj = json.loads(report)
                except Exception:
                    cached_obj = {}
                if not cached_obj.get("encrypted_unreadable"):
                    return {
                        "statusCode": 200,
                        "body": report,
                    }
                print("cached report for " + str(sha256) + " was encrypted_unreadable; re-running")
        else:
            print("no cached report for " + str(sha256))

        print(str(time.time()) + " qs isolated subprocess start")
        status, rt, encrypted_unreadable = _run_isolated(
            data, password, filename, file_uuid, md5, sha1, sha256, sha512
        )
        print(str(time.time()) + " qs isolated subprocess end status=" + str(status))

        if status == "timeout":
            return {
                "statusCode": 504,
                "body": json.dumps({"error": "timeout", "message": "Analysis timed out", "uuid": str(file_uuid)}),
            }
        if status != "ok" or not rt:
            return {
                "statusCode": 500,
                "body": json.dumps({"error": "exception", "message": "Internal analysis error", "uuid": str(file_uuid)}),
            }

        if not encrypted_unreadable:
            cacheReport(sha256, sha512, rt)
        else:
            print("skipping cache for encrypted_unreadable container " + str(sha256))
        return {
            "statusCode": 200,
            "body": rt,
        }
    except Exception as e:
        print(f"Exception analyzing {file_uuid}: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "exception", "message": "Internal analysis error", "uuid": str(file_uuid)}),
        }
