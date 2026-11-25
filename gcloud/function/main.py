"""
QuickSand GCP Cloud Run Function - Combined Service
Copyright (c) 2025-2026 Tyler McLellan / @tylabs
Website: https://tylabs.com

This service combines three QuickSand services into one:
1. File Signing Service - Generates signed URLs for secure file uploads (/upload)
2. Analysis Service - Processes files using the QuickSand engine (/analyze)
3. Search Service - Searches for previously analyzed files (/search)

Environment Variables:
- QS_BUCKET: The GCS bucket name for storing uploaded files and reports
- QS_URL: The base URL for the QuickSand analysis service (used in OIDC audience allowlist)
- QS_ALLOWED_AUDIENCES: Optional comma-separated list of additional allowed OIDC audience URLs
- QS_KMS_KEY: Optional KMS key resource name for Customer-Managed Encryption Keys (CMEK)
- QS_REQUIRE_AUTH: Require auth outside Cloud Run ("1" default; ignored when K_SERVICE is set)
- QS_HMAC_SECRET: Optional local-dev-only HMAC secret (disabled whenever K_SERVICE is set)
- QS_HARD_TIMEOUT_SEC: Hard subprocess wall-clock timeout in seconds (default: 25)

Function Entry Point:
- quicksand_combined (or main)
"""

from datetime import datetime, timedelta
import hashlib
import hmac
import ipaddress
import json
import multiprocessing as mp
import os
import queue
import re
import sys
import time
import traceback
import urllib.parse
import uuid

try:
    from flask import Response, jsonify, request
    import functions_framework
    import google.auth
    from google.auth.transport import requests as google_auth_requests
    from google.cloud import storage
    from google.oauth2 import id_token as google_id_token
except ImportError:
    if (os.environ.get("K_SERVICE") or "").strip():
        raise

    class _HeadersDict(dict):
        def extend(self, other):
            self.update(other)

    class Response:  # type: ignore[no-redef]
        def __init__(self, response=b"", status=200, headers=None, mimetype="text/plain"):
            if isinstance(response, bytes):
                self.data = response
            else:
                self.data = str(response).encode("utf-8")
            self.status_code = status
            self.headers = _HeadersDict(headers or {})
            self.mimetype = mimetype

        def get_data(self, as_text=False):
            return self.data.decode("utf-8", errors="replace") if as_text else self.data

    def jsonify(payload):  # type: ignore[misc]
        return Response(json.dumps(payload), status=200, mimetype="application/json")

    request = None  # type: ignore[assignment]

    class _FunctionsFrameworkStub:
        @staticmethod
        def http(fn):
            return fn

    functions_framework = _FunctionsFrameworkStub()  # type: ignore[assignment]
    google = None  # type: ignore[assignment]
    google_auth_requests = None  # type: ignore[assignment]
    storage = None  # type: ignore[assignment]

    class _IdTokenStub:
        @staticmethod
        def verify_oauth2_token(*_args, **_kwargs):
            raise RuntimeError("google-auth is not installed")

    google_id_token = _IdTokenStub()  # type: ignore[assignment]

# Import quicksand module and JSON helpers
try:
    from quicksand.quicksand import BytesDump, keys_string, quicksand
except ImportError:
    _repo_src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    if os.path.isdir(os.path.join(_repo_src, "quicksand")) and _repo_src not in sys.path:
        sys.path.insert(0, _repo_src)
    try:
        from quicksand.quicksand import BytesDump, keys_string, quicksand
    except ImportError:
        try:
            from quicksand import quicksand
        except ImportError:
            print("Error: quicksand module not found. Please ensure it's installed in requirements.txt")
            raise

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


# --- Constants & Regexes ---
VALID_OIDC_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
RE_K_SERVICE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
ALLOWED_SERVICE_PATHS = ("", "/upload", "/analyze", "/search", "/health")

RE_SHA256 = re.compile(r"^[a-f0-9]{64}$")
RE_SHA512 = re.compile(r"^[a-f0-9]{128}$")
RE_STRONG_HASH = re.compile(r"^(?:[a-f0-9]{64}|[a-f0-9]{128})$")
RE_UUID_SAFE = re.compile(r"^[a-zA-Z0-9._-]+$")
RE_MIME_TYPE = re.compile(
    r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(?:\s*;\s*[A-Za-z0-9_.+-]+=[A-Za-z0-9_.+-]+)*$"
)
RE_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\r\n]")
RE_NON_IP_CHARS = re.compile(r"[^0-9a-fA-F.:]")
RE_SA_LOCAL_PART = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
RE_HEX_DIGEST = re.compile(r"^[a-f0-9]{64}$")


# --- Startup Configuration and Initialization ---
print("Function startup: Reading environment variables...")
qs_bucket_name = os.environ.get("QS_BUCKET")
qs_url_base = os.environ.get("QS_URL")
qs_cors_origin = os.environ.get("QS_CORS_ORIGIN", "*")
MAX_UPLOAD_BYTES = int(os.environ.get("QS_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
HARD_TIMEOUT_SEC = max(1.0, float(os.environ.get("QS_HARD_TIMEOUT_SEC", "25")))
HMAC_MAX_SKEW_SEC = max(1, int(os.environ.get("QS_HMAC_MAX_SKEW_SEC", "300")))

print(f"Config: QS_BUCKET configured={bool(qs_bucket_name)}")
print(f"Config: QS_URL={qs_url_base}")
qs_kms_key_name = os.environ.get("QS_KMS_KEY")
if qs_kms_key_name:
    print("Config: QS_KMS_KEY is set (using CMEK for server-side writes)")
else:
    print("Config: QS_KMS_KEY not set; will rely on bucket default encryption if configured.")

storage_client = None
credentials = None
project_id = None
_auth_transport_request = None

if google is not None and storage is not None:
    try:
        print("Attempting to get default credentials...")
        credentials, project_id = google.auth.default()
        print(f"Credentials obtained. Type: {type(credentials)}")
        print(f"Detected Project ID: {project_id}")
        storage_client = storage.Client(credentials=credentials, project=project_id)
        print("Storage client initialized successfully.")
    except Exception as e:
        print(f"FATAL ERROR during client initialization: {e}")
        traceback.print_exc()

if not qs_bucket_name:
    print("Warning: QS_BUCKET environment variable not set at startup. Operations will fail if triggered.")


def _get_auth_request():
    """Return a reusable Google Auth transport Request object."""
    global _auth_transport_request
    if _auth_transport_request is None and google_auth_requests is not None:
        _auth_transport_request = google_auth_requests.Request()
    return _auth_transport_request


def ensure_credentials():
    """Lazily refresh credentials only when invalid or expired."""
    global credentials
    if credentials is None:
        return None
    if (
        not getattr(credentials, "valid", False)
        or getattr(credentials, "expired", False)
        or not getattr(credentials, "token", None)
    ):
        credentials.refresh(_get_auth_request())
    return credentials


# --- Authentication & Authorization Helpers ---

def _is_cloud_run() -> bool:
    """Return True when running inside Google Cloud Run (K_SERVICE is set)."""
    return bool((os.environ.get("K_SERVICE") or "").strip())


def _is_auth_required() -> bool:
    """Determine whether authentication is enforced for incoming requests.

    Whenever K_SERVICE is set (Cloud Run), QS_REQUIRE_AUTH=0 is ignored so
    authentication can never be accidentally disabled in production.
    """
    raw = (os.environ.get("QS_REQUIRE_AUTH", "1") or "1").strip().lower()
    disabled_requested = raw in ("0", "false", "no", "off")
    if _is_cloud_run():
        if disabled_requested:
            print("SECURITY WARNING: Ignoring QS_REQUIRE_AUTH=0 because K_SERVICE is set.")
        return True
    return not disabled_requested


def _get_effective_project_id() -> str:
    """Resolve the active GCP project ID for service account validation."""
    resolved = (
        project_id
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT")
        or os.environ.get("GCLOUD_PROJECT")
        or ""
    )
    return str(resolved).strip().lower()


def _configured_service_urls() -> tuple:
    """Build explicit (allowed_origins, allowed_full_urls) sets without trusting Host headers."""
    origins = set()
    full_urls = set()

    candidates = []
    current_qs_url = os.environ.get("QS_URL") or qs_url_base
    if current_qs_url:
        candidates.append(current_qs_url)
    extra = os.environ.get("QS_ALLOWED_AUDIENCES", "")
    if extra:
        candidates.extend(part.strip() for part in extra.split(",") if part.strip())

    in_cloud_run = _is_cloud_run()
    for raw_url in candidates:
        parsed = urllib.parse.urlsplit(raw_url.strip())
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        if not netloc or parsed.username or parsed.password:
            continue
        if scheme != "https":
            if in_cloud_run or (parsed.hostname or "").lower() not in ("localhost", "127.0.0.1"):
                continue
        origin = f"{scheme}://{netloc}"
        norm_full = f"{origin}{parsed.path}".rstrip("/")
        origins.add(origin)
        full_urls.add(norm_full or origin)

    return origins, full_urls


def _matches_cloud_run_service_host(hostname: str) -> bool:
    """Match `{K_SERVICE}-*.run.app` derived from the trusted Cloud Run K_SERVICE env var."""
    k_service = (os.environ.get("K_SERVICE") or "").strip().lower()
    if not k_service or not RE_K_SERVICE_NAME.fullmatch(k_service):
        return False
    pattern = rf"^{re.escape(k_service)}-[a-z0-9-]+(?:\.[a-z0-9-]+)?\.run\.app$"
    return re.fullmatch(pattern, hostname) is not None


def _is_allowed_audience(aud) -> bool:
    """Validate OIDC `aud` (full URL or scheme+host origin) against explicit QuickSand URLs."""
    if not isinstance(aud, str):
        return False
    aud_clean = aud.strip()
    if not aud_clean or RE_CONTROL_CHARS.search(aud_clean) or " " in aud_clean:
        return False

    try:
        parsed = urllib.parse.urlsplit(aud_clean)
    except Exception:
        return False

    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    hostname = (parsed.hostname or "").lower()
    if not scheme or not netloc or not hostname:
        return False

    allowed_origins, allowed_full_urls = _configured_service_urls()
    origin = f"{scheme}://{netloc}"
    norm_full = f"{origin}{parsed.path}".rstrip("/") or origin
    norm_path = parsed.path.rstrip("/")

    is_origin_allowed = origin in allowed_origins or (
        scheme == "https" and netloc == hostname and _matches_cloud_run_service_host(hostname)
    )
    if not is_origin_allowed:
        return False

    if norm_full == origin or norm_full in allowed_full_urls:
        return True
    return norm_path in ALLOWED_SERVICE_PATHS


def _is_authorized_service_account(claims: dict) -> bool:
    """Restrict OIDC callers strictly to verified project service accounts."""
    if claims.get("email_verified") is not True:
        return False
    email = claims.get("email")
    if not isinstance(email, str):
        return False
    email_norm = email.strip().lower()
    if email_norm.count("@") != 1:
        return False

    eff_project = _get_effective_project_id()
    if not eff_project:
        print("Auth error: Project ID unavailable; denying OIDC service account check.")
        return False

    local_part, domain_part = email_norm.split("@", 1)
    expected_domain = f"{eff_project}.iam.gserviceaccount.com"
    if domain_part != expected_domain:
        return False
    return RE_SA_LOCAL_PART.fullmatch(local_part) is not None


def _verify_local_hmac(req) -> bool:
    """Verify request-bound HMAC signature in local development only (disabled on Cloud Run)."""
    if _is_cloud_run():
        return False
    secret = os.environ.get("QS_HMAC_SECRET") or ""
    if not secret:
        return False

    ts_raw = (req.headers.get("X-QS-Timestamp") or "").strip()
    sig_raw = (req.headers.get("X-QS-Signature") or "").strip()
    if not ts_raw or not sig_raw or not ts_raw.isdigit():
        return False

    try:
        ts_val = int(ts_raw)
    except ValueError:
        return False

    if abs(time.time() - ts_val) > HMAC_MAX_SKEW_SEC:
        print("HMAC auth rejected: timestamp outside allowed skew window.")
        return False

    if sig_raw.lower().startswith("sha256="):
        sig_raw = sig_raw[7:].strip()
    sig_norm = sig_raw.lower()
    if not RE_HEX_DIGEST.fullmatch(sig_norm):
        return False

    method_bytes = (req.method or "GET").upper().encode("utf-8")
    path_bytes = (req.path or "/").encode("utf-8")
    raw_qs = getattr(req, "query_string", b"") or b""
    if isinstance(raw_qs, str):
        raw_qs = raw_qs.encode("utf-8")
    path_and_query = path_bytes + (b"?" + raw_qs if raw_qs else b"")

    body_bytes = req.get_data(cache=True) or b""
    if isinstance(body_bytes, str):
        body_bytes = body_bytes.encode("utf-8")

    # Canonical message: {ts}.{METHOD}.{path_and_query}.{body}
    canonical = (
        ts_raw.encode("ascii")
        + b"."
        + method_bytes
        + b"."
        + path_and_query
        + b"."
        + body_bytes
    )
    expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig_norm, expected)


def verify_request_auth(req) -> tuple:
    """Authenticate an incoming HTTP request via OIDC Bearer token (or local-dev HMAC).

    Returns:
        (authorized: bool, status_code: int, error_message: str)
    """
    if not _is_auth_required():
        return True, 200, ""

    auth_header = (req.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        if not token:
            return False, 401, "Missing Bearer token"
        try:
            claims = google_id_token.verify_oauth2_token(token, _get_auth_request())
        except Exception as e:
            print(f"OIDC token verification failed: {e}")
            return False, 401, "Invalid or expired authentication token"

        if not isinstance(claims, dict):
            return False, 401, "Invalid authentication token claims"

        iss = claims.get("iss")
        if iss not in VALID_OIDC_ISSUERS:
            print(f"OIDC rejected: invalid issuer {iss!r}")
            return False, 401, "Invalid token issuer"

        aud = claims.get("aud")
        if not _is_allowed_audience(aud):
            print(f"OIDC rejected: disallowed audience {aud!r}")
            return False, 401, "Invalid token audience"

        if not _is_authorized_service_account(claims):
            print(
                f"OIDC rejected: unauthorized caller email={claims.get('email')!r} "
                f"verified={claims.get('email_verified')!r}"
            )
            return False, 403, "Caller is not an authorized project service account"

        return True, 200, ""

    if not _is_cloud_run() and _verify_local_hmac(req):
        return True, 200, ""

    return False, 401, "Authentication required"


# --- Input Sanitization Helpers ---

def _sanitize_ip(raw_ip) -> str:
    """Strip non-IP characters and validate IPv4/IPv6 syntax."""
    if not raw_ip:
        return "unknown"
    text = RE_CONTROL_CHARS.sub("", str(raw_ip)).strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    m_v4 = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", text)
    if m_v4:
        try:
            return str(ipaddress.ip_address(m_v4.group(0)))
        except ValueError:
            pass
    cleaned = RE_NON_IP_CHARS.sub("", text)[:45]
    if cleaned:
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError:
            pass
    return "unknown"


def _extract_client_ip(req) -> str:
    """Extract and sanitize client IP safely behind Google Cloud Run's load balancer."""
    xff = req.headers.get("X-Forwarded-For") or ""
    candidate = ""
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if _is_cloud_run() and len(parts) >= 2:
            candidate = parts[-2]
        elif parts:
            candidate = parts[0]
    if not candidate:
        candidate = getattr(req, "remote_addr", None) or ""
    return _sanitize_ip(candidate)


def _sanitize_filename(raw_filename) -> str:
    """Strip control characters, CR/LF, and both POSIX/Windows path separators from filename."""
    if not raw_filename:
        return "unknown"
    no_ctrl = RE_CONTROL_CHARS.sub("", str(raw_filename))
    basename = re.split(r"[/\\]", no_ctrl)[-1]
    basename = basename.replace("/", "").replace("\\", "").strip()
    if not basename or basename in (".", ".."):
        return "unknown"
    return basename[:255]


def _sanitize_content_type(raw_ct):
    """Sanitize optional Content-Type, rejecting control characters and path traversal."""
    if not raw_ct:
        return None
    cleaned = RE_CONTROL_CHARS.sub("", str(raw_ct)).replace("\\", "").strip()[:128]
    if not cleaned:
        return None
    if ".." in cleaned or not RE_MIME_TYPE.fullmatch(cleaned):
        return "application/octet-stream"
    return cleaned


# --- Subprocess Isolation Around QuickSand Document Parsing ---

def _get_mp_context():
    """Prefer `fork` on Linux for fast CoW startup; fall back cleanly to `spawn`."""
    available = mp.get_all_start_methods()
    if sys.platform.startswith("linux") and "fork" in available:
        try:
            return mp.get_context("fork")
        except ValueError:
            pass
    return mp.get_context("spawn")


def _analysis_worker(
    out_queue,
    data: bytes,
    password,
    inner_timeout: int,
    max_total_bytes: int,
    filename: str,
    file_uuid: str,
    md5: str,
    sha1: str,
    sha256: str,
    sha512: str,
) -> None:
    """Isolated child-process entrypoint executing QuickSand parsing and YARA matching."""
    try:
        try:
            import resource

            cpu_cap = max(2, int(inner_timeout) + 5)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_cap, cpu_cap + 2))
        except Exception:
            pass

        qs = quicksand(
            data,
            timeout=inner_timeout,
            strings=True,
            capture=False,
            password=password,
            max_total_bytes=max_total_bytes,
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
    except Exception as exc:
        print(f"Worker exception analyzing uuid={file_uuid}: {exc}")
        traceback.print_exc()
        try:
            out_queue.put(("error", "", False))
        except Exception:
            pass


def run_quicksand_isolated(
    data: bytes,
    *,
    password=None,
    filename: str = "",
    file_uuid: str = "",
    md5: str = "",
    sha1: str = "",
    sha256: str = "",
    sha512: str = "",
    hard_timeout_sec=None,
    max_total_bytes: int = 64 * 1024 * 1024,
    worker_fn=None,
) -> tuple:
    """Execute QuickSand analysis in an isolated child process with a hard wall-clock timeout.

    Reads from the IPC Queue *before* `proc.join()` so serialized JSON reports larger than
    OS pipe buffers (>64 KB) never deadlock, and `proc.kill()`s hung workers cleanly.

    Returns:
        (status, report_json, encrypted_unreadable) where status is "ok", "timeout", or "error".
    """
    effective_hard = float(
        hard_timeout_sec
        if hard_timeout_sec is not None
        else os.environ.get("QS_HARD_TIMEOUT_SEC", str(HARD_TIMEOUT_SEC))
    )
    effective_hard = max(0.2, effective_hard)
    inner_timeout = max(1, min(18, int(max(1.0, effective_hard - 4.0))))

    ctx = _get_mp_context()
    out_queue = ctx.Queue(maxsize=1)
    target_fn = worker_fn or _analysis_worker
    proc = ctx.Process(
        target=target_fn,
        args=(
            out_queue,
            data,
            password,
            inner_timeout,
            max_total_bytes,
            filename,
            file_uuid,
            md5,
            sha1,
            sha256,
            sha512,
        ),
        daemon=True,
    )

    deadline = time.monotonic() + effective_hard
    result_tuple = None

    try:
        proc.start()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                result_tuple = out_queue.get(timeout=min(0.2, remaining))
                break
            except queue.Empty:
                if not proc.is_alive():
                    try:
                        result_tuple = out_queue.get_nowait()
                    except queue.Empty:
                        pass
                    break

        if result_tuple is None:
            if proc.is_alive() or time.monotonic() >= deadline:
                print(
                    f"Hard timeout ({effective_hard}s) exceeded for uuid={file_uuid}; "
                    f"killing worker pid={proc.pid}"
                )
                try:
                    proc.kill()
                except Exception:
                    pass
                proc.join(timeout=2.0)
                return "timeout", None, False

            proc.join(timeout=1.0)
            print(f"Worker exited abnormally (exitcode={proc.exitcode}) for uuid={file_uuid}")
            return "error", None, False

        proc.join(timeout=2.0)
        if proc.is_alive():
            try:
                proc.kill()
            except Exception:
                pass
            proc.join(timeout=1.0)

        return result_tuple
    finally:
        if proc.is_alive():
            try:
                proc.kill()
            except Exception:
                pass
            proc.join(timeout=1.0)
        try:
            out_queue.close()
            out_queue.cancel_join_thread()
        except Exception:
            pass


# --- GCS Storage & Report Cache Helpers ---

def get_file(file_uuid):
    if not qs_bucket_name or storage_client is None:
        print("Error: Storage client or QS_BUCKET not configured, cannot get file.")
        return None, "", ""
    print(f"{time.time()} download file: {file_uuid}")
    bucket = storage_client.bucket(qs_bucket_name)
    blob = bucket.blob(f"new/{file_uuid}")
    try:
        blob.reload()
        if blob.size is not None and blob.size > MAX_UPLOAD_BYTES:
            print(f"Error: Blob {file_uuid} size {blob.size} exceeds MAX_UPLOAD_BYTES ({MAX_UPLOAD_BYTES})")
            return None, "", "oversize"

        data = blob.download_as_bytes()
        if len(data) > MAX_UPLOAD_BYTES:
            print(f"Error: Downloaded blob {file_uuid} size {len(data)} exceeds MAX_UPLOAD_BYTES")
            return None, "", "oversize"

        filename = ""
        submitter_ip = ""
        if blob.metadata:
            raw_fn = (
                blob.metadata.get("original-filename")
                or blob.metadata.get("original_filename")
                or blob.metadata.get("x-goog-meta-original-filename")
                or blob.metadata.get("filename")
                or ""
            )
            filename = _sanitize_filename(raw_fn) if raw_fn else ""
            raw_ip = (
                blob.metadata.get("ip")
                or blob.metadata.get("uploader_ip")
                or blob.metadata.get("x-goog-meta-ip")
                or ""
            )
            submitter_ip = _sanitize_ip(raw_ip) if raw_ip else ""

        print(f"{time.time()} got file: {filename} from IP: {submitter_ip}")
        return data, filename, submitter_ip
    except Exception as e:
        print(f"Error downloading file {file_uuid}: {e}")
        return None, "", ""


def _upload_json_blob(bucket, blob_name: str, payload: str) -> None:
    blob = bucket.blob(blob_name)
    if qs_kms_key_name:
        try:
            blob.kms_key_name = qs_kms_key_name
        except Exception as e:
            print(f"Warning: Failed to set kms_key_name on blob: {e}")
    blob.upload_from_string(payload, content_type="application/json")


def cache_report(sha256: str, sha512: str, data: str) -> None:
    """Cache report strictly by collision-resistant SHA-256 (with optional SHA-512 alias pointer).

    MD5 and SHA-1 are intentionally excluded from cache object keys and alias pointers
    to prevent collision-based report poisoning.
    """
    if not qs_bucket_name or storage_client is None:
        print("Error: Storage client or QS_BUCKET not configured, cannot cache report.")
        return

    sha256_norm = (sha256 or "").strip().lower()
    sha512_norm = (sha512 or "").strip().lower()
    if not RE_SHA256.fullmatch(sha256_norm):
        print("Error: Refusing to cache report without valid 64-char SHA-256 digest.")
        return

    bucket = storage_client.bucket(qs_bucket_name)
    try:
        _upload_json_blob(bucket, f"report/{sha256_norm}.json", data)
        print(f"{time.time()} cached primary report: {sha256_norm} (sha256)")

        if RE_SHA512.fullmatch(sha512_norm):
            alias_payload = json.dumps({"_alias_sha256": sha256_norm})
            _upload_json_blob(bucket, f"report/{sha512_norm}.json", alias_payload)
            print(f"{time.time()} cached SHA-512 alias pointer: {sha512_norm}")
    except Exception as e:
        print(f"Error caching report for sha256={sha256_norm}: {e}")


def check_report_recent(hash_value: str) -> bool:
    if not qs_bucket_name or storage_client is None:
        print("Error: Storage client or QS_BUCKET not configured, cannot check report.")
        return False

    norm_hash = (hash_value or "").strip().lower()
    if not RE_STRONG_HASH.fullmatch(norm_hash):
        return False

    bucket = storage_client.bucket(qs_bucket_name)
    try:
        blob = bucket.get_blob(f"report/{norm_hash}.json")
        if blob and blob.updated:
            now_utc = datetime.now(tz=blob.updated.tzinfo)
            if blob.updated > now_utc - timedelta(days=6):
                print(f"Cached report for {norm_hash} is recent.")
                return True
            print(f"Cached report for {norm_hash} is older than 6 days.")
        return False
    except Exception as e:
        if "Not Found" not in str(e):
            print(f"Error checking report {norm_hash}: {e}")
        return False


def get_report(hash_value: str):
    """Retrieve a cached report by SHA-256 or SHA-512, safely resolving SHA-256 alias pointers."""
    if not qs_bucket_name or storage_client is None:
        print("Error: Storage client or QS_BUCKET not configured, cannot get report.")
        return None

    norm_hash = (hash_value or "").strip().lower()
    if not RE_STRONG_HASH.fullmatch(norm_hash):
        print(f"Refusing get_report for non-SHA256/SHA512 digest: {norm_hash!r}")
        return None

    print(f"{time.time()} download report: {norm_hash}")
    bucket = storage_client.bucket(qs_bucket_name)
    blob = bucket.blob(f"report/{norm_hash}.json")
    try:
        raw_text = blob.download_as_bytes().decode("utf-8")
    except Exception as e:
        if "Not Found" not in str(e):
            print(f"Error getting report {norm_hash}: {e}")
        return None

    try:
        parsed = json.loads(raw_text)
    except Exception:
        return raw_text

    if isinstance(parsed, dict) and "_alias_sha256" in parsed:
        alias_target = str(parsed.get("_alias_sha256") or "").strip().lower()
        if not RE_SHA256.fullmatch(alias_target):
            print(f"Security warning: refusing invalid _alias_sha256 target {alias_target!r}")
            return None
        try:
            target_blob = bucket.blob(f"report/{alias_target}.json")
            target_text = target_blob.download_as_bytes().decode("utf-8")
            target_obj = json.loads(target_text)
            if isinstance(target_obj, dict) and "_alias_sha256" in target_obj:
                print("Security warning: refusing chained _alias_sha256 pointer.")
                return None
            return target_text
        except Exception as e:
            if "Not Found" not in str(e):
                print(f"Error resolving alias target {alias_target}: {e}")
            return None

    return raw_text


# --- CORS & Error Response Helpers ---

def get_cors_headers():
    return {
        "Access-Control-Allow-Origin": qs_cors_origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
        "Access-Control-Allow-Headers": (
            "Content-Type, Authorization, X-Forwarded-For, X-QS-Timestamp, X-QS-Signature, "
            "X-Goog-Meta-IP, X-Goog-Meta-Original-Filename, X-Goog-Content-Length-Range"
        ),
        "Access-Control-Max-Age": "3600",
    }


def _json_response(payload: dict, status: int = 200, extra_headers: dict = None):
    resp = jsonify(payload)
    resp.headers.extend(get_cors_headers())
    if extra_headers:
        resp.headers.extend(extra_headers)
    return resp, status


# --- Main HTTP Handler ---

@functions_framework.http
def quicksand_combined(request):
    """
    Combined Cloud Function handler for all QuickSand services.
    Routes requests based on the path:
    - /upload -> File signing service
    - /analyze -> Analysis service
    - /search -> Search service
    - /health -> Health check endpoint
    """
    if request.method == "OPTIONS":
        return Response(status=204, headers=get_cors_headers())

    path = request.path.strip("/")

    if path == "health":
        return _json_response({"status": "ok", "service": "quicksand-combined"}, 200)

    authorized, auth_status, auth_msg = verify_request_auth(request)
    if not authorized:
        extra = {"WWW-Authenticate": "Bearer"} if auth_status == 401 else None
        return _json_response({"error": auth_msg}, auth_status, extra_headers=extra)

    if path == "upload":
        return handle_upload(request)
    elif path == "analyze":
        return handle_analyze(request)
    elif path == "search":
        return handle_search(request)
    else:
        return _json_response(
            {"error": "Invalid path. Use /upload, /analyze, /search, or /health"},
            400,
        )


# Alias `main` so Functions Framework works even if target defaults to `main`
main = quicksand_combined


def handle_upload(request):
    """Handle file upload signing requests."""
    print("\n--- Function Triggered: handle_upload ---")

    try:
        ensure_credentials()
    except Exception as e:
        print(f"Error refreshing credentials during upload: {e}")
        traceback.print_exc()
        return _json_response({"error": "Server configuration error"}, 500)

    if storage_client is None or not qs_bucket_name:
        print("Error: Storage client or QS_BUCKET is not initialized.")
        return _json_response({"error": "Server configuration error"}, 500)

    random_uuid = str(uuid.uuid4())
    object_name = f"new/{random_uuid}"

    submit_ip = _extract_client_ip(request)
    filename = _sanitize_filename(request.args.get("filename", ""))
    safe_ct = _sanitize_content_type(request.args.get("contentType"))

    effective_max_bytes = MAX_UPLOAD_BYTES
    raw_max = request.args.get("maxBytes")
    if raw_max is not None:
        try:
            parsed_max = int(raw_max)
            if 1 <= parsed_max <= MAX_UPLOAD_BYTES:
                effective_max_bytes = parsed_max
        except (ValueError, TypeError):
            pass

    content_length_range = f"0,{effective_max_bytes}"

    required_put_headers = {
        "x-goog-meta-ip": submit_ip,
        "x-goog-meta-original-filename": filename,
        "x-goog-content-length-range": content_length_range,
    }

    try:
        bucket = storage_client.bucket(qs_bucket_name)
        blob = bucket.blob(object_name)

        service_account_email = getattr(credentials, "service_account_email", None)
        access_token = getattr(credentials, "token", None)

        gen_kwargs = dict(
            version="v4",
            method="PUT",
            expiration=timedelta(seconds=900),
            service_account_email=service_account_email,
            access_token=access_token,
            headers=required_put_headers,
        )
        if safe_ct:
            gen_kwargs["content_type"] = safe_ct
            required_put_headers["content-type"] = safe_ct
        signed_url = blob.generate_signed_url(**gen_kwargs)

    except Exception as e:
        print(f"Error occurred during signed URL generation: {e}")
        traceback.print_exc()
        return _json_response({"error": "Failed to generate signed upload URL"}, 500)

    if signed_url:
        current_qs_url = os.environ.get("QS_URL") or qs_url_base
        response_data = {
            "upload_url": signed_url,
            "analysis_url": f"{current_qs_url}?uuid={random_uuid}" if current_qs_url else f"?uuid={random_uuid}",
            "meta": {
                "uuid": random_uuid,
                "object_name": object_name,
                "original_filename": filename,
                "submitter_ip": submit_ip,
                "content_length_range": content_length_range,
            },
        }
        if safe_ct:
            response_data["meta"]["content_type"] = safe_ct
        return _json_response(response_data, 200)

    return _json_response({"error": "Failed to generate signed upload URL"}, 500)


def handle_analyze(request):
    """Handle file analysis requests inside an isolated worker subprocess."""
    print("\n--- Function Triggered: handle_analyze ---")

    if storage_client is None or not qs_bucket_name:
        print("Error: Storage client or QS_BUCKET is not configured.")
        return _json_response({"error": "Server configuration error"}, 500)

    file_uuid = request.args.get("uuid", "").strip()
    rerun_arg = request.args.get("rerun", "").lower()
    rerun = rerun_arg in ("true", "1")
    raw_password = request.args.get("password")
    password = raw_password[:256] if isinstance(raw_password, str) and raw_password != "" else None

    if not file_uuid:
        return _json_response({"error": "uuid query parameter is missing"}, 400)

    if len(file_uuid) > 128 or not RE_UUID_SAFE.fullmatch(file_uuid) or ".." in file_uuid:
        return _json_response({"error": "invalid uuid parameter"}, 400)

    print(f"processing uuid={file_uuid}, rerun={rerun}")

    data, filename, submitter_ip = get_file(file_uuid)
    if data is None:
        if submitter_ip == "oversize":
            return _json_response(
                {"error": "uploaded file exceeds maximum allowed size", "uuid": file_uuid},
                413,
            )
        return _json_response({"error": "file not found", "uuid": file_uuid}, 404)

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()

    if rerun or password is not None:
        print(f"FRESH SCAN MODE: Bypassing cache for {sha256} (rerun={rerun}, password_supplied={password is not None})")
    elif check_report_recent(sha256):
        print(f"getting cached report for {sha256}")
        report = get_report(sha256)
        if report:
            try:
                cached_obj = json.loads(report)
            except Exception:
                cached_obj = {}
            if not cached_obj.get("encrypted_unreadable"):
                resp = Response(report, mimetype="application/json")
                resp.headers.extend(get_cors_headers())
                return resp, 200
            print(f"Cached report for {sha256} was encrypted_unreadable; proceeding to re-run analysis.")
        else:
            print(f"check_report_recent was true, but get_report failed for {sha256}, proceeding to re-run analysis.")

    print(f"{time.time()} qs isolated subprocess start for {sha256}")
    status, rt, encrypted_unreadable = run_quicksand_isolated(
        data,
        password=password,
        filename=filename,
        file_uuid=file_uuid,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        sha512=sha512,
        max_total_bytes=64 * 1024 * 1024,
    )
    print(f"{time.time()} qs isolated subprocess end status={status}")

    if status == "timeout":
        return _json_response(
            {"error": "timeout", "message": "Analysis timed out", "uuid": file_uuid},
            504,
        )

    if status != "ok" or not rt:
        return _json_response(
            {"error": "exception", "message": "Internal analysis error", "uuid": file_uuid},
            500,
        )

    if not encrypted_unreadable:
        cache_report(sha256, sha512, rt)
    else:
        print(f"Skipping report cache for {sha256}: container is encrypted and unreadable.")

    resp = Response(rt, mimetype="application/json")
    resp.headers.extend(get_cors_headers())
    return resp, 200


def handle_search(request):
    """Handle report lookup requests strictly by 64-char SHA-256 or 128-char SHA-512."""
    print("\n--- Function Triggered: handle_search ---")

    if storage_client is None or not qs_bucket_name:
        print("Error: Storage client or QS_BUCKET is not configured.")
        return _json_response({"error": "Server configuration error"}, 500)

    raw_query = request.args.get("query")
    if not raw_query:
        return _json_response({"error": "query parameter is missing"}, 400)

    query = str(raw_query).strip().lower()
    if not RE_STRONG_HASH.fullmatch(query):
        return _json_response(
            {"error": "Invalid hash format. Provide a 64-char SHA-256 or 128-char SHA-512 hex digest."},
            400,
        )

    print(f"Searching for digest: {query}")
    report = get_report(query)
    if report is not None:
        resp = Response(report, mimetype="application/json")
        resp.headers.extend(get_cors_headers())
        return resp, 200

    return _json_response({"error": "No report found for the given hash"}, 404)
