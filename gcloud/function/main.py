"""
QuickSand GCP Cloud Run Function - Combined Service (https://stopmalware.cloud.run)
Copyright (c) 2025-2026 Tyler McLellan / @tylabs
Website: https://tylabs.com

This service combines three QuickSand services into one:
1. File Signing Service - Generates signed URLs for secure file uploads (/upload)
2. Analysis Service - Processes files using the QuickSand engine (/analyze)
3. Search Service - Searches for previously analyzed files (/search)

Environment Variables Required:
- QS_BUCKET: The GCS bucket name for storing uploaded files and reports
- QS_URL: The base URL for the QuickSand analysis service
- QS_KMS_KEY: Optional KMS key resource name for Customer-Managed Encryption Keys (CMEK)

Function Entry Point:
- quicksand_combined (or main)
"""

from datetime import datetime, timedelta
import hashlib
import json
import os
import re
import time
import traceback
import uuid

from flask import Response, jsonify, request
import functions_framework
import google.auth
from google.auth.transport import requests
from google.cloud import storage

# Import quicksand module and JSON helpers
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

# --- Startup Configuration and Initialization ---
print("Function startup: Reading environment variables...")
qs_bucket_name = os.environ.get("QS_BUCKET")
qs_url_base = os.environ.get("QS_URL")
print(f"Config: QS_BUCKET={qs_bucket_name}")
print(f"Config: QS_URL={qs_url_base}")
qs_kms_key_name = os.environ.get("QS_KMS_KEY")
if qs_kms_key_name:
    print("Config: QS_KMS_KEY is set (using CMEK for server-side writes)")
else:
    print("Config: QS_KMS_KEY not set; will rely on bucket default encryption if configured.")

# --- Initialize storage_client using explicitly loaded default credentials ---
storage_client = None
credentials = None
project_id = None

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


def ensure_credentials():
    """Lazily refresh credentials only when invalid or expired."""
    global credentials
    if credentials is None:
        return None
    if not getattr(credentials, "valid", False) or getattr(credentials, "expired", False) or not getattr(credentials, "token", None):
        r = requests.Request()
        credentials.refresh(r)
    return credentials


# --- Helper Functions ---

def get_file(file_uuid):
    if not qs_bucket_name:
        print("Error: QS_BUCKET not set, cannot get file.")
        return None, "", ""
    print(f"{time.time()} download file: {file_uuid}")
    bucket = storage_client.bucket(qs_bucket_name)
    blob = bucket.blob(f"new/{file_uuid}")
    try:
        blob.reload()
        print(f"Debug - Blob metadata after reload: {blob.metadata}")

        data = blob.download_as_bytes()
        filename = ""
        submitter_ip = ""

        if blob.metadata:
            print(f"Debug - Full metadata: {blob.metadata}")
            filename = (
                blob.metadata.get("original-filename")
                or blob.metadata.get("original_filename")
                or blob.metadata.get("x-goog-meta-original-filename")
                or blob.metadata.get("filename")
                or ""
            )
            submitter_ip = (
                blob.metadata.get("ip")
                or blob.metadata.get("uploader_ip")
                or blob.metadata.get("x-goog-meta-ip")
                or ""
            )
            print(f"Debug - Retrieved filename: {filename}")
            print(f"Debug - Retrieved IP: {submitter_ip}")
        else:
            print("Debug - No metadata found on blob")

        print(f"{time.time()} got file: {filename} from IP: {submitter_ip}")
        return data, filename, submitter_ip
    except Exception as e:
        print(f"Error downloading file {file_uuid}: {e}")
        return None, "", ""


def cache_report(md5, sha1, sha256, sha512, data):
    if not qs_bucket_name:
        print("Error: QS_BUCKET not set, cannot cache report.")
        return
    bucket = storage_client.bucket(qs_bucket_name)

    try:
        hash_values = {
            "sha256": sha256,
            "md5": md5,
            "sha1": sha1,
            "sha512": sha512,
        }

        primary_blob = None
        for hash_type, hash_val in hash_values.items():
            if not hash_val:
                continue
            blob_name = f"report/{hash_val}.json"
            if primary_blob is None:
                blob = bucket.blob(blob_name)
                if qs_kms_key_name:
                    try:
                        blob.kms_key_name = qs_kms_key_name
                    except Exception as e:
                        print(f"Warning: Failed to set kms_key_name on blob: {e}")
                blob.upload_from_string(data, content_type="application/json")
                primary_blob = blob
                print(f"{time.time()} cached primary report: {hash_val} ({hash_type})")
            else:
                try:
                    alias_blob = bucket.blob(blob_name, kms_key_name=qs_kms_key_name) if qs_kms_key_name else bucket.blob(blob_name)
                    rewrite_token = None
                    while True:
                        rewrite_token, _, _ = alias_blob.rewrite(primary_blob, token=rewrite_token)
                        if rewrite_token is None:
                            break
                    print(f"{time.time()} copied report alias: {hash_val} ({hash_type})")
                except Exception:
                    blob = bucket.blob(blob_name)
                    if qs_kms_key_name:
                        try:
                            blob.kms_key_name = qs_kms_key_name
                        except Exception:
                            pass
                    blob.upload_from_string(data, content_type="application/json")
                    print(f"{time.time()} cached report fallback: {hash_val} ({hash_type})")
    except Exception as e:
        print(f"Error caching report for sha256={sha256}: {e}")


def check_report_recent(hash_value):
    if not qs_bucket_name:
        print("Error: QS_BUCKET not set, cannot check report.")
        return False
    bucket = storage_client.bucket(qs_bucket_name)

    try:
        blob = bucket.get_blob(f"report/{hash_value}.json")
        if blob and blob.updated:
            now_utc = datetime.now(tz=blob.updated.tzinfo)
            if blob.updated > now_utc - timedelta(days=6):
                print(f"Cached report for {hash_value} is recent.")
                return True
            else:
                print(f"Cached report for {hash_value} is older than 6 days.")
                return False
        else:
            return False
    except Exception as e:
        if "Not Found" in str(e):
            print(f"Cached report for {hash_value} not found.")
            return False
        else:
            print(f"Error checking report {hash_value}: {e}")
            return False


def get_report(hash_value):
    if not qs_bucket_name:
        print("Error: QS_BUCKET not set, cannot get report.")
        return None
    print(f"{time.time()} download report: {hash_value}")
    bucket = storage_client.bucket(qs_bucket_name)
    blob = bucket.blob(f"report/{hash_value}.json")
    try:
        data = blob.download_as_bytes().decode("utf-8")
        print(f"{time.time()} got report: {hash_value}")
        return data
    except Exception as e:
        if "Not Found" in str(e):
            print(f"Cached report for {hash_value} not found.")
            return None
        else:
            print(f"Error getting report {hash_value}: {e}")
            return None


# --- CORS Headers ---
def get_cors_headers():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Forwarded-For, X-Goog-Meta-IP, X-Goog-Meta-Original-Filename",
        "Access-Control-Max-Age": "3600",
    }


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
        resp = jsonify({"status": "ok", "service": "quicksand-combined"})
        resp.headers.extend(get_cors_headers())
        return resp, 200
    elif path == "upload":
        return handle_upload(request)
    elif path == "analyze":
        return handle_analyze(request)
    elif path == "search":
        return handle_search(request)
    else:
        resp = jsonify({"error": "Invalid path. Use /upload, /analyze, /search, or /health"})
        resp.headers.extend(get_cors_headers())
        return resp, 400


# Alias `main` so Functions Framework works even if target defaults to `main`
main = quicksand_combined


def handle_upload(request):
    """Handle file upload signing requests"""
    print("\n--- Function Triggered: handle_upload ---")

    ensure_credentials()

    if storage_client is None:
        print("Error: Storage client was not initialized at startup.")
        resp = jsonify({"error": "Server configuration error: GCS client failed to initialize"})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    if not qs_bucket_name:
        print("Error: QS_BUCKET environment variable is not set at runtime.")
        resp = jsonify({"error": "Server configuration error: GCS bucket name not set"})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    random_uuid = str(uuid.uuid4())
    object_name = f"new/{random_uuid}"

    submit_ip = request.headers.get("X-Forwarded-For") or request.remote_addr
    filename = request.args.get("filename", "")
    content_type = request.args.get("contentType")

    required_put_headers = {
        "x-goog-meta-ip": submit_ip if submit_ip else "unknown",
        "x-goog-meta-original-filename": filename if filename else "unknown",
    }

    try:
        bucket = storage_client.bucket(qs_bucket_name)
        blob = bucket.blob(object_name)

        service_account_email = getattr(credentials, "service_account_email", None)

        gen_kwargs = dict(
            version="v4",
            method="PUT",
            expiration=timedelta(seconds=3600),
            service_account_email=service_account_email,
            access_token=credentials.token,
            headers=required_put_headers,
        )
        if content_type:
            gen_kwargs["content_type"] = content_type
            required_put_headers["content-type"] = content_type
        signed_url = blob.generate_signed_url(**gen_kwargs)

    except Exception as e:
        print(f"Error occurred during signed URL generation: {e}")
        traceback.print_exc()
        resp = jsonify({"error": "Failed to generate signed upload URL. Check server logs.", "details": str(e)})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    if signed_url:
        response_data = {
            "upload_url": signed_url,
            "analysis_url": f"{qs_url_base}?uuid={random_uuid}" if qs_url_base else f"?uuid={random_uuid}",
            "meta": {
                "uuid": random_uuid,
                "object_name": object_name,
                "original_filename": filename,
                "submitter_ip": submit_ip,
            },
        }

        resp = jsonify(response_data)
        resp.headers.extend(get_cors_headers())
        return resp, 200

    resp = jsonify({"error": "An unexpected internal error occurred during signed URL generation."})
    resp.headers.extend(get_cors_headers())
    return resp, 500


def handle_analyze(request):
    """Handle file analysis requests"""
    print("\n--- Function Triggered: handle_analyze ---")

    if not qs_bucket_name:
        print("QS_BUCKET environment variable is not set.")
        resp = jsonify({"error": "Server configuration error: QS_BUCKET environment variable not set."})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    file_uuid = request.args.get("uuid", "").strip()
    rerun_arg = request.args.get("rerun", "").lower()
    rerun = rerun_arg in ("true", "1")

    if not file_uuid:
        resp = jsonify({"error": "uuid query parameter is missing"})
        resp.headers.extend(get_cors_headers())
        return resp, 400

    if not re.match(r"^[a-zA-Z0-9._-]+$", file_uuid) or ".." in file_uuid:
        resp = jsonify({"error": "invalid uuid parameter"})
        resp.headers.extend(get_cors_headers())
        return resp, 400

    print(f"processing uuid={file_uuid}, rerun={rerun}")

    data, filename, submitter_ip = get_file(file_uuid)
    if data is None:
        resp = jsonify({"error": "file not found in Google Cloud Storage", "uuid": file_uuid, "bucket": qs_bucket_name})
        resp.headers.extend(get_cors_headers())
        return resp, 404

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()

    if rerun:
        print(f"RERUN MODE: Forcing fresh scan, bypassing cache for {sha256}")
    elif check_report_recent(sha256):
        print(f"getting cached report for {sha256}")
        report = get_report(sha256)
        if report:
            resp = Response(report, mimetype="application/json")
            resp.headers.extend(get_cors_headers())
            return resp
        else:
            print(f"check_report_recent was true, but get_report failed for {sha256}, proceeding to re-run analysis.")

    print(f"{time.time()} qs start for {sha256} (fresh scan)")
    try:
        qs = quicksand(data, timeout=18, strings=True, capture=False)
        print(f"{time.time()} qs process start")
        qs.process()
        print(f"{time.time()} qs process end")

        qs.results["filename"] = filename
        qs.results["uuid"] = file_uuid
        qs.results.setdefault("md5", md5)
        qs.results.setdefault("sha1", sha1)
        qs.results.setdefault("sha256", sha256)
        qs.results.setdefault("sha512", sha512)
        qs.results.setdefault("size", len(data))

        processed_results = keys_string(qs.results)
        rt = json.dumps(processed_results, cls=BytesDump)
        print(f"{time.time()} qs end convert to json")

        cache_report(md5, sha1, sha256, sha512, rt)

        resp = Response(rt, mimetype="application/json")
        resp.headers.extend(get_cors_headers())
        return resp

    except Exception as e:
        error_message = f"exception during analysis for uuid {file_uuid}: {str(e)}"
        print(error_message)
        traceback.print_exc()
        resp = jsonify({"error": "exception", "message": error_message, "uuid": file_uuid})
        resp.headers.extend(get_cors_headers())
        return resp, 500


def handle_search(request):
    """Handle search requests"""
    print("\n--- Function Triggered: handle_search ---")

    if not qs_bucket_name:
        print("QS_BUCKET environment variable is not set.")
        resp = jsonify({"error": "Server configuration error: QS_BUCKET environment variable not set."})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    query = request.args.get("query")
    if not query:
        resp = jsonify({"error": "query parameter is missing"})
        resp.headers.extend(get_cors_headers())
        return resp, 400

    query = re.sub(r"<[^>]+>", "", query).strip().lower()
    if not re.match(r"^[a-f0-9]{32,128}$", query):
        resp = jsonify({"error": "Invalid hash format"})
        resp.headers.extend(get_cors_headers())
        return resp, 400

    print(f"Searching for: {query}")

    bucket = storage_client.bucket(qs_bucket_name)
    blob = bucket.get_blob(f"report/{query}.json")

    if blob:
        try:
            report = blob.download_as_bytes().decode("utf-8")
            resp = Response(report, mimetype="application/json")
            resp.headers.extend(get_cors_headers())
            return resp
        except Exception as e:
            print(f"Error retrieving report for hash {query}: {e}")
            resp = jsonify({"error": "Error retrieving report"})
            resp.headers.extend(get_cors_headers())
            return resp, 500
    else:
        resp = jsonify({"error": "No report found for the given hash"})
        resp.headers.extend(get_cors_headers())
        return resp, 404
