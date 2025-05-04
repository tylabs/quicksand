"""
QuickSand GCP Cloud Run Function - Combined Service
Copyright (c) 2025 Tyler McLellan / @tylabs
Website: https://tylabs.com

This service combines three QuickSand services into one:
1. File Signing Service - Generates signed URLs for secure file uploads
2. Analysis Service - Processes files using the QuickSand engine
3. Search Service - Searches for previously analyzed files

Environment Variables Required:
- QS_BUCKET: The GCS bucket name for storing uploaded files and reports
- QS_URL: The base URL for the QuickSand analysis service

Function Entry Point:
- quicksand_combined
"""

import json
import uuid
import os
import re
import time
import hashlib
from datetime import datetime, timedelta
from google.cloud import storage
import functions_framework
from flask import request, jsonify, Response
import traceback
import google.auth
from google.auth.transport import requests

# Import quicksand module
try:
    from quicksand.quicksand import quicksand
except ImportError:
    print("Error: quicksand module not found. Please ensure it's installed in requirements.txt")
    raise

# --- Startup Configuration and Initialization ---
print("Function startup: Reading environment variables...")
qs_bucket_name = os.environ.get("QS_BUCKET")
qs_url_base = os.environ.get("QS_URL")
print(f"Config: QS_BUCKET={qs_bucket_name}")
print(f"Config: QS_URL={qs_url_base}")

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

# Basic configuration checks
if not qs_bucket_name:
    print("Warning: QS_BUCKET environment variable not set at startup. Operations will fail if triggered.")

# --- Helper Functions ---

def get_file(uuid):
    if not qs_bucket_name:
        print("Error: QS_BUCKET not set, cannot get file.")
        return None, "", ""
    print(f"{time.time()} download file: {uuid}")
    bucket = storage_client.bucket(qs_bucket_name)
    blob = bucket.blob(f"new/{uuid}")
    try:
        blob.reload()
        print(f"Debug - Blob metadata after reload: {blob.metadata}")
        
        data = blob.download_as_bytes()
        filename = ""
        submitter_ip = ""
        
        if blob.metadata:
            print(f"Debug - Full metadata: {blob.metadata}")
            filename = (blob.metadata.get("original-filename") or 
                       blob.metadata.get("x-goog-meta-original-filename") or 
                       blob.metadata.get("filename") or 
                       "")
            submitter_ip = (blob.metadata.get("ip") or 
                          blob.metadata.get("x-goog-meta-ip") or 
                          "")
            print(f"Debug - Retrieved filename: {filename}")
            print(f"Debug - Retrieved IP: {submitter_ip}")
        else:
            print("Debug - No metadata found on blob")
            
        print(f"{time.time()} got file: {filename} from IP: {submitter_ip}")
        return data, filename, submitter_ip
    except Exception as e:
        print(f"Error downloading file {uuid}: {e}")
        return None, "", ""

def cache_report(md5, sha1, sha256, sha512, data):
    if not qs_bucket_name:
        print("Error: QS_BUCKET not set, cannot cache report.")
        return
    bucket = storage_client.bucket(qs_bucket_name)
    
    # Parse the JSON data to get all hash values
    try:
        report_data = json.loads(data)
        hash_values = {
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'sha512': sha512
        }
        
        # Store the report with each hash type
        for hash_type, hash_val in hash_values.items():
            if hash_val:  # Only store if the hash value exists
                blob = bucket.blob(f"report/{hash_val}.json")
                try:
                    blob.upload_from_string(data, content_type="application/json")
                    print(f"{time.time()} cached report: {hash_val} ({hash_type})")
                except Exception as e:
                    print(f"Error caching report {hash_val} ({hash_type}): {e}")
    except Exception as e:
        print(f"Error caching report {hash_value}: {e}")

def check_report_recent(hash_value):
    if not qs_bucket_name:
        print("Error: QS_BUCKET not set, cannot check report.")
        return False
    bucket = storage_client.bucket(qs_bucket_name)
    
    blob = bucket.get_blob(f"report/{hash_value}.json")
    try:
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

def keys_string(data):
    new_data = {}
    for key, value in data.items():
        if isinstance(value, list):
            new_list = []
            for item in value:
                if isinstance(item, dict):
                    new_dict = {}
                    for k, v in item.items():
                        if isinstance(v, list):
                            new_v_list = []
                            for elem in v:
                                if hasattr(elem, '__str__'):
                                    new_v_list.append(str(elem))
                                else:
                                    new_v_list.append(elem)
                            new_dict[k] = new_v_list
                        elif hasattr(v, '__str__'):
                            new_dict[k] = str(v)
                        else:
                            new_dict[k] = v
                    new_list.append(new_dict)
                elif hasattr(item, '__str__'):
                    new_list.append(str(item))
                else:
                    new_list.append(item)
            new_data[key] = new_list
        elif isinstance(value, dict):
            new_data[key] = keys_string(value)
        elif hasattr(value, '__str__'):
            new_data[key] = str(value)
        else:
            new_data[key] = value
    return new_data

# --- CORS Headers ---
def get_cors_headers():
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Forwarded-For, X-Goog-Meta-IP, X-Goog-Meta-Original-Filename',
        'Access-Control-Max-Age': '3600'
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
    """
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        return Response(status=204, headers=get_cors_headers())

    # Get the path from the request
    path = request.path.strip('/')
    
    # Route to appropriate handler based on path
    if path == 'upload':
        return handle_upload(request)
    elif path == 'analyze':
        return handle_analyze(request)
    elif path == 'search':
        return handle_search(request)
    else:
        resp = jsonify({"error": "Invalid path. Use /upload, /analyze, or /search"})
        resp.headers.extend(get_cors_headers())
        return resp, 400

def handle_upload(request):
    """Handle file upload signing requests"""
    print("\n--- Function Triggered: handle_upload ---")
    
    # Refresh credentials
    r = requests.Request()
    credentials.refresh(r)

    # Check if client initialization was successful
    if storage_client is None:
        print("Error: Storage client was not initialized at startup.")
        resp = jsonify({'error': 'Server configuration error: GCS client failed to initialize'})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    # Check if the required configuration is available
    if not qs_bucket_name:
        print("Error: QS_BUCKET environment variable is not set at runtime.")
        resp = jsonify({'error': 'Server configuration error: GCS bucket name not set'})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    print(f"Request Method: {request.method}")
    print(f"Request Args: {request.args}")
    print(f"Request Headers: {dict(request.headers)}")

    random_uuid = str(uuid.uuid4())
    print(f"Generated UUID: {random_uuid}")

    object_name = f"new/{random_uuid}"
    print(f"Generated Object Name: {object_name}")

    submit_ip = request.headers.get("X-Forwarded-For")
    if not submit_ip:
        submit_ip = request.remote_addr
        print(f"Using request.remote_addr: {submit_ip} as X-Forwarded-For not present.")
    else:
        print(f"Using X-Forwarded-For header: {submit_ip}")

    filename = request.args.get("filename", "")
    print(f"Extracted Filename (from args): {filename}")

    required_put_headers = {
        'x-goog-meta-ip': submit_ip if submit_ip else 'unknown',
        'x-goog-meta-original-filename': filename if filename else 'unknown'
    }
    print(f"Required PUT Headers for Signed URL condition: {required_put_headers}")

    try:
        bucket = storage_client.bucket(qs_bucket_name)
        blob = bucket.blob(object_name)
        print(f"Storage blob object created for bucket '{qs_bucket_name}' and object '{object_name}'.")

        service_account_email = None
        if hasattr(credentials, "service_account_email"):
            service_account_email = credentials.service_account_email
            print(f"Using service account email: {service_account_email} for signing.")
        else:
            print("Warning: Service account email not found on credentials.")

        print("Attempting to generate V4 signed URL...")
        signed_url = blob.generate_signed_url(
            version="v4",
            method="PUT",
            expiration=timedelta(seconds=3600),
            service_account_email=service_account_email,
            access_token=credentials.token,
            headers=required_put_headers
        )
        print("V4 signed URL generated successfully.")
        if signed_url:
            print(f"Signed URL starts with: {signed_url[:100]}...")

    except Exception as e:
        print(f"Error occurred during signed URL generation:")
        print(f"Error details: {e}")
        traceback.print_exc()
        resp = jsonify({'error': 'Failed to generate signed upload URL. Check server logs.', 'details': str(e)})
        resp.headers.extend(get_cors_headers())
        return resp, 500

    if signed_url:
        response_data = {
            'upload_url': signed_url,
            'analysis_url': f"{qs_url_base}?uuid={random_uuid}",
            'meta': {
                'uuid': random_uuid,
                'object_name': object_name,
                'original_filename': filename,
                'submitter_ip': submit_ip
            }
        }
        if qs_url_base:
            response_data['analysis_url'] = f"{qs_url_base}?uuid={random_uuid}"

        print("Response data prepared.")
        print(json.dumps(response_data, indent=2))

        resp = jsonify(response_data)
        resp.headers.extend(get_cors_headers())
        print("Returning JSON response with CORS header.")
        return resp, 200

    print("Reached end of function without returning a specific response (unusual).")
    resp = jsonify({'error': 'An unexpected internal error occurred during signed URL generation.'})
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

    uuid = request.args.get('uuid')
    rerun_arg = request.args.get('rerun', '').lower()
    rerun = rerun_arg in ('true', '1')

    if not uuid:
        resp = jsonify({"error": "uuid query parameter is missing"})
        resp.headers.extend(get_cors_headers())
        return resp, 400

    print(f"processing uuid={uuid}, rerun={rerun}")

    data, filename, submitter_ip = get_file(uuid)
    if data is None:
        resp = jsonify({"error": "file not found in Google Cloud Storage", "uuid": uuid, "bucket": qs_bucket_name})
        resp.headers.extend(get_cors_headers())
        return resp, 404

    # Calculate hash
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()

    if not rerun and check_report_recent(sha256):  # Use SHA256 for recency check
        print(f"getting cached report for {sha256}")
        report = get_report(sha256)
        if report:
            resp = Response(report, mimetype='application/json')
            resp.headers.extend(get_cors_headers())
            return resp
        else:
            print(f"check_report_recent was true, but get_report failed for {sha256}, proceeding to re-run analysis.")

    print(f"{time.time()} qs start for {sha256}")
    try:
        qs = quicksand(data, timeout=18, strings=True, capture=False)
        print(f"{time.time()} qs process start")
        qs.process()
        print(f"{time.time()} qs process end")

        qs.results['filename'] = filename
        qs.results['uuid'] = uuid
        #qs.results['md5'] = md5
        #qs.results['sha1'] = sha1
        #qs.results['sha256'] = sha256
        #qs.results['sha512'] = sha512
#
        processed_results = keys_string(qs.results)
        rt = json.dumps(processed_results)
        print(f"{time.time()} qs end convert to json")

        cache_report(md5,sha1,sha256,sha512, rt)  # Pass hashes for caching

        resp = jsonify(processed_results)
        resp.headers.extend(get_cors_headers())
        return resp

    except Exception as e:
        error_message = f"exception during analysis for uuid {uuid}: {str(e)}"
        print(error_message)
        traceback.print_exc()
        resp = jsonify({"error": "exception", "message": error_message, "uuid": uuid})
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

    query = request.args.get('query')
    if not query:
        resp = jsonify({"error": "query parameter is missing"})
        resp.headers.extend(get_cors_headers())
        return resp, 400

    query = re.sub(r'<[^>]+>', '', query)
    print(f"Searching for: {query}")

    # Try to get the report using the query as a hash
    bucket = storage_client.bucket(qs_bucket_name)
    blob = bucket.get_blob(f"report/{query}.json")
    
    if blob:
        try:
            report = blob.download_as_string().decode('utf-8')
            resp = Response(report, mimetype='application/json')
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