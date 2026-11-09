### QuickSand 2: Python3 Version Copyright (c) 2021-2026 @tylabs
### Lambda function for AWS to process a document with quicksand

from datetime import datetime, timedelta
import hashlib
import json
import re
import time

import boto3
import botocore
import config

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


# The print statements are saved in the AWS lambda function logs

def getFile(file_uuid):
    print(f"{time.time()} download file: {file_uuid}")
    try:
        obj = config.boto_s3.get_object(Bucket=config.qs_bucket, Key="new/" + file_uuid)
        data = obj["Body"].read()
    except Exception as e:
        print(f"Error downloading file {file_uuid}: {e}")
        return None, ""

    filename = ""
    meta = obj.get("Metadata") or {}
    if meta:
        filename = (
            meta.get("filename")
            or meta.get("original-filename")
            or meta.get("original_filename")
            or ""
        )
        print(f"Retrieved filename: {filename}")
    print(f"{time.time()} got file")
    return data, filename


def cacheReport(md5, sha1, sha256, sha512, data):
    hashes = {
        "sha256": sha256,
        "md5": md5,
        "sha1": sha1,
        "sha512": sha512,
    }
    for hash_type, hash_val in hashes.items():
        if not hash_val:
            continue
        key = f"report/{hash_val}.json"
        try:
            config.boto_s3.put_object(
                Bucket=config.qs_bucket,
                Key=key,
                Body=data,
                ContentType="application/json",
            )
            print(f"{time.time()} cached report: {hash_val} ({hash_type})")
        except Exception as e:
            print(f"Error caching report {hash_val} ({hash_type}): {e}")


def checkReportRecent(hash_val):
    try:
        last_date_time = datetime.now() - timedelta(days=6)
        config.boto_s3.head_object(
            Bucket=config.qs_bucket,
            Key="report/" + str(hash_val) + ".json",
            IfModifiedSince=last_date_time,
        )
        return True
    except Exception:
        return False


def getReport(hash_val):
    print(f"{time.time()} download report: {hash_val}")
    try:
        obj = config.boto_s3.get_object(
            Bucket=config.qs_bucket,
            Key="report/" + str(hash_val) + ".json",
        )
        data = obj["Body"].read().decode("utf-8")
        print(f"{time.time()} got report: {hash_val}")
        return data
    except Exception as e:
        print(f"Error getting report {hash_val}: {e}")
        return None


def lambda_handler(event, context):
    params = (event or {}).get("queryStringParameters") or {}
    file_uuid = (params.get("uuid") or "").strip()
    rerun_arg = str(params.get("rerun") or "").lower()
    rerun = rerun_arg in ("1", "true")

    if not file_uuid:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "uuid is missing"}),
        }

    if not re.match(r"^[a-zA-Z0-9._-]+$", file_uuid) or ".." in file_uuid:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "invalid uuid parameter"}),
        }

    try:
        print("getting uuid=" + str(file_uuid))
        data, filename = getFile(file_uuid)
        if data is None:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "file not found in S3", "uuid": str(file_uuid)}),
            }

        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        sha512 = hashlib.sha512(data).hexdigest()

        if not rerun and (checkReportRecent(sha256) or checkReportRecent(md5)):
            lookup_hash = sha256 if checkReportRecent(sha256) else md5
            print("getting cached report for " + str(lookup_hash))
            report = getReport(lookup_hash)
            if report:
                return {
                    "statusCode": 200,
                    "body": report,
                }
        else:
            print("no cached report for " + str(sha256))

        # the default timeout is 29 seconds for a lambda run over API gateway so we time everything
        print(str(time.time()) + " qs start")

        qs = quicksand(data, timeout=18, strings=True, capture=False)
        print(str(time.time()) + " qs process")

        qs.process()
        print(str(time.time()) + " qs end process")

        qs.results["filename"] = filename
        qs.results["uuid"] = file_uuid
        qs.results.setdefault("md5", md5)
        qs.results.setdefault("sha1", sha1)
        qs.results.setdefault("sha256", sha256)
        qs.results.setdefault("sha512", sha512)
        qs.results.setdefault("size", len(data))

        processed_results = keys_string(qs.results)
        rt = json.dumps(processed_results, cls=BytesDump)
        print(str(time.time()) + " qs end convert")

        cacheReport(md5, sha1, sha256, sha512, rt)
        return {
            "statusCode": 200,
            "body": rt,
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "exception", "message": str(e), "uuid": str(file_uuid)}),
        }
