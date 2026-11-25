### QuickSand 2: Python3 Version Copyright (c) 2021-2026 @tylabs
### Lambda search for hash (strictly SHA-256 or SHA-512)

from datetime import datetime, timedelta
import json
import re
import time

import config

RE_SHA256 = re.compile(r"^[a-f0-9]{64}$")
RE_STRONG_HASH = re.compile(r"^(?:[a-f0-9]{64}|[a-f0-9]{128})$")


def checkReportRecent(hash_val):
    norm = (hash_val or "").strip().lower()
    if not RE_STRONG_HASH.fullmatch(norm):
        return False
    try:
        last_date_time = datetime.now() - timedelta(days=6)
        config.boto_s3.head_object(
            Bucket=config.qs_bucket,
            Key="report/" + norm + ".json",
            IfModifiedSince=last_date_time,
        )
        return True
    except Exception:
        return False


def getReport(hash_val):
    print(str(time.time()) + " download report")
    try:
        obj = config.boto_s3.get_object(
            Bucket=config.qs_bucket,
            Key="report/" + str(hash_val) + ".json",
        )
        data = obj["Body"].read().decode("utf-8")
        try:
            parsed = json.loads(data)
        except Exception:
            parsed = None
        if isinstance(parsed, dict) and "_alias_sha256" in parsed:
            alias_target = str(parsed.get("_alias_sha256") or "").strip().lower()
            if not RE_SHA256.fullmatch(alias_target):
                return json.dumps({"error": "not found"}), 404
            target_obj = config.boto_s3.get_object(
                Bucket=config.qs_bucket,
                Key="report/" + alias_target + ".json",
            )
            target_data = target_obj["Body"].read().decode("utf-8")
            target_parsed = json.loads(target_data)
            if isinstance(target_parsed, dict) and "_alias_sha256" in target_parsed:
                return json.dumps({"error": "not found"}), 404
            return target_data, 200
        print(str(time.time()) + " got report")
        return data, 200
    except Exception as e:
        print(f"Error retrieving report for {hash_val}: {e}")
        return json.dumps({"error": "not found"}), 404


def lambda_handler(event, context):
    params = (event or {}).get("queryStringParameters") or {}
    raw_query = params.get("query")
    if not raw_query:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "query parameter is missing"}),
        }

    query = str(raw_query).strip().lower()
    if RE_STRONG_HASH.fullmatch(query) is None:
        return {
            "statusCode": 400,
            "body": json.dumps(
                {"error": "invalid hash format; provide a 64-char SHA-256 or 128-char SHA-512 hex digest"}
            ),
        }

    report, status_code = getReport(query)
    return {
        "statusCode": status_code,
        "body": report,
    }
