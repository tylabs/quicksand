### QuickSand 2: Python3 Version Copyright (c) 2021-2026 @tylabs
### Lambda search for hash

from datetime import datetime, timedelta
import json
import re
import time

import config


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
    print(str(time.time()) + " download report")
    try:
        obj = config.boto_s3.get_object(
            Bucket=config.qs_bucket,
            Key="report/" + str(hash_val) + ".json",
        )
        data = obj["Body"].read().decode("utf-8")
        print(str(time.time()) + " got report")
        return data, 200
    except Exception:
        return json.dumps({"error": "not found", "query": hash_val}), 404


def lambda_handler(event, context):
    params = (event or {}).get("queryStringParameters") or {}
    raw_query = params.get("query")
    if not raw_query:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "query parameter is missing"}),
        }

    query = re.sub(r"<[^>]+>", "", str(raw_query)).strip().lower()
    if re.match(r"^[a-f0-9]{32,128}$", query) is None:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "invalid hash format", "query": query}),
        }

    report, status_code = getReport(query)
    return {
        "statusCode": status_code,
        "body": report,
    }
