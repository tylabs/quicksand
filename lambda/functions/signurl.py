### QuickSand 2: Python3 Version Copyright (c) 2021-2026 @tylabs
### Lambda function for AWS - sign upload url to send to S3 from a web form

import ipaddress
import json
import logging
import os
import re
import uuid

import boto3
from botocore.exceptions import ClientError
import config

MAX_UPLOAD_BYTES = int(os.environ.get("QS_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
RE_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\r\n]")
RE_NON_IP_CHARS = re.compile(r"[^0-9a-fA-F.:]")


def _sanitize_ip(raw_ip):
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


def _sanitize_filename(raw_filename):
    if not raw_filename:
        return "unknown"
    no_ctrl = RE_CONTROL_CHARS.sub("", str(raw_filename))
    base = re.split(r"[/\\]", no_ctrl)[-1].replace("/", "").replace("\\", "").strip()
    if not base or base in (".", ".."):
        return "unknown"
    return base[:255]


def create_presigned_post(bucket_name, object_name,
                          fields=None, conditions=None, expiration=3600):
    """Generate a presigned URL S3 POST request to upload a file."""
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_post(
            bucket_name,
            object_name,
            Fields=fields,
            Conditions=conditions,
            ExpiresIn=expiration,
        )
    except ClientError as e:
        logging.error(e)
        return None

    return response


def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object."""
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': object_name},
            ExpiresIn=expiration,
        )
    except ClientError as e:
        logging.error(e)
        return None

    return response


def lambda_handler(event, context):
    random_uuid = str(uuid.uuid4())

    headers = (event or {}).get('headers') or {}
    raw_ip = (
        headers.get('x-forwarded-for')
        or headers.get('X-Forwarded-For')
        or ''
    )
    submit_ip = _sanitize_ip(str(raw_ip).split(",")[0].strip())

    params = (event or {}).get('queryStringParameters') or {}
    raw_filename = params.get('filename') or ''
    filename = _sanitize_filename(raw_filename)
    redirect_target = str(config.qs_url) + str(random_uuid)

    effective_max_bytes = MAX_UPLOAD_BYTES
    raw_max = params.get('maxBytes')
    if raw_max is not None:
        try:
            parsed_max = int(raw_max)
            if 1 <= parsed_max <= MAX_UPLOAD_BYTES:
                effective_max_bytes = parsed_max
        except (ValueError, TypeError):
            pass

    response = create_presigned_post(
        config.qs_bucket,
        "new/" + str(random_uuid),
        fields={
            'success_action_redirect': redirect_target,
            'x-amz-meta-ip': submit_ip,
            'x-amz-meta-filename': filename,
        },
        conditions=[
            ["content-length-range", 0, effective_max_bytes],
            {"success_action_redirect": redirect_target},
            {"x-amz-meta-ip": submit_ip},
            {"x-amz-meta-filename": filename},
        ],
        expiration=900,
    )
    if response is None:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Failed to generate presigned POST URL'}),
        }

    response['meta'] = {'uuid': random_uuid}
    return {'statusCode': 200, 'body': json.dumps(response)}
