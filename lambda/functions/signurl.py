### QuickSand 2: Python3 Version Copyright (c) 2021 @tylabs
### Lambda function for AWS - sign upload url to send to S3 from a web form

import boto3
import json
from botocore.exceptions import ClientError
import uuid
import config

def create_presigned_post(bucket_name, object_name,
                          fields=None, conditions=None, expiration=3600):
    """Generate a presigned URL S3 POST request to upload a file

    :param bucket_name: string
    :param object_name: string
    :param fields: Dictionary of prefilled form fields
    :param conditions: List of conditions to include in the policy
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Dictionary with the following keys:
        url: URL to post to
        fields: Dictionary of form fields and values to submit with the POST
    :return: None if error.
    """

    # Generate a presigned S3 POST URL
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_post(bucket_name,
                                                     object_name,
                                                     Fields=fields,
                                                     Conditions=conditions,
                                                     ExpiresIn=expiration)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL and required fields
    return response
    

def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """

    # Generate a presigned URL for the S3 object
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response
    
    
def lambda_handler(event, context):
    print(event)
    random = str(uuid.uuid4())
    
    submit_ip = ""
    try:
        submit_ip = event['headers']['x-forwarded-for']
    except:
        None
    filename = ""
    try:
        filename = event['queryStringParameters']['filename']
    except:
        None


    response = create_presigned_post(config.qs_bucket, "new/" + str(random), fields={
        'success_action_redirect': config.qs_url + str(random),
        'x-amz-meta-ip': str(submit_ip),
        'x-amz-meta-filename': str(filename)
    }, conditions=[["starts-with", "$success_action_redirect", ""], ["starts-with", "$x-amz-meta-ip", ""], ["starts-with", "$x-amz-meta-filename", ""]], expiration=3600)
    response['meta'] = {'uuid': random}
    return {'statusCode': 200, 'body': json.dumps( response)}
