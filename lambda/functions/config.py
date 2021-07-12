import boto3
import botocore

# General Settings Here


# S3 bucket - don't need the secret if you have given lambda permissions for s3
boto_s3 = boto3.client(
                        's3',
                        region_name='##region###',
                        config=botocore.config.Config(s3={'addressing_style':'path'})
                        )

qs_bucket = '##bucketname###'

qs_url = 'https://scan.tylabs.com/report?uuid='