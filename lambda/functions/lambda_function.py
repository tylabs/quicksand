### QuickSand 2: Python3 Version Copyright (c) 2021 @tylabs
### Lambda function for AWS to process a document with quicksand

import json
from quicksand.quicksand import quicksand
import pprint
import boto3
import botocore
import time
from datetime import datetime, timedelta
import hashlib
import config


def keys_string(d):
    #print(d)
    rval = {}
    if not isinstance(d, dict):
        if isinstance(d,(tuple,list,set)):
            v = [keys_string(x) for x in d]
            return v
        elif isinstance(d,bytes):
           try: 
                return d.decode("utf-8")
           except:
                return d.hex()
        else:
            try: 
                return d.decode("utf-8")
            except:
                return d
    keys = list(d.keys())
    for k in keys:
        v = d[k]
        if isinstance(k,bytes):
            try:
                k = k.decode("utf-8")
            except:
                k = k.hex()
        if isinstance(v,dict):
            v = keys_string(v)
        elif isinstance(v,(tuple,list,set)):
            v = [keys_string(x) for x in v]
        rval[k] = v
    return rval

# The print statements are saved in the AWS lambda function logs

def getFile(uuid):
    print(str(time.time()) + " download file")
    object = config.boto_s3.get_object(Bucket=config.qs_bucket, Key='new/' + uuid)
    data=object['Body'].read()
    filename = ""
    try:
        print(object['Metadata']['filename'])
        filename = object['Metadata']['filename']
    except:
        None
    print(str(time.time()) + " got file")
    return (data, filename)

def cacheReport(hash, data):
    config.boto_s3.put_object(ACL='bucket-owner-full-control', Bucket=config.qs_bucket,
              Key='report/' + str(hash) + ".json",
              Body=data,
              ContentType='application/json')

def checkReportRecent(hash):
   try:
      last_date_time = datetime.now() - timedelta(days = 6)
      config.boto_s3.head_object(Bucket=config.qs_bucket, Key='report/' + str(hash) + ".json", IfModifiedSince=last_date_time)
      return True
   except:
      None
   return False


def getReport(hash):
    print(str(time.time()) + " download report")
    object = config.boto_s3.get_object(Bucket=config.qs_bucket, Key='report/' + str(hash) + ".json")
    data=object['Body'].read()
    print(str(time.time()) + " got report")
    return data


def lambda_handler(event, context):

    uuid = None
    try:
        uuid = event['queryStringParameters']['uuid']
    except:
        None

    rerun = False
    try:
        if event['queryStringParameters']['rerun'] == "1":
           rerun = True
        # todo add a password field
    except:
        None


    try:
      
        if uuid != None:
            print ("getting uuid=" + str(uuid))
            data, filename = getFile(uuid)
            if data == None:
  
                return {
                    'statusCode': 401,
                    'body': "{\"error\": \"file not found in S3\", \"uuid\": \"" + str(uuid) + "\"}"
               }
            md5 = hashlib.md5(data).hexdigest()
        
            if rerun == False and checkReportRecent(md5):
                print("getting cached report for " + str(md5))
                report = getReport(md5)
                print (report)
                return {
                    'statusCode': 200,
                    'body': report
                }
            else:
                print("no cached report for " + str(md5))

            # the default timeout is 29 seconds for a lambda run over API gateway so we time everything

            print(str(time.time()) + " qs start")

            qs = quicksand(data, timeout=18, strings=True, capture=False)
            print(str(time.time()) + " qs process")

            qs.process()
            print(str(time.time()) + " qs end process")

            qs.results['filename'] = filename
            qs.results['uuid'] = uuid
            rt = json.dumps(keys_string(qs.results))
            print(str(time.time()) + " qs end convert")

            cacheReport(qs.results['md5'], rt)
            return {
                'statusCode': 200,
                'body': rt
            }
    except Exception as e:
        return {
            'statusCode': 203,
            'body': "{\"error\": \"exception\", \"message\": \"" + str(e) + "\"}" 

        }

    return {
        'statusCode': 204,
        'body': "{\"error\": \"uuid is missing\"}"
    }
