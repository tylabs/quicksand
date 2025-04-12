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
                                # Check if elem is a StringMatch object and convert
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
            new_data[key] = keys_string(value)  # Recursively process nested dictionaries
        elif hasattr(value, '__str__'):
            new_data[key] = str(value)
        else:
            new_data[key] = value
    return new_data

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
            #print(qs.results)
            rt = json.dumps(qs.results)
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
