### QuickSand 2: Python3 Version Copyright (c) 2021 @tylabs
### Lambda search for hash

import json
import re
import time
import config



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
    try:
        object = config.boto_s3.get_object(Bucket=config.qs_bucket, Key='report/' + str(hash) + ".json")
        data=object['Body'].read()
        print(str(time.time()) + " got report")
    except:
        return json.dumps({"error": "not found", "query": hash})
    return data



def lambda_handler(event, context):
    # TODO implement
    
    query = None
    try:
        query = event['queryStringParameters']['query'].lower()
    except:
        None
    
    report = json.dumps({"error": "not an md5", "query": query})
    if re.match(r'^[a-f0-9]{32}$', query) is not None:
        report = getReport(query)
        
        
    
    
    return {
        'statusCode': 200,
        'body': report
    }
