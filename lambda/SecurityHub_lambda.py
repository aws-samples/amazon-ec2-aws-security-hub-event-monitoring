import boto3
import re
import time
import csv
import logging
from datetime import datetime
from botocore.exceptions import ClientError
#
# Initializing clients for CloudWatch Logs, Security Hub and S3.
# Please change the region to the region where you are deploying this
logs_client = boto3.client('logs', 'ap-southeast-1')
sh_client = boto3.client('securityhub', 'ap-southeast-1')
s3client = boto3.client('s3', 'ap-southeast-1')
# Destination S3 Bucket for storing output
S3bucket ='security-findings-ss'
# file_name variable: File name of the csv file for saving the output of the CloudWatch Log Insights in S3
# file_path variable: Adding path of the file
file_name = str(int(time.time()))+".csv"
file_path='/tmp/{}'.format(file_name)
#
def exportToS3(content): #Function to create a report in csv format to upload to S3
    headers=['SRC_IP','Hostname', 'Count_Of_Errors'] # Defining headers of the csv file
    with open(file_path, 'w') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(headers)
        for readings in content:
            row_value_list=[]
            for value_list in readings:
                row_value_list.append(value_list['value'])
            csv_writer.writerow(row_value_list)
    csvfile = open(file_path,'rb')
    try:
        response_upload=s3client.put_object(Body=csvfile, Bucket=S3bucket, Key=file_name) #Upload to S3
    except ClientError as e:
        logging.error(e)
#
def runCWInsightsquery(): #Function to run CloudWatch query 
    period_in_min=600 # Time period in Minutes for which to analyze the CloudWatch Logs
    start_at=int(time.time() - period_in_min*60)
    end_at=int(time.time())
    response = logs_client.start_query(logGroupName ='secure', queryString= 'fields @timestamp, @message|filter @message like /(?=.*Connection)(?=.*preauth)/ | parse @message /(?<SRC_IP>[.]* ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[.]*)/ | parse @message /(?<Host>[.]* (ip\-[0-9]{1,3}\-[0-9]{1,3}\-[0-9]{1,3}\-[0-9]{1,3})[.]*)/ | stats count(*) by SRC_IP, Host', startTime=start_at, endTime=end_at)
    output = logs_client.get_query_results(queryId=response['queryId'])
    while  output['status'] != 'Complete':
        time.sleep(3)
        output = logs_client.get_query_results(queryId=response['queryId'])
    queryResult = output['results']
    exportToS3(queryResult)
    hosts=[]
    for entry in queryResult:
        hosts.append(entry[1]['value'])
    unique_hosts=list(set(hosts))
    str_hosts=str(unique_hosts).replace('[','').replace(']','')
    msgstring='Possible ssh brute force attack on '+ str_hosts # This string will be published in Security Hub
    return (msgstring)
##
def process_event(sns_alarm): # Function to process the SNS Event and publish findings to Security Hub
    cwfindings=[]
    message_SH = runCWInsightsquery()
    sns_id=sns_alarm['Records'][0]['Sns']['MessageId']
    region=sns_alarm['Records'][0]['EventSubscriptionArn'].split(":")[3]
    account_id=sns_alarm['Records'][0]['EventSubscriptionArn'].split(":")[4]
    event_time=sns_alarm['Records'][0]['Sns']['Timestamp']
    update_time=datetime.now().astimezone().isoformat()
    event_Subject=sns_alarm['Records'][0]['Sns']['Subject']
    alarm_arn=sns_alarm['Records'][0]['Sns']['Message'].split(",")[7]
    # Writng these findings to Security Hub
    cwfindings.append({
        "SchemaVersion": "2018-10-08",
        "Id": sns_id,
        "ProductArn": "arn:aws:securityhub:{0}:{1}:product/{1}/default".format(region, account_id),
        "GeneratorId": alarm_arn,
        "AwsAccountId": account_id,
        "Types": [
            "Software and Configuration Checks/AWS CloudWatch Insights"
        ],
        "CreatedAt": event_time,
        "UpdatedAt": update_time,
        "Severity": {
                "Label": "HIGH",
                "Product": 10
        },
        "Title": event_Subject,
        "Description": message_SH,
        'Remediation': {
            'Recommendation': {
                'Text': 'Please investigate source IPs logged in file {} in the {} bucket .'.format(file_name, S3bucket)
            }
        },
        'Resources': [
            {
                'Id': alarm_arn,
                'Type': "EC2 CloudWatch logs",
                'Partition': "aws",
                'Region': region
            }
        ]
    })
    if cwfindings:
        try:
            sh_response = sh_client.batch_import_findings(Findings=cwfindings)
            print(sh_response)
            if sh_response['FailedCount'] > 0:
                print("Failed to import {} findings".format(sh_response['FailedCount']))
        except Exception as error:
            print("Error: ", error)
            raise
##
def lambda_handler(event, context):
    process_event(event)