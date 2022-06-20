import boto3
import json
import logging
import botocore.exceptions as boto3exceptions

logger = logging.getLogger()
logger.setLevel(logging.INFO)
security_hub_client = boto3.client('securityhub')


'''
Update the finding status in Security Hub
'''

def process_findings(findingIdentifier):
    try:
        response = security_hub_client.batch_update_findings(
            FindingIdentifiers = findingIdentifier,
            Workflow = {
                'Status': 'NOTIFIED'
            },
            Note = {
                "Text": "This finding has been published to pagerGuty SNS. Findings for this resource have been set to NOTIFIED.",
                "UpdatedBy": "WorkflowStatusUpdater"
            }
        )
    except boto3exceptions.ClientError as error:
        logger.exception("client error")
        raise ConnectionError(f"Client error invoking batch update findings {error}")
    except boto3exceptions.ParamValidationError as error:
        logger.exception("invalid parameters")
        raise ValueError(f"The parameters you provided are incorrect: {error}")

def lambda_handler(event, context):
    resource_ids = []
    print("Received event: " + json.dumps(event, indent=2))
    for record in event["Records"]:
        message = json.loads(record["Sns"]["Message"])
        print("Received message: " + json.dumps(message, indent=2))
        for finding in message['detail']['findings']:
            findingIdentifier=[{
                    'Id': finding["Id"],
                    'ProductArn': finding["ProductArn"]
                }]
            process_findings(findingIdentifier)

    return {"statusCode" : 200}