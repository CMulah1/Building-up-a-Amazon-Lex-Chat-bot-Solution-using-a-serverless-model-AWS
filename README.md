# Building-up-a-Amazon-Lex-Chat-bot-Solution-using-a-serverless-model-AWS
Building up a Amazon Lex Chat bot Solution using a serverless model (AWS Lambda) 

AWS Project

By Clovis Mulah

Project Title: Building up a Amazon Lex Chat bot Solution using a 
                           serverless model (AWS Lambda) for HMSHost website.


Note:
The solution document works on AWS SAM [A deployment tool to create serverless app]. I hope you will be able to use this document to use SAM tool and see how you can create the solution easily. Once you create the infrastructure, please go to individual service and inspect the codes and functionalities. 

My references: 

More about SAM: https://github.com/awslabs/serverless-application-model
Install SAM On local Machine : https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html

Project Requirements:

•	Must accurately and clearly indicate to the user if Amazon owns the IPv4 IP address (e.g 1.1.1.1, or 54.158.161.121) provided by the user. 
o	For example, should the user ask: “Does Amazon own 8.8.8.8?” The bot should say something to the effect of: “No, Amazon does not own 8.8.8.8”. Amazon does not own the IP Address 8.8.8.8, and the bot has clearly informed the user of the same.

•	Must reply to at least “Does Amazon own {ip}?”

•	Must gracefully inform the user if an invalid IP address is provided (e.g. 1.1.1.300).

•	Must be publicly accessible (UI only) for verification by AWS staff.


•	Should utilize the sample UI available here[Source]. (deploys UI to S3 to satisfy requirement 3)

•	Should use the official AWS IP Ranges JSON file.
Terms “Must” and “Should” are defined according to RFC 2119 guidelines. So “must” is required, and “should” is (highly) recommended.
What we can help with
•	CloudFormation Template deployment. 
•	The most important step is the parameters being provided to the template.
•	Two ways to create a dictionary (map) in python:
constructed_dict = dict(key1='value1', key2='value2')
liternal_dict = {"key1": "value1", "key2": "value2"}

Validation Process
•	provide a link to the UI for the bot that is deployed via the CloudFormation template.

•	Ask: 
o	Does Amazon own 8.8.8.8? (Bot should indicate that the IP is not owned by Amazon)
o	Does Amazon own 54.158.161.121? (Bot should indicate that the IP is owned by Amazon)
o	Does Amazon own 1.1.1.300? (Bot should indicate that the IP is invalid and ask the user to try again.)
o	Feel free to try with different Ips

Extra Implementation:
•	Account for additional input from the user.
•	Add the ability to determine which AWS Service the IP is allocated to.
•	Add the ability to determine whether or not a network (CIDR block) is owned by Amazon.

Content
Resources
•	UI: CloudFormation Template[Source]
o	Parameters:
	BotName: AwsIpInfoBot
	WebAppConfBotInitialText: Ask me if Amazon owns an IP address! Try saying "Does Amazon own 1.1.1.1?" or "Does Amazon own 54.158.161.121? “
	Ask me if Amazon owns an IP address! Try saying "Does Amazon own 1.1.1.1?" or "Does Amazon own 54.158.161.121? “
	WebAppConfBotInitialSpeech: Say "Does Amazon own 1.1.1.1?"" to get started.
	WebAppConfToolbarTitle: Amazon IP Info Bot



My Implementation Overview


Components
•	User Interface
o	CloudFormation Template
o	JS Application Hosted in S3
•	Lex Bot
o	Single Lambda Function for Validation and Fulfillment. 
o	Validation makes sure the IP is actually a valid IP.
o	Fulfillment calls an API to get information about an IP.
•	API Gateway REST API
o	Single Lambda Function as Proxy Integration back-end for pulling IP Information from ip-ranges.json
o	IP is provided as a query string parameter. (e.g.? ip=1.1.1.1)




Detailed Walkthrough

•	Create a folder on the Desktop to work within. 
o	Mac OS: 
o	mkdir ~/Desktop/techchallenge && cd ~/Desktop/techchallenge
•	Download or move  learnandhiretechchallengecomplete.zip into folder.
o	Mac OS: 
o	aws s3 cp s3://dmselsbucket/learnandhiretechchallengecomplete.zip
•	Unzip, and enter unzipped folder.
o	Mac OS: 
o	unzip learnandhire.zip && cd learnandhire
•	Build SAM Application:
o	Mac OS: 
o	Sam build
•	Package SAM Application and create new template referencing uploaded deployment packages.
o	Mac OS: 
o	Sam package --s3-bucket SC Conroy-Sam-packages --output-template-file template-packaged.yaml
•	Deploy Sam Application:
o	Mac OS: 
o	Sam deploy --template-file template-packaged.yaml --stack-name AmazonIpInfoService-test --capabilities CAPABILITY_IAM


•	Log in to AWS Console
•	Navigate to the Lex Console
•	Click Actions, then Import
•	Provide the following zip file and click Import: AwsIpInfoBot_Bot.zip (included in learnandhiretechchallengecomplete.zip)
•	Once complete, click on the bot name under Bots in the Lex console.
•	Locate and expand the Lambda initialization and validation section of the editor.
•	Check the box next to Initialization and validation code hook, and select the Lambda Function deployed from the previous steps:
o	Lambda Function: The function name will start with “AmazonIpInfoService-LexValidationAndFulfillment-” and will end with a random string of letters and numbers.
o	Version or alias: Latest
•	Under Fulfillment, choose AWS Lambda function, and select the Latest version of the same Lambda function as the previous step.
•	Click Save Intent, at the bottom of the page.
•	Click Build, at the top of the page; confirm by clicking Build again.
o	Once complete, feel free to test the bot by asking “Does Amazon own 1.1.1.1?" and "Does Amazon own 54.158.161.121? “
•	Navigate to the CloudFormation Console
•	Click “Create Stack”



•	Provide the URL for the template, then click Next



•	Under Parameters, set the following; leave the rest as the default value, then click Next:
o	BotName: AwsIpInfoBot
o	WebAppConfBotInitialText: Ask me if Amazon owns an IP address! Try saying "Does Amazon own 1.1.1.1?" or "Does Amazon own 54.158.161.121? “
o	WebAppConfBotInitialSpeech: Say "Does Amazon own 1.1.1.1?"" to get started.
o	WebAppConfToolbarTitle: Amazon IP Info Bot
•	Click Next
•	Scroll to the bottom of the page, make sure the parameters are set correctly, then check the boxes next to:
o	I acknowledge that AWS CloudFormation might create IAM resources with custom names.
o	I acknowledge that AWS CloudFormation might require the following capability: CAPABILITY_AUTO_EXPAND
•	Click Create Stack
•	Once the stack is created, open the link under Output > WebAppUrl
•	Ask the bot “Does Amazon own {ip}?”, replacing {ip} with any IP address. The bot will tell you if Amazon owns it or not. If an invalid IP address is provided, the bot will ask the user to try again.

Code Samples
My SAM Template

AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: Serverless API for asking questions about AWS IP addresses with Lex Bot validation and fulfillment.

# More info about Globals: https://github.com/awslabs/serverless-application-model/blob/master/docs/globals.rst
Globals:
  Function:
    Timeout: 30

Resources:
  AwsIpInfoApiIntegration:
    Type: AWS::Serverless::Function # More info about Function Resource: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#awsserverlessfunction
    Properties:
      CodeUri: ./aws_ips
      Handler: aws_ip_info_api.handler
      Runtime: python3.7
      Events:
        HelloWorld:
          Type: Api # More info about API Event Source: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#api
          Properties:
            Path: /ip-info
            Method: get

  LexValidationAndFulfillment:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: ./lex_codehooks
      Handler: aws_ip_info_lex.handler
      Runtime: python3.7
      Environment:
        Variables:
          API_ENDPOINT: !Sub "https://${ServerlessRestApi}.execute-api.${AWS::Region}.amazonaws.com/Prod/ip-info/"

Outputs:
  # ServerlessRestApi is an implicit API created out of Events key under Serverless::Function
  # Find out more about other implicit resources you can reference within SAM
  # https://github.com/awslabs/serverless-application-model/blob/master/docs/internals/generated_resources.rst#api
  IpInfoApi:
    Description: "API Gateway endpoint URL for Prod stage for IP Info Service."
    Value: !Sub https://${ServerlessRestApi}.execute-api.${AWS::Region}.amazonaws.com/Prod/ip-info/

Lex Lambda Function

"""
Lambda Function for validating user input and fulfilling intents for AwsIp 
"""
import ipaddress
import json
import os

import requests


invalid_ip_message = {
    "contentType": "PlainText",
    "content": "It doesn't seem like that's a valid IP v4 "
               "address. What IP v4 address do you want me to "
               "check, again? "
}


def dialog_handler(event):
    """
    Handles the validation of user input for the Lex Bot.
    Parameter and Return Reference:
    https://docs.aws.amazon.com/lex/latest/dg/lambda-input-response-format.html
    Parameters
    ----------
    event: dict Event object from Lex

    Returns
    -------
    session_attributes, dialog_action: tuple[dict, dict] session attributes and dialog
    action that Lex is expecting.
    """
    session_attributes = event.get('sessionAttributes')
    slots = event.get('currentIntent').get('slots')

    try:
        ipaddress.ip_address(event['currentIntent']['slots']['ip'])
        dialog_action = {
            "type": "Delegate",
            "slots": slots
        }
    except ValueError:
        dialog_action = {
            "type": "ElicitSlot",
            "intentName": "IpInfo",
            "slotToElicit": "ip",
            "message": invalid_ip_message,
        }

    return session_attributes, dialog_action


def fulfillment_handler(event):
    """
    Handles the fulfillment actions for the Lex Bot.
    Parameter and Return Reference:
    https://docs.aws.amazon.com/lex/latest/dg/lambda-input-response-format.html
    Parameters
    ----------
    event: dict Event object from Lex

    Returns
    -------
    session_attributes, dialog_action: tuple[dict, dict] session attributes and dialog
    action that Lex is expecting.
    """
    session_attributes = event.get('sessionAttributes')
    slots = event.get('currentIntent').get('slots')
    ip = slots.get('ip')
    ip_ownership_response = requests.get(
        os.environ['API_ENDPOINT'],
        params={'ip': ip}
    )
    is_amazon_owned = ip_ownership_response.json().get('amazonOwned')

    if is_amazon_owned:
        message = f"Amazon owns {slots.get('ip')}"
    else:
        message = f"Amazon does not own {slots.get('ip')}"

    dialog_action = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "message": {
            "contentType": "PlainText",
            "content": message
        }
    }

    return session_attributes, dialog_action


def handler(event, context):
    """
    Validates and fulfills for AwsIpInfoBot
    Parameter and Return Reference:
    https://docs.aws.amazon.com/lex/latest/dg/lambda-input-response-format.html
    Context reference:
    https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
    Parameters
    ----------
    event: dict Event object from Lex
    context: dict Context object

    Returns
    -------
    response: dict Full response to Lex service in the expected format.
    """
    print('API Andpoint:', os.environ['API_ENDPOINT'])
    print(json.dumps(event, indent=4))

    invoke_source = event['invocationSource']

    if not event['currentIntent']['name'] == 'IpInfo':
        raise ValueError('Unknown Intent.')

    if invoke_source == 'DialogCodeHook':
        session_attributes, dialog_action = dialog_handler(event)

    elif invoke_source == 'FulfillmentCodeHook':
        session_attributes, dialog_action = fulfillment_handler(event)
    else:
        raise ValueError('Unknown invocationSource.')

    response = dict(
        sessionAttributes=session_attributes,
        dialogAction=dialog_action
    )
    return response
Lex Lambda with Extra implementation

"""
Lambda Function for validating user input and fulfilling intents for AwsIp 
"""
import ipaddress
import json
import os

import requests


invalid_ip_message = {
    "contentType": "PlainText",
    "content": "It doesn't seem like that's a valid IP v4 "
               "address. What IP v4 address do you want me to "
               "check, again? "
}


invalid_network_message = {
    "contentType": "PlainText",
    "content": "It doesn't seem like that's a valid IP v4 "
               "CIDR block. What IP v4 network do you want me to "
               "check, again?"
}


def validate_ip(intent, event, slots):
    try:
        ipaddress.ip_address(event['currentIntent']['slots']['ip'])
        return {
            "type": "Delegate",
            "slots": slots
        }
    except ValueError:
        return {
            "type": "ElicitSlot",
            "intentName": intent,
            "slotToElicit": "ip",
            "message": invalid_ip_message,
        }


def validate_network(intent, event, slots):
    try:
        ipaddress.ip_network(event['currentIntent']['slots']['network'])
        return {
            "type": "Delegate",
            "slots": slots
        }
    except ValueError:
        return {
            "type": "ElicitSlot",
            "intentName": intent,
            "slotToElicit": "network",
            "message": invalid_network_message,
        }


def is_amzn_ip(slots):
    ip = slots.get('ip')
    ip_ownership_response = requests.get(
        os.environ['API_ENDPOINT'],
        params={'ip': ip}
    )
    is_amazon_owned = ip_ownership_response.json().get('amazonOwned')
    if is_amazon_owned:
        message = f"Amazon owns {slots.get('ip')}"
    else:
        message = f"Amazon does not own {slots.get('ip')}"
    dialog_action = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "message": {
            "contentType": "PlainText",
            "content": message
        }
    }
    return dialog_action


def get_ip_service(slots):
    ip = slots.get('ip')
    ip_ownership_response = requests.get(
        os.environ['API_ENDPOINT'],
        params={
            'ip': ip,
            'detail': 'service'
        }
    )
    is_amazon_owned = ip_ownership_response.json().get('amazonOwned')
    service = ip_ownership_response.json().get('service')
    if is_amazon_owned and service:
        message = f"The IP {slots.get('ip')} is used by the {service} service."
    elif is_amazon_owned and not service:
        message = f"Amazon owns {slots.get('ip')}, but no specific service uses it."
    elif not is_amazon_owned:
        message = f"Amazon does not own {slots.get('ip')}"
    else:
        message = 'Something went very wrong on my end; please try that again.'
    dialog_action = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "message": {
            "contentType": "PlainText",
            "content": message
        }
    }
    return dialog_action


def is_amzn_network(slots):
    network = slots.get('network')
    network_ownership_response = requests.get(
        os.environ['API_ENDPOINT'],
        params={'network': network}
    )
    is_amazon_owned = network_ownership_response.json().get('amazonOwned')
    if is_amazon_owned:
        message = f"Amazon owns {slots.get('network')}"
    else:
        message = f"Amazon does not own {slots.get('network')}"
    dialog_action = {
        "type": "Close",
        "fulfillmentState": "Fulfilled",
        "message": {
            "contentType": "PlainText",
            "content": message
        }
    }
    return dialog_action


def dialog_handler(event):
    """
    Handles the validation of user input for the Lex Bot.
    Parameter and Return Reference:
    https://docs.aws.amazon.com/lex/latest/dg/lambda-input-response-format.html
    Parameters
    ----------
    event: dict Event object from Lex

    Returns
    -------
    session_attributes, dialog_action: tuple[dict, dict] session
    attributes and dialog action that Lex is expecting.
    """
    dialog_action = dict()
    session_attributes = event.get('sessionAttributes')
    slots = event.get('currentIntent').get('slots')
    intent = event['currentIntent']['name']

    if intent == 'IpInfo':
        dialog_action = validate_ip(intent, event, slots)
    elif intent == 'IpService':
        dialog_action = validate_ip(intent, event, slots)
    elif intent == 'AmznNetwork':
        dialog_action = validate_network(intent, event, slots)

    return session_attributes, dialog_action


def fulfillment_handler(event):
    """
    Handles the fulfillment actions for the Lex Bot.
    Parameter and Return Reference:
    https://docs.aws.amazon.com/lex/latest/dg/lambda-input-response-format.html
    Parameters
    ----------
    event: dict Event object from Lex

    Returns
    -------
    session_attributes, dialog_action: tuple[dict, dict] session attributes and dialog
    action that Lex is expecting.
    """
    session_attributes = event.get('sessionAttributes')
    slots = event.get('currentIntent').get('slots')
    intent = event['currentIntent']['name']

    if intent == 'IpInfo':
        dialog_action = is_amzn_ip(slots)
    elif intent == 'IpService':
        dialog_action = get_ip_service(slots)
    elif intent == 'AmznNetwork':
        dialog_action = is_amzn_network(slots)
    else:
        raise ValueError('Unknown Intent.')

    return session_attributes, dialog_action


def lambda_handler(event, context):
    """
    Validates and fulfills for AwsIpInfoBot
    Parameter and Return Reference:
    https://docs.aws.amazon.com/lex/latest/dg/lambda-input-response-format.html
    Context reference:
    https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html
    Parameters
    ----------
    event: dict Event object from Lex
    context: dict Context object

    Returns
    -------
    response: dict Full response to Lex service in the expected format.
    """
    print('API Andpoint:', os.environ['API_ENDPOINT'])
    print(json.dumps(event, indent=4))

    invoke_source = event['invocationSource']

    if not event['currentIntent']['name'] in ['IpInfo', 'IpService', 'AmznNetwork']:
        raise ValueError('Unknown Intent.')

    if invoke_source == 'DialogCodeHook':
        session_attributes, dialog_action = dialog_handler(event)

    elif invoke_source == 'FulfillmentCodeHook':
        session_attributes, dialog_action = fulfillment_handler(event)
    else:
        raise ValueError('Unknown invocationSource.')

    response = dict(
        sessionAttributes=session_attributes,
        dialogAction=dialog_action
    )
    return response
API Gateway Proxy Integrated lambda

import ipaddress
import json
from botocore.vendored import requests

json_url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'

# Retrieves the JSON file from the public location. 
get_json_response = requests.get(json_url)
prefix_list = get_json_response.json()['prefixes']


def get_all_prefixes():
    """
    Gathers all the prefixes (e.g. 0.0.0.0/32) from the JSON file in to a set.
    
    Returns
    -------
    prefixes: set 
    """
    prefixes = set()
    for prefix in prefix_list:
        prefixes.add(prefix['ip_prefix'])
    return prefixes


def is_aws_ip(ip):
    """
    Checks each prefix in a set of all AWS prefixes to see if the IP address
    is included in the prefix. If so, returns True, otherwise returns False
    
    Parameters
    ----------
    ip: ipaddress.IPv4Address The IP address to check.

    Returns
    -------
    aws_ip: boolean
    """
    if not isinstance(ip, ipaddress.IPv4Address) or not isinstance(ip, ipaddress.IPv6Address):
        ip = ipaddress.ip_address(ip)
    aws_ip = False
    prefixes = get_all_prefixes()
    for prefix in prefixes:
        prefix = ipaddress.ip_network(prefix)
        if prefix.__contains__(ip):
            aws_ip = True
    return aws_ip


def handler(event, context):
    """
    Checks an Amazon IP Address against the public JSON file at
    https://ip-ranges.amazonaws.com/ip-ranges.json
    """

    user_ip = event['queryStringParameters']['ip']

    response_body = {
        "amazonOwned": is_aws_ip(user_ip),
    }

    return {
        "statusCode": 200,
        "body": json.dumps(response_body),
    }
API Gateway Proxy Integrated Lambda with Extra Challenges:

import ipaddress
import json
from botocore.vendored import requests

json_url = 'https://ip-ranges.amazonaws.com/ip-ranges.json'

# Retrieves the JSON file from the public location.
get_json_response = requests.get(json_url)
prefix_list = get_json_response.json()['prefixes']


def get_all_prefixes():
    """
    Gathers all the prefixes (e.g. 0.0.0.0/32) from the JSON file in to a set.

    Returns
    -------
    prefixes: set
    """
    prefixes = set()
    for prefix in prefix_list:
        prefixes.add(prefix['ip_prefix'])
    return prefixes


def get_ip_network(ip):
    """
    Checks each prefix in a set of all AWS prefixes to see if the IP address
    is included in the prefix. If so, returns True, otherwise returns False

    Parameters
    ----------
    ip: ipaddress.IPv4Address The IP address to check.

    Returns
    -------
    aws_ip: boolean
    """
    if not isinstance(ip, ipaddress.IPv4Address) or not isinstance(ip, ipaddress.IPv6Address):
        ip = ipaddress.ip_address(ip)
    ip_prefix = set()
    prefixes = get_all_prefixes()
    for prefix in prefixes:
        prefix = ipaddress.ip_network(prefix)
        if prefix.__contains__(ip):
            ip_prefix.add(prefix)
    return ip_prefix


def get_ip_service(ip):
    if not isinstance(ip, ipaddress.IPv4Address) or not isinstance(ip, ipaddress.IPv6Address):
        ip = ipaddress.ip_address(ip)
    ip_service = None
    for aws_prefix in prefix_list:
        ip_prefix = ipaddress.ip_network(aws_prefix['ip_prefix'])
        if ip_prefix.__contains__(ip):
            prefix_service = aws_prefix.get('service')
            ip_service = prefix_service if prefix_service != 'AMAZON' else None
    return ip_service


def is_aws_ip(ip):
    """
    Checks each prefix in a set of all AWS prefixes to see if the IP address
    is included in the prefix. If so, returns True, otherwise returns False

    Parameters
    ----------
    ip: ipaddress.IPv4Address The IP address to check.

    Returns
    -------
    is_aws_owned: boolean
    """
    if not isinstance(ip, ipaddress.IPv4Address) or not isinstance(ip, ipaddress.IPv6Address):
        ip = ipaddress.ip_address(ip)
    is_aws_owned = False
    prefixes = get_all_prefixes()
    for prefix in prefixes:
        prefix = ipaddress.ip_network(prefix)
        if prefix.__contains__(ip):
            is_aws_owned = True
    return is_aws_owned


def is_aws_prefix(prefix):
    """
    Checks each prefix in a set of all AWS prefixes to see if the IP address
    is included in the prefix. If so, returns True, otherwise returns False

    Parameters
    ----------
    prefix: ipaddress.IPv4Network The network to check.

    Returns
    -------
    is_aws_owned: boolean
    """
    if not isinstance(prefix, ipaddress.IPv4Network) or not isinstance(prefix, ipaddress.IPv6Network):
        prefix = ipaddress.ip_network(prefix)
    is_aws_owned = False
    owned_aws_prefix = None
    prefixes = get_all_prefixes()
    for aws_prefix in prefixes:
        aws_prefix = ipaddress.ip_network(aws_prefix)
        if prefix.subnet_of(aws_prefix) or aws_prefix == prefix:
            is_aws_owned = True
            owned_aws_prefix = aws_prefix
    return is_aws_owned, owned_aws_prefix


def handler(event, context):
    """
    Checks an Amazon IP Address against the public JSON file at
    https://ip-ranges.amazonaws.com/ip-ranges.json
    """

    response_body = dict()
    user_ip = event.get('queryStringParameters').get('ip')
    user_network = event.get('queryStringParameters').get('network')
    detail = event.get('queryStringParameters').get('detail')

    if not user_ip and not user_network:
        error_response = {
            "error": "Bad Request",
            "message": 'Query parameter ip or network is required.'
        }
        return {
            "statusCode": 400,
            "body": json.dumps(error_response),
        }
    elif user_ip:
        response_body.update(ip=user_ip)
        response_body.update(amazonOwned=is_aws_ip(user_ip))
    elif user_network:
        response_body.update(network=user_network)
        amazon_owned, aws_prefix = is_aws_prefix(user_network)
        response_body.update(amazonOwned=amazon_owned)
        if amazon_owned:
            response_body.update(amazonPrefix=str(aws_prefix))

    if detail == 'service':
        response_body.update(service=get_ip_service(user_ip))

    return {
        "statusCode": 200,
        "body": json.dumps(response_body),
    }
Custom Slot Type:

{
  "metadata": {
    "schemaVersion": "1.0",
    "importType": "LEX",
    "importFormat": "JSON"
  },
  "resource": {
    "description": "An Internet Protocol Version 4 address.",
    "name": "IpVersionFourAddress",
    "version": "1",
    "enumerationValues": [
      {
        "value": "6.6.6.6",
        "synonyms": []
      },
      {
        "value": "7.7.7.7",
        "synonyms": []
      },
      {
        "value": "8.8.8.8",
        "synonyms": []
      },
      {
        "value": "9.9.9.9",
        "synonyms": []
      },
      {
        "value": "1.1.1.1",
        "synonyms": []
      },
      {
        "value": "2.2.2.2",
        "synonyms": []
      },
      {
        "value": "3.3.3.3",
        "synonyms": []
      },
      {
        "value": "4.4.4.4",
        "synonyms": []
      },
      {
        "value": "5.5.5.5",
        "synonyms": []
      },
      {
        "value": "255.255.255.255",
        "synonyms": []
      },
      {
        "value": "100.100.100.100",
        "synonyms": []
      },
      {
        "value": "10.10.10.10",
        "synonyms": []
      }
    ],
    "valueSelectionStrategy": "ORIGINAL_VALUE"
  }
}
Lex Intent (Includes Slot Type)

{
  "metadata": {
    "schemaVersion": "1.0",
    "importType": "LEX",
    "importFormat": "JSON"
  },
  "resource": {
    "name": "IpInfo",
    "version": "2",
    "fulfillmentActivity": {
      "codeHook": {
        "uri": "arn:aws:lambda:us-east-1:069768089450:function:AmazonIpInfoService-LexValidationAndFulfillment-1U7L6DUY3OVPQ",
        "messageVersion": "1.0"
      },
      "type": "CodeHook"
    },
    "sampleUtterances": [
      "Does Amazon own {ip}"
    ],
    "slots": [
      {
        "sampleUtterances": [],
        "slotType": "IpVersionFourAddress",
        "slotTypeVersion": "1",
        "slotConstraint": "Required",
        "valueElicitationPrompt": {
          "messages": [
            {
              "contentType": "PlainText",
              "content": "What IP Address do you want to check ownership of?"
            }
          ],
          "maxAttempts": 2
        },
        "priority": 1,
        "name": "ip"
      }
    ],
    "dialogCodeHook": {
      "uri": "arn:aws:lambda:us-east-1:069768089450:function:AmazonIpInfoService-LexValidationAndFulfillment-1U7L6DUY3OVPQ",
      "messageVersion": "1.0"
    },
    "slotTypes": [
      {
        "description": "An Internet Protocol Version 4 address.",
        "name": "IpVersionFourAddress",
        "version": "1",
        "enumerationValues": [
          {
            "value": "6.6.6.6",
            "synonyms": []
          },
          {
            "value": "7.7.7.7",
            "synonyms": []
          },
          {
            "value": "8.8.8.8",
            "synonyms": []
          },
          {
            "value": "9.9.9.9",
            "synonyms": []
          },
          {
            "value": "1.1.1.1",
            "synonyms": []
          },
          {
            "value": "2.2.2.2",
            "synonyms": []
          },
          {
            "value": "3.3.3.3",
            "synonyms": []
          },
          {
            "value": "4.4.4.4",
            "synonyms": []
          },
          {
            "value": "5.5.5.5",
            "synonyms": []
          },
          {
            "value": "255.255.255.255",
            "synonyms": []
          },
          {
            "value": "100.100.100.100",
            "synonyms": []
          },
          {
            "value": "10.10.10.10",
            "synonyms": []
          }
        ],
        "valueSelectionStrategy": "ORIGINAL_VALUE"
      }
    ]
  }
}
Template source: https://github.com/CMulah1

