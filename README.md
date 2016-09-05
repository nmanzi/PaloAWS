# PaloAWS Lambda
`updatenat.py` is an AWS Lambda function designed to do the following:
1. Resolve the IP addresses of configured ELBs
2. Match the IPs with configured Availability Zones
3. Check if the associated Address Object on the PA Firewall residing in the respective Availability Zone matches the
resolved IP
4. Update the Address Objects if the addresses do not match the ELB's IPs
5. Store the resolved IP addresses as JSON in an S3 Bucket to reduce processing time at the next execution
6. Commit the updated PA configuration

## Instructions
Edit the `config/config.py` file to suit your requirements. For the Palo Alto user, consider creating:
* A role on each configured Palo Alto allowing:
    * XML API > Configuration
    * XML API > Operational Requests
    * XML API > Commit
* A user on each configured Palo Alto Firewall configured with the above role

The Lambda requires the following:
* AWS Role with Get/Put Object privileges to the configured S3 Bucket

Configure your AWS Lambda to use the `updatenat.lambda_handler` function, triggered by a CloudWatch Schedule 
(once per minute). The timeout should be set to at least 10 seconds.

This script can also be called outside of an AWS Lambda. You'll need to update the config/config.py file, entering
values for `AWS_REGION`, `AWS_ACCESS_KEY`, and `AWS_SECRET_KEY`.

## Requirements
* boto3
* botocore

This repo contains required packages that are not provided in an AWS Lambda context. These packages are:
* netaddr [https://github.com/drkjam/netaddr]
* pan-python [https://github.com/kevinsteves/pan-python]
* dnslib [https://github.com/paulchakravarti/dnslib]

(If there's a better way to include these packages in this repo, please let me know!)

## Known Issues / TODO
* This could be sped up a lot by only committing at the end of processing.
* We can't yet deal with missing/deleted ELBs, but it's easy to fix.

## Thanks
Thanks go to Paul Chakravarti for dnslib, Kevin Steves for pan-python, and David Moss for netaddr.