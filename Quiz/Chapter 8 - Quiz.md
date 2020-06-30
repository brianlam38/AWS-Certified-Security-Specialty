## Which of the following must be in place in order for an EC2 instance to successfully send logs to CloudWatch logs? (Choose 2)

```
>> The EC2 instance role must have permission to write to CloudWatch Logs
>> The CloudWatch agent must be running
Your IAM user must have permission to write to CloudWatch Logs
The EC2 instance role must have permission to read CloudWatch Logs
The CloudTrail must be enabled
```

## You are trying to configure cross account access to enable your development team to access S3 objects in your production account. However when one of your developers performs a test, they are not able to access the objects. What could the problem be? (Choose 2)

```
The Production account does not have permission to call STS:AssumeRole
>> The Development account does not have permission to call STS:AssumeRole
>> The Development account is not a trusted entity
The Production account is not a trusted entity
```

In order to set this up you will need to:
* Configure an __IAM Role w/ permissions to access the S3 bucket__ in the PROD ACCOUNT.
* Configure the DEV ACCOUNT as a __trusted entity__.
* Ensure that the DEV ACCOUNT __IAM permission to call the STS:AssumeRole API__.

## You are trying to configure Active Directory Federation to allow your AD users to access your AWS resources. You cannot get it to work as expected. You are reviewing the CloudTrail Logs to check which STS API calls are being made. Which STS API call should you look out for?

```
STS:AssumeRole
>> STS:AssumeRoleWithSAML
STS:ChangeRole
STS:AssumeRoleWithWebIdentity
```

AssumeRoleWithSAML returns a set of temporary security credentials for users who have been authenticated via a SAML authentication response, Active Directory is SAML 2 compliant.

## Which of the following policies would you use to define which AWS resources are permitted to invoke a Lambda function?

```
>> Function policy
Execution role policy
The resource policy of the event source which triggers the function
The IAM policy of the user who owns the event source which trigger the function
```

* Function Policy: defines which __AWS resources are allowed to invoke a Lambda function__.
* Execution Role: defines which __resources your Lambda function has access to__.

## You are trying to create a public subnet in your VPC you have added an Internet Gateway and configured the relevant Security Groups and Network ACLs, however you are still unable to access any of the web servers in your subnet over the internet. What could be the problem?

```
Your web servers are not behind an Elastic Load Balancer
You didn't configure the routing table in your peered VPC
You haven't configured a route to the internet via the Virtual Private Gateway
>> You haven't configured a route to the internet via the Internet Gateway
```

To enable Internet access, you must do the following things:
1. Attach an internet gateway to your VPC.
2. Ensure that your __subnet's route table points to the internet gateway__.
3. Ensure that your network access control and security group rules allow the relevant traffic to flow to and from your instance.
4. Ensure that instances in your subnet have a globally unique IP address (public IPv4 address, Elastic IP address, or IPv6 address).

## You are logged into the AWS console and you are attempting to access the CloudWatch dashboard, however you are not able to do so. What could the problem be?

```
You do not have the required IAM permissions to access the CloudWatch console
CloudWatch has not been enabled
The CloudWatch agent has not been installed on your EC2 instances
You have selected the wrong Region
```

