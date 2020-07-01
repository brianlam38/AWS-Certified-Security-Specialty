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
>> You do not have the required IAM permissions to access the CloudWatch console
CloudWatch has not been enabled
The CloudWatch agent has not been installed on your EC2 instances
You have selected the wrong Region
```

## You have configured a Lambda function to deal with unauthorized EC2 instances by terminating them immediately. A number of unauthorized EC2 instances were created in your account over the weekend which has triggered a number of CloudWatch Events. However by Monday morning, these instances are still running and have not been terminated. What could be the reason for this? (Choose 2)

```
Your IAM user account does not have permission to read the CloudTrail logs
The Lambda function does not have permission to read CloudWatch events
Your IAM user does not have permission to terminate EC2 instances
CloudTrail does not have permission to send events to CloudWatch Events
>> The Lambda function does not have permission to terminate EC2 instances
>> CloudWatch events does not have permission to invoke the Lambda function
``` 

## You have configured a new VPC with a private subnet and added a NAT Gateway and configured the subnet route table to route all internet traffic via the NAT Gateway. However when you try to run a yum update, none of your instances are able to reach the internet. What could be the problem?

```
You have forgotten to configure an outbound Security Group rule allowing outbound HTTPS traffic to 0.0.0.0/0 and an inbound Security Group rule allowing incoming HTTPS traffic from 0.0.0.0/0

You have forgotten to configure an inbound Security Group rule allowing incoming HTTPS traffic from 0.0.0.0/0

>> You have forgotten to configure an outbound Security Group rule allowing outbound HTTPS traffic to 0.0.0.0/0

Create Network ACLs allowing incoming traffic on ports 80 and 443 from 0.0.0.0/0
```

Security Groups are __stateful__ so you only need to configure the __outbound rule__ and any incoming response will also be allowed.

Security group characteristics:
* By default, security groups allow all outbound traffic.
* Security group rules are always permissive; you can't create rules that deny access.
*  Security groups are stateful — if you send a request from your instance, the __RESPONSE TRAFFIC FOR THAT REQUEST__ is allowed to flow in regardless of inbound security group rules. For VPC security groups, this also means that responses to allowed inbound traffic are allowed to flow out, regardless of outbound rules. For more information, see Connection tracking.

The NACL rules mentioned will not fix the problem because:
* they relate to inbound traffic only; and
* are not appropriate for a private subnet.

## You are attempting to decrypt a file which you have already successfully encrypted using your CMK, however when you try to decrypt you are not authorized to do so. Which policy should you check?

```
The CMK Key policy
The S3 bucket policy
>> The IAM policy attached to your user
The S3 Access Control Lis
```

Access to use KMS CMKs is controlled by the Key Policy which defines who the key users and key administrators are, and also the user's IAM Policy which defines which API calls the user is authorized to perform.

In this case, the __user does NOT have permission to call the kms:Decrypt API__.

## Your Lambda function is successfully completing and is returning a status code of 200, however no logs are appearing in CloudWatch Logs. What could be the problem?

```
>> Lambda does not have permission to write logs to CloudWatch
Lambda does not have permission to write to CloudTrail
CloudWatch Logs are not real-time, if you wait 15 minutes, the logs should appear
CloudWatch does not have permission to invoke the Lambda function
```

In order to PUBLISH LOGS to CloudWatch, the __Lambda Execution role requires permission__ to do so. If you created your function using the AWS console, you can use the console to create a role including these permissions by default.

## You have written a Lambda function designed to attach a restrictive IAM policy denying access to create EC2 instances to any user found to be creating unauthorized Internet Gateways in your secure VPC. However, during testing you find that the function doesn't work as expected and the user's permissions remain the same. Which of the following would you to do to investigate this?

```
Check the Function Policy allows permission to update the IAM policy and attach it to the user
Check the Execution Policy allows permission to update the IAM policy and attach it to the user
>> Check the Execution Role allows permission to update the IAM policy and attach it to the user
Check the Function Role allows permission to update the IAM policy and attach it to the user
```

Lambda EXECUTION ROLE = grant permission for __Lambda to access AWS services and resources__.
* Execution Role is created or provided during Lambda creation.

Lambda FUNCTION POLICY = grant permission for __specific AWS service or app to invoke the Lambda__.

## You are trying to create a public subnet in your VPC you have added an Internet Gateway and configured the relevant Security Groups and Network ACLs, however you are still unable to access any of the web servers in your subnet over the internet. What could be the problem?

```
Your web servers are not behind an Elastic Load Balancer
You didn't configure the routing table in your peered VPC
You haven't configured a route to the internet via the Virtual Private Gateway
>> You haven't configured a route to the internet via the Internet Gateway
```

To enable Internet access, you must do the following things:
* Attach an INTERNET GATEWAY to your VPC.
* Ensure that your subnet's ROUTE TABLE points to the internet gateway.
* Ensure that your NETWORK ACCESS CONTROL (NACL) and SECURITY GROUP rules allow the relevant traffic to flow to and from your instance.
* Ensure that INSTANCES in your subnet have a globally unique IP address (public IPv4 address, Elastic IP address, or IPv6 address).

## Which of the following must be in place in order for an EC2 instance to successfully send logs to CloudWatch logs? (Choose 2)

```
>> The EC2 instance role must have permission to write to CloudWatch Logs
>> The CloudWatch agent must be running
Your IAM user must have permission to write to CloudWatch Logs
The EC2 instance role must have permission to read CloudWatch Logs
The CloudTrail must be enabled
```

## Which of the following policies would you use to define which AWS resources are permitted to invoke a Lambda function?

```
>> Function policy
Execution role policy
The resource policy of the event source which triggers the function
The IAM policy of the user who owns the event source which trigger the function
```

The Function Policy defines which AWS resources are allowed to invoke a Lambda function.

The Execution Role defines which resources your Lambda function has access to.

## Your S3 bucket policy allows your IAM user account full access to all S3 resources, however when you try to delete an object from the bucket, you are unable to do so. What could the problem be?

```
>> The IAM policy associated with your user account includes a deny statement which is preventing you from deleting the object
Key policy associated with the object includes a deny statement which is preventing you from deleting it
You are not the owner of the bucket
The object is encrypted
```

Access will be determined by the __Bucket Policy__ and the user's __IAM policy__.

__AN EXPLICIT DENY IN ANY POLICY OVERRIDES ANY ALLOWS IN S3.__
