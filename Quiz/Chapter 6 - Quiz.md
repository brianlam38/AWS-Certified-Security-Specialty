## Which kind of attack is designed to make your website or application unavailable to your users by flooding your application with traffic using botnets?

```
Man-in-the-Middle Attack
>> DDoS attack
SQL Injection
Phishing
```

A Distributed Denial of Service (DDoS) attack is a malicious attempt to make a targeted system, such as a website or application, unavailable to end users. To achieve this, attackers use a variety of techniques that __consume network or other resources, interrupting access for legitimate end users__.

## Which of the following AWS services would you use to store confidential licence keys so that they can be made available securely to applications in your environment?

```
CloudFormation templates
AWS Secrets Manager
Lambda environment variables
>> Systems Manager Parameter Store
KMS
```

AWS Systems Manager Parameter Store provides secure, hierarchical storage for configuration data management and secrets management. You can __store data such as passwords, database strings, and license codes__ as parameter values. You can store values as plain text or encrypted data.

## Which of the following technologies can you use to implement DDoS mitigation? (Choose 4)

```
>> CloudFront
>> Elastic Load Balancing
>> Route 53
EC2
VPC Flow Logs
>> AWS Shield
RDS
```

AWS provides a range of services which allow you to build strong architectures which are resilient to DDoS attacks, e.g. services such as __Route 53, CloudFront, Elastic Load Balancing, and AWS WAF__ to control and absorb traffic, and deflect unwanted requests. These services integrate with __AWS Shield, a managed DDoS protection service__ that provides always-on detection and automatic inline mitigations to safeguard web applications running on AWS. Check out the DDoS White Paper for best practices!

## Which of the following features of CloudFront can you use to protect exposed endpoints in your AWS architecture? (Choose 2)

```
Edge Locations
>> Origin Access Identity
Cross Origin Resource Sharing
>> Geo restriction
```

Geo restriction allows you to __restrict access to users based in specific countries__, using allow lists and block lists. If you're using Amazon S3 for your origin, you can __use an origin access identity to require users to access your content using a CloudFront URL instead of the Amazon S3 URL__.

## Which of the following approaches can you use to best protect your system from being affected by a DDoS attack? (Choose 3)

```
Implement strong password policies
>> Understand what normal behaviour looks like
Back up your critical data on a regular basis
>> Minimize the attack surface area
>> Be ready to scale to absorb an attack
Apply regular software updates
```

__Minimizing the attack surface__, __scaling to absorb__ and __understanding what normal behaviour looks like__ so that you can detect an attack are best practices for DDoS protection.

* Password policies, software updates and backups are good practices but they won't protect you from a DDoS attack.
* Please read the DDoS White Paper for an overview of DDoS mitigation techniques recommended by AWS!

## You would like to run penetration testing on your AWS environment, which of the following are valid options in AWS?

```
Use Trusted Advisor
>> Go to the AWS Marketplace and search for a penetration testing tool like Kali Linux
Submit a request to have AWS complete penetration testing on your behalf
Use Amazon Inspector
```

AWS does not provide any penetration testing services, however you can search the AWS Marketplace to find Third Party Penetration testing tools compatible with Linux or Windows

* AWS Trusted Advisor: provides real-time guidance to help you provision resources following AWS best-practices.
    * Increase security, performance, reduce overall costs, monitor service limits.
* Amazon Inspector: automated security assessment service to improve security and compliance of applications deployed on AWS.

## You can use AWS Shield to protects you against Layer 3 and 4 attacks on which of the following services? (Choose 3)

```
>> Elastic Load Balancer
API Gateway
>> Route 53
Kinesis
>> CloudFront
S3
```

AWS Shield provides protection against DDoS attacks for applications running on AWS. AWS Shield Standard is automatically enabled to all AWS customers at no additional cost. AWS Shield Advanced is an optional paid service which provides additional protections against more sophisticated and larger attacks for your applications running on __Amazon EC2, Elastic Load Balancing (ELB), Amazon CloudFront, AWS Global Accelerator, and Route 53__.

## You are configuring a secure website and would like users to connect to your website using HTTPS. Which of the following are supported options to store your SSL/TLS certificates? (Choose 2)

```
Elastic File System
>> AWS Certificate Manager
S3
>> IAM
```

To enable HTTPS connections to your website or application in AWS, you need an SSL/TLS server certificate. AWS recommends the use of __AWS Certificate Manager__ to provision, manage, and deploy your server certificates (in supported regions). In __unsupported regions, you must use IAM as a certificate manager__.

## Which of the following are valid options for using SSL certificates with CloudFront? (Choose 3)

```
>> Custom SSL Certificate stored in IAM
>> Default CloudFront Certificate
>> Custom SSL Certificate stored in ACM
Default ACM Certificate
Custom SSL Certificate stored in KMS
Default SSL Certificate stored in S3
```

Use the __Default CloudFront Certificate if you don't mind your users accessing your site using the default *.cloudfront.net domain name__. If you would like to use your own domain name, you will need to provide a __Custom SSL certificate++ which can be stored in either ACM or IAM__.

No other options are supported.

## Your EC2 instance has been hacked, which of the following should you do immediately as part of your incident response plan? (Choose 3)

```
Delete the Key Pair associated with the instance
Log in to the instance from your workstation and figure out how this happened
>> Redeploy the instance to an isolated environment for forensic analysis
>> Stop the instance
Terminate the instance immediately
>> Create a snapshot of the EBS volume
```

The most important thing is to prevent any further damage to your environment by __stopping the instance__. Take an __EBS snapshot__ and __deploy a new instance using the snapshot into a private subnet isolated from the rest of your environment__. You can then safely undertake forensic analysis.

* If you terminate the instance immediately, you will not be able to perform forensics.
* Use a forensic workstation to perform your investigation to avoid compromising your desktop environment.
* Deleting the Key Pair is not required.

## Which of the following services does AWS WAF integrate with? (Choose 2)

```
>> Application Load Balancer
Network Load Balancer
EC2
>> CloudFront
Elastic BeanStalk
```

AWS WAF is a web application firewall that helps protect web applications from attacks by allowing you to configure rules that allow, block, or monitor (count) web requests based on conditions that you define.

AWS WAF is tightly integrated with __Amazon CloudFront__ and the __Application Load Balancer__, services that AWS customers commonly use to deliver content for their websites and applications.

## Which of the following AWS services can integrate with ACM? (Choose 2)

```
EC2
S3
Route 53
Lambda
>> CloudFront
>> Application Load Balancer
```

ACM integrates with the following services: __CloudFront, ALB, API Gateway, Elastic Beanstalk, CloudFormation__.

## Which of the following DDoS mitigation best practices can you implement by using a Bastion host to access your EC2 instances?

```
Architect for resilience
Be ready to scale
Know what is normal, alert on what is not
>> Minimize the attack surface
```

By using a Bastion host to access EC2 instances, you can __reduce your attack surface and limit your application’s internet exposure__. Resources that are not exposed to the internet are more difficult to attack.

## Which AWS service can you use to automate common administrative tasks like applying patches or joining instances to a Windows domain without having to log in to each instance in turn?

```
>> Systems Manager Run Command
AWS Config
CloudFormation
Use a Lambda function
```

AWS Systems Manager Run Command lets you __remotely and securely manage the configuration of your managed instances__. A managed instance is any __Amazon EC2 instance__ or __on-premises machine in your hybrid environment__ that has been configured for Systems Manager.

## You have accidentally exposed your AWS Access Key ID and Secret Access Key in code you uploaded to GitHub. What should you do? (Choose 3)

```
>> Delete the Access Key that has been exposed
>> Make your Access Key inactive
Create a new SSH Key Pair
Keep the Access Key but create a new Secret Access Key
>> Create new Access Key and Secret Access Key
Delete your SSH Key pair
```

You will need to:
1. __make the key inactive__.
2. __create a new Access Key and Secret Access Key__.
3. __delete the Access Key that has been exposed, after successfully updating and testing applications with the new key__.

Any applications that were using the old key should be updated with the details of the new key and successfully tested, before you delete the old key.

* AWS Access Key / Secret Access Key is for logging into AWS accounts.
* SSH Key Pair is for logging into EC2 instances.
