## Distributed Denial of Service (DDoS) Overview

Recommended to read DDoS Whitepaper before exam, to prepare for DDoS QNs: https://d0.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf

__DDoS is worth quite a few points in the exam__

__DDos__ is an attack that attempts to make your website or app unavailable to your end users via. multiple methods such as:
* Large packet floods.
* Combination of reflection and amplification techniques.
* Using large botnets.

__Amplification / Reflection__ attacks include NTP/SSDP/DNS/Chargen/SNMP attacks etc.
* Attacker sends a 3rd-paryt server a request using a spoofed IP -> server responds with a greater payload than initial request.
* Response payload is usually 28-54 times larger to the spoofed IP address.
* Example 1: NTP Amplification
    * Attacker sends 64 byte request with spoofed IP -> server responds by sending 3,456 bytes of traffic to spoofed IP.
    * Attacker co-ordinates this with multiple NTP servers a second to send legit NTP traffic to the target.
* Example 2: __Slowloris__ (application attack)
    * Attack opens multiple connections with server without closing them, by sending partial HTTP requests.
    * Server waits for connections to be completed -> server's max concurrent connections pool is filled -> drops legit traffic.

How to mitigate DDoS:
1. Minimize the Attack Surface Area.
    * Some prod environments have multiple entry points e.g. SSH/RDP to web servers, DB servers etc.
    * Use a __jump box / bastion host__ + whitelist allowed IP addresses + move these servers to a private subnet.
2. Be ready to scale to absorb the attack.
    * Key strategy behind DDoS: bring your infra to breaking point. Defeat this strategy by designing your infra to scale as/when it is needed.
    * Scale __horizontally__ (add more machines into pool of resources) and __vertically__ (add more power to existing machines).
    * Attack is _spread over a large area_.
    * Attackers have to _counter attack_, taking up more of their resources.
    * Scaling buys time to _analyze_ the attack.
    * Scaling provides you with _additional lvls of redundancy_.
3. Safeguard exposed resources.
    * For situations where you can't eliminate internet entry points to your apps, take additional measures to restrict access without interrupting legitimate user traffic. Three measures:
    * AWS WAF: Most DDoS attacks are app-layer rather than infra-layer
        * __WAF Service__: protect EC2s, ALBs, CF distributions.
        * __AWS Marketplace WAFs__: use external 3rd-party WAFs.
    * AWS CloudFront:
        * __Geo Restriction/Blocking__: restrict access to users in specific countries (whitelist or blacklists).
        * __Origin access identity__: restrict access to your S3 bucket so that people can only access S3 using CloudFront URLs.
    * AWS Route53.
        * __Alias Record Sets__: Immediately redirect traffic to an AWS CF distribution, or to a different ELB with higher capacity EC2 instances running WAFs or your own security tools.
        * __Private DNS__: Allows you to manage internal DNS names for your app resources (web servers, databases) without exposing this info to the public internet.
4. Learn what normal behaviour looks like.
    * Be aware of normal and unusual behaviour.
    * Spot abnormalities fast -> create alarms to alert you of unusual behaviour -> collect forensive data to understand attacks.
5. Create a plan for attacks.
    * You've validated the design of your architecture.
    * You understand costs for increased resiliency and know what techniques to employ when an attack happens.
    * You know who to contact when an attack happens.
6. __AWS Shield__: service that protects all AWS customers on ELB, CloudFront and Route53.
    * Protects against SYN/UDP floods, reflection attacks and other layer 3/4 (Network and Transport) attacks.
7. __AWS Shield Advanced__: provides enhanced protections for your apps running on ELB, CloudFront, Route53 against larger and more sophisticated attacks. Costs $3,000 per month.
    * Always-on, flow-based monitored of network traffic and active application monitoring to provide near real-time notifications of DDoS attacks.
    * DDoS Response Team (DRT) 24/7 to manage and mitigate application-layer DDoS attacks.
    * Protects AWS bill against higher fees due to ELB, CloudFront and Route53 usage spikes during DDoS attacks.


## WAF Integration into AWS

WAF scenarios will be in the exam.

WAF only integrates directly with __(1) Application Load Balancers__ and __(2) CloudFront Distributions__.
WAF does NOT integrate with EC2, DynamoDB, Route53 or any other services.


## EC2 has been hacked - what to do?

1. Stop the instance immediately.
2. Take a snapshot of the EBS volume + terminate the instance.
3. Deploy a copy of the instance in a totally __isolated environment__.
* Isolated VPC, no internet access - ideally a private subnet.
4. Access the instance using an __isolated forensic workstation__.
* Don't do it on your normal laptop - use a dedicated workstation/device with an antivirus, no software on it except for forensic tools such as Wireshark, Kali etc.
5. Read logs to figure out how they obtained access.


## Leaked Github keys - what to do?

For IAM Users:
1. Goto `IAM` -> De-activate the IAM User Access Key.
2. Create a new IAM User Access Key.
3. Delete the old IAM User Access Key.

For Root User:
1. Goto `My Security Credentials` (top nav / outside of IAM).
2. Goto `Access Keys` -> De-activate Root User Access Key.
3. Create a new Root User Access Key.
4. Delete the old Root User Access Key.


## Reading CloudTrail Logs

1. Goto `CloudTrail` -> `View Trail`
2. Select a trail -> select `S3 log bucket` -> Choose region -> date -> open a log S3 object.

Exam tips:
* Understand that any API calls made in AWS are logged in CloudTrail.
* Replicate CloudTrail logs to an audit account which no-one else has access to.
* Any "performance" monitoring related questions would be CloudWatch, NOT CloudTrail.


## Penetration Testing in AWS

Penetration Testing is allowed without prior approving for 8 services
1. EC2
2. RDS
3. CloudFront
4. Aurora
5. API Gateway
6. Lambda and Lambda Edge functions
7. Lightsail resources
8. Elastic Beanstalk environments

Prohibited Activities
1. DNS Zone walking via. Route53w Hosted Zones
2. DDoS
3. Port flooding
4. Protocol flooding
5. Request flooding (login request flooding, API request flooding)

Other Simulated Events
* Request authorization for other simulated events by emailing `aws-security-simulated-event@amazon.com`


## AWS Certificate Manager (ACM)

Use __AWS Certificate Manager (ACM)__ to provision a SSL certificate for a domain name you have registered.
SSL certificates are automatically renewed provided you purchase the domain name from __Route53__.

You can import your own certificate vs. you can request a certificate.

Requesting a certificate
1. Add your domain name
2. Select your domain validation methods
    * (1) DNS validation: requires you to modify DNS config for the domain in your certificate request.
    * (2) Email validation: requires you to respond to an email sent to an email address under the domain.
3. For DNS validation
    * Add a CNAME record to the DNS config for your domain.
    * Goto `Route53` -> create a record -> add the CNAME record.
4. Wait ~5-10 minutes and the status of the certificate should be `Issued`.

SSL/TLS certificate renewal
* Auto-renewal: ACM provides autorenewal for Amazon-issued SSL/TLS certs.
* Manual renewal: Imported SSL/TLS certs OR certs associated with R53 private hosted zones must be manually renewed.

Using Amazon SSL certificates
1. SSL/TLS cert with CloudFront
* Goto `CloudFront` -> select a distribution -> select `Distribution Settings` -> edit to change from default CloudFront SSL cert to the new custom SSL certificate associated with your domain name.
2. SSL/TLS cert with EC2
* Goto `EC2` -> `Load Balancers` -> create a Load Balancer -> `choose a certificate from ACM`

__NOTE: You CANNOT export Amazon-issued SSL/TLS certs and use it elsewhere, only within AWS services.__


## Securing Load Balancers using Perfect Forward Secrecy

__Perfect Forward Secrecy__ 
A property of secure communications protocols in which compromises of long-term (public/private key) keys DO NOT compromise past session keys. Forward secrecy protects past sessions against future compromises of secret keys or passwords.

__Security Policy__ when setting up ALB:
* Choose the `2016-08` Security Policy as it supports most ciphers.
* Enable Perfect Forward Secrecy on your ALBs by selecting a Security Policy with a `ECDHE-X` cipher.


## API Gateway - Throttling and Caching

AWS API Gateway throttling
* API Gateway throttles requests to your API, to prevent it from being overwhelmed by too many requests.
* When request submissions exceed steady-state request rate or burst-limits, API Gateway fails the limit-exceeding requests and returns `429 Too Many Requests` to the client.
* Limits
    * `Steady-state` = 10,000 requests/second.
    * `Burst-limit` (max concurrent requests that API Gateway can fulfil) = 5,000 requests across all APIs within an AWS account.
* Examples
    * Caller submits 10,000 requests/second period evenly (e.g. 10 requests/ms) = ALL REQUESTS SERVED.
    * Caller submits 10,000 requests in the 1st millisecond = FIRST 5,000 SERVED -> THROTTLES REMAINING 5,000 FOR REMAINING 1 SECOND PERIOD.
    * Caller submits 5,000 requests in the 1st millisecond, then evenly spreads another 5,000 requests through remaining 999 milliseconds. = SERVES ALL REQUESTS IN 1 SECOND PERIOD WITHOUT 429 RESPONSE.
* Account-level rate limit and burst limit can be increased upon request e.g. Ticketmaster who will have huge traffic spikes.

AWS API Gateway caching
* Use API Caching in AWS API Gateway to cache endpoint's response.
* Use caching to reduce number of calls made to your endpoint and also improve latency of requests to your API.
* When caching is enabled for a stage (test, prod etc.), API caches responses from your endpoint for a specified __Time To Live (TTL)__.
* `TTL 300` = default | `TTL 3600` = maximum | `TTL 0` = caching disabled.


## AWS Systems Manager - Parameter Store

__AWS Systems Manager__ is a service to manage EC2 systems at scale.

1. Create a parameter
* Type: _String_ (plaintext), _String List_ (plaintext list), _Secure String_ (KMS encrypted)
2. Store sensitive data inside
3. Access parameters across different AWS services.
* Accessed by EC2, EC2 Run Command, Lambda, CloudFormation etc.

Exam only requires high-level knowledge of AWS Systems Manager (Parameter Store)


## AWS Systems Manager - EC2 Run Command

The Systems Manager (SSM) __EC2 Run Command__ allows you to:
* manage a large number of EC2 instances and on-premise systems.
* automate admin tasks and adhoc config changes e.g installing apps, patching, joining new instances to a Windows domain without having to RDP into each instance.

Using EC2 Run Command:
1. Create a role for SSM - `EC2 role for Simple Systems Manager`
2. Create an instance - Windows image, attach IAM role created above.
3. Under `Actions` in SSM, click `Run a Command` -> choose a command document i.e. `Configure CloudWatch` -> select the target instance and then run.

Exam tips:
* Commands can be applied to a group of systems based on AWS instance tags or by selecting manually.
* __SSM agent__ needs to be installed (it is installed by default on certain Windows and Linxu AMIs) and an IAM SSM role enabled on all your managed instances for Run Command to work.
* The commands and parameters are defined in a __Systems Manager Document__
* Commands can be issued using AWS Console, AWS CLI, AWS Tools for Windows PowerShell, Systems Manager API or Amazon SDKs.
* You can use this service with your on-premise systems as well as EC2 instances.


## Compliance Frameworks

ISO27001
* Specifies requirements for _establishing_, _implementing_, _operating_, _monitoring_, _reviewing_, _maintaining_ and _improving_ documented Information Security Management System (ISMS) within the context of the organization's overall business risks.

FedRAMP (Federal Risk and Authorization Management Program)
* Government-wide program that provides a standardised approach to security assessment, authorisation and continuous monitoring for cloud products and services.

HIPAA (Federal Health Insurance Portability and Accountability Act of 1996)
* Primary goal is to make it easier for people to keep health insurance, protect the confidentiality and security of healthcare info and to help the healthcare industry control administrative costs.
* Primary goal: _lower cost of healthcare_ and _ensure good data security around people's healthcare info_.

NIST (National Institute of Standards and Technology - U.S Department of Commerce)
* A framework for improving critical infrastructure cybersecurity - a set of industry standards and best practices to help organisations manage cybersecurity risks.

PCI DSS (Payment Card Industry Data Security Standard)
* Widely accepted set of policies and procedures intended to optimise security of credit, debit and cash card transactions and protect cardholders against misuse of their personal info.

PCI DSS 12 requirements (not required for exam, but good for interviews):

_Build and Maintain a Secure Network and Systems_
1. Install and maintain a firewall configuration to protect cardholder data.
2. Do not use vendor-supplied defaults for system passwords and other security parameters.

_Protect Cardholder Data_
3. Protect stored cardholder data.
4. Encrypt transmission of cardholder data across open, public networks.

_Maintain a Vulnerability Management Program_
5. Protect all systems against a malware and regularly update anti-virus software or programs.
6. Develop and maintain secure systems and applications.

_Implement Strong Access Control Meaures_
7. Restrict access to cardholder data by business need-to-know.
8. Identify and authenticate access to system components. E.g. use IAM or services such as Auth0
9. Restrict physical access to cardholder data. E.g. copies of credit card records

_Regularly Monitor and Test Networks_
10. Track and monitor all access to network resources and cardholder data. E.g. CloudTrail, CloudWatch and other logging tools etc. or use a 3rd-party service to perform monitoring.
11. Regularly test security systems and processes. E.g. Pentesting, simulated phishing etc.

_Maintain an Information Security Policy_
12. Maintain a policy that addresses information security for all personnel.

SAS70
* Statement of Auditing Standards No. 70
SOC 1
* Service Organization Controls - accounting standards.
FISMA
* Federal Information Security Modernization Act.

FIPS 140-2 is a U.S government computer security standard used to approve cryptographic modules.
* Rated from Level 1 to Level 4 (highest)
* AWS CloudHSM meets Level 3.

Check out https://aws.amazon.com/compliance.


## Chapter 7 Summary

AWS Shield
* Free service that protects all AWS customers on _Elastic Load Balancers_, _CloudFront_ and _Route53_.
* Protects against SYN/UDP Floods, Reflection Attacks and other layer 3/4 attacks.
* Advanced Shield protects you against larger and more sophistcated attacks - $3,000 per month cost.

AWS Advanced Shield
* Always-on, flow-based monitoring of network traffic and active application monitoring.
* Real-time notifications of DDoS attacks.
* DDoS 24/7 Response Team to manage and mitigate application-layer DDoS attacks.
* Protects AWS bill against higher fees due to ELB, CF, R53 usage spikes during DDoS.

DDoS
* Remember technology that can be used to mitigate a DDoS: _CloudFront, Route53, ELBs, WAFs, Autoscaling, CloudWatch_.

EC2 has been hacked
* Stop instance immediately.
* Take snapshot of EBS volume.
* Deploy instance in an isolated environment. Isolated VPC, no internet access - ideally private subnet.
* Access instance via. forensic workstation.
* Read through logs to figure out how (Windows Event Logs).

Keys leaked on Github
* Delete key from user's account + generate a new key.

AWS Certificate Manager
* SSL Certificates renew automatically, provided you purchase a domain name from Route53 and it's not for a Route53 Private Hosted Zone.
* Use Amazon SSL Certificates with both Load Balancers and CloudFront.
* You cannot export the Amazon SSL Certificates (so you can only use it on AWS infrastructure.)

Perfect Forward Secrecy
* Someone who compromises your private key cannot use it to decrypt past traffic.
* __ECDHE__ TLS cipher is needed -> by default choose `2016-08` Security Policy.

API Gateway Throttling
* Prevents your API from being overwhelmed by too many requests.
* When request submissions exceed steady-state request rate and burst limits, API Gateway fails all exceeding requests and returns a `429 Too Many Requests` response to the client.
* Steady-state rate = 10,000 requests per second.
* Account-level rate limit and burst limit can be increased upon request.

API Gateway Caching
* Cache your endpoint's response - reduce number of calls to the endpoint and improve latency of responese from endpoint.
* API Gateway caches repsonse for a specified TTL (time-to-live) period in seconds.
* Default TTL = 300 seconds | Maximum TTL = 3600 seconds | TTL = 0 disabled caching.

AWS SSM Run Command
* Commands applied to a group of instances based on AWS instance tags or by selecting manually.
* SSM Agent needs to be installed (installed by default on some AMIs).
* Systems Manager Document defines the commands and parameters run.
* Works on-premise systems and EC2 instances.

