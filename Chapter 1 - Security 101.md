# AWS Security 101

### Security Basics

CIA
* __Confidentiality__: IAM, MFA, bucket policies, security groups, ACL's within VPC's, KMS encryption etc.
* __Integrity__: Certificate Manager (SSL), IAM, bucket policies, S3 version control, MFA for S3 deletion etc.
* __Availability__: Autoscaling, Multi-AZs, Route53 health checks etc.

AAA
* __Authentication__: auth into IAM entity (user/role)
* __Authorization__: IAM policies to define access
* __Accounting__: audit trail i.e. CloudTrail

Non-repudiation
* Not being able to deny something has happened.
* CloudTrail, CloudWatch.


### How does AWS Secure their Stuff?

Physical and Environmental Security
* AWS consist of regions, with 2+ availability zones, each made up of multiple data centres.
* Secured by fire-detection/suppression, power (2 feeds / different power sources), climate and temperature, management (ex-soldiers / physical access in-out), storage device decommissioning (zero out all data from disks and then shredding/smashing disk).

Business Continuity Management
* Monitor availability, incident response
* Perform company-wide executive reviews when an incident has occurred + communicating issues out to customers

Network Security
* Secure network architecture
* Secure access points - everything is available as a public API, so access points but be secured.
* Transmission protection e.g. TLS security on console login, S3 bucket access etc.
* Amazon corporate segregation - Amazon.com network is completely different network to AWS. Bastion is required for employee access from Amazon.com -> AWS
* Fault-tolerant design - multiple AZ's in multiple regions
* Network monitoring and protection - DDoS mitigation via. AWS shield + advanced DDoS mitigation is available (more costly)

AWS Access
* Account Review and Audit - AWS users' accounts are audited/reviewed every 90days. If account has not been used, it will be revoked and reapplying for access is required.
* Background Checks
* Credentials Policy - Amazon's password policies (very complex, changed every 90 days).

Secure Design Principles
* Formal design reviews by AWS security team, threat modelling, completion of risk assessments, static code analysis tools run as part of build process, all deployed software undergoes re-occurring penetration testing prepared by carefully selected industry experts.

Change Management
* AWS performs routine emergency and configuration changes to AWS infra.
* It is all authorized, tested, logged, approved and documented in accordance with industry norms for similar systems.
* AWS communicates to customers via. email / service health dashboard.

Why should we trust AWS?
* AWS meets a whole bunch of compliance programs / IT security standards.
* Big ones are ISO27001, PCIDSS compliant, HIPAA (medical records).
* Your own software/infrastructure requires a GAP-AUDIT.

Exam Tips
* Remember different security controls around: physical and environmental security, business continuity, network security, AWS access, secure design principles, change management.
* Remember that the corporate Amazon.com network is completely segregated from the AWS network. Permissions / reviews are requried when an employee wants to access AWS. Permissions are revoked as soon as nologin for 90 days.


### Shared Responsibility Model

What is it?
* Security WITHIN the cloud is the responsibility of the customer.
* E.g. House example:
    * Landlord is responsible for installing fire alarms, fences.
    * You are responsible for locking your door, making sure windows are shut etc.

AWS Security Responsibilities
* Global infrastructure - their datacentres
* Hardware, software, networking and facilities - all their hardware, software such as RDS / AWS operation systems etc.
* Managed services - S3, DynamoDB etc.

Customer Security Responsibilities
* Infrastructure as a Service
* Updates and security patches e.g. EC2 instances etc.
* Configuration of AWS-provided firewall - VPC rules, security groups, network ACLs etc.

Diagram of the Shared Responsibility Model:  
https://aws.amazon.com/compliance/shared-responsibility-model/

Basically, if the customer has no access to the underlying OS/software/infrastructure, then it is AWS's responsibility.


### Shared Responsibility - AWS service types

Infrastructure services - compute services such as EC2, EBS, Auto Scaling, VPC
* You can architect and build cloud infrastructure, control the OS, configure and operate any identity management system that provides access to the user layer of the virtualization stack.
* EC2 - AMIs, OS, applications, data in transit, data at rest, data stores, credentials, policies and configuration.

Container services - services such as RDS, Elastic Map Reduce (EMR) and Elastic Beanstalk.
* RDS example - you have a DB that you can install/access but you don't manage the underlying OS. AWS is responsible for patching for the RDS instance.
* Services that are typically run on separate EC2s or other infrastructure instances. Sometimes you don't manage the OS or platform layer.
* Customer is responsible for setting up and managing network controls such as firewall rules, managing platform-level identity and access management separately from IAM.

Abstracted services - services such as S3, Glacier, DynamoDB, SQS, SES.
* Services that abstract the platform or management layer on which you can build and operate cloud applications.
* Customer can access the endpoints of these abstracted services using AWS APIs.
* AWS is responsible for managing the underlying service components or OS in which these services reside.

Exam Tips: Have a STRONG understanding of the shared responsibility model.
* The model changes for the three different service types:
1. Infrastructure services (EC2, EBS, VPC)
2. Container services (RDS, EMR, Elastic Beanstalk) - AWS responsible for the OS, container itself.
3. Abstracted services (S3, Glacier, DynamoDB, SQS, SES) - AWS responsible for almost everything, except for the application layer e.g. TLS / access controls.


### Security IN AWS

Controls that you need:
* __Visibility__: AWS Config - managed and custom rules
* __Auditability__: AWS CloudTrail - records every API call in the environment
* __Controllability__:
    * AWS KMS - multi-tenant. Underlying hardware is shared, but strict controls.
    * AWS CloudHSM (hardware security module) - dedicated. Underlying hardware is NOT shared. __Exam: Which service is required for FIPS 140-2 Compliance? - CloudHSM as KMS being multi-tenant/shared does not comply.__
* __Agility__:
    * AWS CloudFormation - deploy templates to any regions
    * AWS Elastic Beanstalk - AWS provision resources for you, rather than you doing it each service manually
* __Automation__:
    * AWS OpsWorks - operate alongside CF / EB
    * AWS CodeDeploy - operate alongside CF / EB
* Scale__: Every customer gets the same AWS security foundations, from a startup to a Fortune 500 company.

Other services applying to all controls
* AWS IAM - creating users, password policies, MFA, groups
* AWS CloudWAtch - monitor environment, see breaches, CPU runtime
* AWS Trusted Advisor - advises on security, budgeting, system performance and reliability