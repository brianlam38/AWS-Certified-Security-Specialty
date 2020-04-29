## VPC Overview

__Virtual Private Cloud (VPC)__ lets you provision a logically isolated section of the AWS cloud where you can launch AWS resources in a virtual network that you define / i.e. a LOGICAL DATACENTRE IN AWS.
* Have complete control over the virtual networking env.
    * Selection of your own IP range.
    * Creation of subnets.
    * Config of route tables and network gateways.
* Can easily customize network config for your VPC
    * e.g. create public-facing subnet for your webservers that has access to the internet.
    * e.g. create private-facing subnet for your databases/appservers that has NO access to the internet.
* Can leverage multiple layers of security
    * Security groups, network access control lists (NACLs) to help control access to EC2s in each subnet.
    * NOTE: SGs = stateful (port changes apply to inbound AND outbound) / NACLs = stateless (port changes apply to inbound OR outbound)
* Can create a Hardware Virtual Private Network (VPN) connection between your corporate datacenter and VPC and leverage AWS cloud as an extension of your corporate datacenter.
* 1 SUBNET = 1 AVAILABILITY ZONE
* MINIMUM IPs per subnet: subnet /28 = 16 ip addresses
* MAXIMUM IPs per subnet: subnet /16 = 65,536 ip addresses
* You can have multiple VPCs inside a region.

How VPC works:
1. Traffic entry into VPC:
    * via. __VPC Virtual Private Gateway__ (VPN connection)
    * via. __VPC Internet Gateway__ (internet connection)
2. Traffic to Router:
    * Configure how this traffic is routed via. Route Tables
3. Traffic hits Network ACLs (first-line of defence)
4. Traffic hits Security Groups
    * SGs govern if traffic is allowed to talk to our instances.
5. Traffic hits destination EC2

What can you do with a VPC?
* Launch instances into a subnet of your choosing.
* Assign custom IP address ranges in each subnet.
* Configure route tables between subnets.
* Create internet gateway and attach it to your VPC.
* Much better security control over your AWS resources.

Default VPC vs. Custom VPC:
* Default VPC is user friendly, allowing you to immediately deploy instances.
* All subnets in default VPC have a route out to the internet.
* Each EC2 instance has both a public and private IP address (unlesse they're in private subnets).

VPC Peering: connect one VPC with another via. direct network route using private IP addresses.
* Instances behave as if they were on the same private network.
* You can peer VPCs with other AWS accounts as well as other VPCs in the same account.
* Peering is in a star configuration: i.e. 1 central VPC peers with 4 others.
    * NO TRANSITIVE PEERING e.g. VPC A can talk to B vice-versa, but A cannot talk to C via. B. Peering must be created between A and C.


## Setting up a Custom VPC

1. (NOT REQUIRED) Check out the default resources in your AWS account
    * Default VPC, default subnets, default route table, default internet-gateway, default security group.
2. Go to VPC -> Create a new VPC
    * IPv4 CIDR block: 10.0.0.0/16 (biggest address range possible)
    * Tenancy: default (multi-tenant hardware environment) / dedicated (no sharing with other AWS customers, expensive.)
    * You should now have the resources provisioned: a Route Table, Network ACL, Security Group (won't create default subnets)
3. Provision a series of subnets
    * Name: [CIDR range]-[availability zone]
    * Select the VPC you created, select the AZ, CIDR address range
4. Provision an Internet Gateway - so there is connectivity from the internet to the VPC
    * Create an IG -> attach to the custom VPC.
    * Each VPC can only have ONE IG attached.
5. Create a new Route Table that is EXPLICITLY public-facing into the Custom VPC - to replace the default internet-facing MAIN Route Table.
    * Enable internet-access: Goto `Routes` -> add route `0.0.0.0/0` -> select target Internet Gateway.
    * Associate subnet with the new Route Table: Goto `Subnet Associations` -> select a subnet to associate the new Route Table with.
    * Disable internet-access for MAIN Route Table, so all new subnets created by default won't be internet-facing anymore.
6. Test internet connectivity - using EC2s
    * First goto `Subnets` -> `Subnet actions` -> turn on `Auto-assign public IP addresses` for the public subnet
    * TEST PUBLIC (representing a webserver): Launch an EC2 -> select Custom VPC -> select the public subnet -> create SG with open port 22.
    * TEST PRIVATE (representing a private server e.g. SQL server): Launch an EC2 -> select Custom VPC -> select the private subnet.
    * You should be able to SSH into the public EC2 using the public IP address.
    * You should NOT be able to SSH into the private EC2 as there is no assigned public IP / SG config does not allow.
7. Configure private EC2 server - example is a MYSQL server
    * Allow inbound 22 SSH, 3306 MYSQL, 80/443 HTTP(S), 0-65535 ICMP PING with source = public subnet CIDR address (so EC2 in private subnet can talk to the webserver in the public subnet)
8. Connect to the private EC2 from public EC2
    * Test connection by SSH into public EC2 and PING private EC2.
    * _(SECURITY WARNING: IN PRODUCTION, USE A BASTION HOST)_ Store private key for private EC2 on the public EC2 -> SSH into private EC2.
    * NOTE: there will be no outbound route yet to the public from the private EC2.
9. Create outbound route for the private EC2 w/o placing into public subnet - for installing packages / patch OS.

The first 4 IP addresses and the last IP address of each subnet CIDR block can't be used as:
* IP #1 reserved for the network address
* IP #2 reserved for the VPC router
* IP #3 reserved for DNS purposes `10.0.0.2`
* IP #4 reserved for future use
* IP #LAST reserved for network broadcast address

SUBNETS: _The purpose of subnetting is to help relieve network congestion. If you have an excessive amount of traffic flow across your network, then that traffic can cause your network to run slowly. When you subnet your network, most of the network traffic will be isolated to the subnet in which it originated. Ideally, your subnet structure should mimic your network's geographic structure. Other benefits of subnetting include routing efficiency, easier network management and improving network security_

ROUTE TABLES: _Route tables contain a set of rules (routes) that are used to determine where network traffic from your subnet or gateway is directed. It allows subnets to talk to each other. Every AWS subnet you provision will automatically be attached to your default/main route table. Ideally, you should create a separate route table that is internet accessible rather than use your default/main route table as every new subnet being provisioned will be associated with the default/main route table, hence become internet accessible._


## NAT Instances (OLD METHOD)

NOTE: Network Address Translation (NAT) is a process where a network device assigns a public IP address to a computer inside a private network. The purpose of a NAT is to limit the no. of public IP addresses a company must use for economic and security purposes.

Launch and set up a NAT ec2 instance
1. Find a NAT instance within community AMI's
2. Place instance in the custom VPC.
3. Place instance in the public subnet.
4. Configure the Web-DMZ security group (with SSH22/HTTP80/HTTPS443 open).
5. Launch the instance.
6. Configure instance to _disable Source/Destination checks_ (used by normal ec2s) as a NAT instance is not the src/dest itself.

Create a route OUT from the default route table via. NAT instance:
1. Goto VPC -> Route Tables -> select default route table
2. Edit default route table -> add destination `0.0.0.0/0`, with the `NAT instance` as the target.

Test the route out:
1. SSH into public instance -> SSH into private instance using key.
2. Ping google or run `yum update` to test internet accessibility.

NAT instance downsides:
* Bottlenecks: single instance, single availability zone, limited network throughout.
* The amount of traffic that NAT instances can support depends on instance size. You must increase instance size if more throughout is required.
* Reliant on a single OS, any crashes = no internet access for any servers in the private subnet.
* High availility requires using Autoscaling Groups, multiple subnets in different AZs and scripts to automate failover = pain in the ass.
* Bad design in general to use NAT instances, as it can get complex to make it work efficiently.
* __AWS new feature NAT gateway now should replace the use of a single NAT instances.__

NAT instance can be used as a bastion server (server used to RDP/SSH into instances within your private subnet).


## NAT Gateways (PREFERRED METHOD)

Launch and set up a NAT gateway
1. Goto VPC -> select NAT Gateway
2. Select the `public subnet` in the custom VPC -> Select `create new EIP` to create an Elastic IP address.
3. Click `create a NAT Gateway`
4. Edit default route table -> add destination `0.0.0.0/0`, with the `NAT gateway` as the target.

Test the route out by performing the same test as with the NAT instance.

Comparison of NAT instances and NAT gateways: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-comparison.html

Benefits of NAT Gateways:
* Preferred by enterprise.
* Scales automatically up to 10Gbps.
* Highly available, automatic failover.
* NAT Gateways are managed by AWS (patching, antivirus etc. = more secure than NAT instances)
* NAT Gateways don't need to sit behind a security group.
* Automatically assigned with a public IP (no need to create EIP).

Having 1 NAT Gateway in 1 AZ is not good enough, you need to have at least 1 NG per AZ so there is some form of redundancy in terms of AZ failure.


## NACLs vs. Security Groups

Network Access Control List (NACL) acts as a firewall for controlling traffic in/out of your subnets.
* NACLs are stateless, responses to allowed inbound traffic are subject to the rules of outbound traffic (vice versa.)
* You can only associate 1 subnet to 1 NACL, not 1 subnet to multiple NACLs
* Subnets are automatically associated with the default VPC NACL.
* NACLs can only be deployed to 1 VPC, they cannot span VPCs.
* The _default VPC NACL_ will _ALLOW ALL_ traffic in/out of subnets associated with the NACL.
* Any _custom NACLs_ created by default will _DENY ALL_ traffic in/out.

Creating and configuring NACL (example: setting up webserver):
1. Goto VPC -> Network ACLs -> `Create Network ACL`
2. Add inbound rules `HTTP 80`, `HTTPS 443`, `SSH 22` ALLOW, leaving the DENY ALL.
3. Add outbound rules `HTTP 80`, `HTTPS 443`, `Custom TCP 1024 - 65535` ALLOW, leaving the DENY ALL.
4. Associate NACL with the public subnet. Since 1 subnet can only be associated with 1 NACL, the default NACL will be disassociated.

Rules are evaluated in numerical order.
* Example: Rule `#100 | HTTP 80 ALLOW ALL` vs. Rule `#101 | HTTP 80 DENY MY_IP`
    * The website will work because Rule #100 overrides Rule #101.
* Example: Rule `#100 | HTTP 80 ALLOW ALL` vs. Rule `#99| HTTP 80 DENY MY_IP`
    * The website WON'T work anymore because Rule #99 overrides Rule #101.

NACLs are assessed BEFORE Security Groups - traffic blocked on NACL level won't reach SG, even if SG allows HTTP80.

You can block IP addresses using NACLs, not Security Groups.


## Application Load Balancers and Custom VPC's

Setting up an ALB (a type of Elastic Load Balancer - AWS offers ELB options Application/Network/Classic)
* Goto EC2 -> `Create Load Balancer` -> `Application Load Balancer`
* Select Scheme = `internet facing`
* Select subnets from at least TWO public Availability Zones to increase the availability of your Load Balancer.


## Elastic Load Balancers and TLS/SSL Termination

When using ELBs, you have the choice to terminate TLS/SSL on the Load Balancer or EC2 instances.

Terminate at load balancer
* ALB decrypts HTTPS request -> inspects HTTP headers -> routes request to EC2 as plaintext over the local private network in your VPC.
* Benefits
    * Offloads decryption overhead to ALB, meanings EC2 has more resources for application processing.
    * More cost effective as you require less EC2 compute power, therefore can use smaller EC2 instances to handle application load.
    * Reduces administrative overhead if you have many EC2 instances, from managing X509 certificates (used to encrypt/decrypt) individually on multiple EC2s.
* Security implications
    * Traffic between ALB and EC2 is unencrypted (however, AWS states that network traffic cannot be listened to by EC2s that aren't part of the connection, even if they are running within your own AWS account).
    * Compliance / regulatory requirements to use end-to-end encrytion all the way to your EC2 may require you to terminate TLS/SSL on the EC2 instances.

Which Load Balancer to use?
* Application Load Balancer only supports TLS/SSL termination on the Load Balancer itself. Only supports HTTP/HTTPS.
* Network Load Balancer supports TLS/SSL termination on your EC2 instances. You will need to use TCP protocol (load balancing at the TCP level).
* Classic Load Balancer is a legacy option.

Exam tips:
* Best use of EC2 resources = use APPLICATION.
* Regulatory / Compliance requirements for E2E-encryption = use NETWORK or CLASSIC.
* For any other protocol that is not HTTP/HTTPS = use NETWORK or CLASSIC.


## VPC Flow Logs

VPC Flow Logs enables you to capture info about the IP traffic going to/from network interfaces (ENIs) in your VPC.
* Flow Log data is stored using AWS CloudWatch logs.
* Flow Logs can be created at 3 different levels:
   1. VPC level: capture all ENI traffic
   2. Subnet level: capture ENI and EC2 traffic within a particular subnet
   3. Network Interface level

Creating Flow Logs
1. Goto VPC -> Click `Actions` -> `Create Flow Log`.
2. Select `Filter` (type of traffic to log) = ALL traffic, ACCEPTED traffic , REJECTED traffic.
3. Select `Role` = Flow Log IAM role that allows Flow Log to create logs in CloudWatch.
4. Select `Destination Log Group` = goto CloudWatch -> create a Log Group -> select this group.

Flow Log options
* You can stream the logs to AWS Lambda or AWS Elasticsearch.
    * You can have your environment pro-actively react to something that happens inside your VPC.
* You can export the data to S3.

Exam tips;
* You cannot enable Flow Logs for VPCs that are PEERED with your VPC unless the peer VPC is in your account.
* You cannot tag a Flow Log.
* After creating a Flow Log, you cannot change its configuration e.g. can't associate to another IAM role with the Flow Log.
* Not all IP traffic is monitored:
    * Traffic generated by instances when they contact the AWS DNS server. Logged only if you use your own DNS server.
    * Traffic generated by Windows instance for Amazon Windows license activation.
    * Traffic to/from `169.254.169.254` for instance metadata.
    * DHCP traffic.
    * Traffic to reserved IP addresses (1st four and last IP) for the default VPC router.


## NATs and Bastions

NAT instance: used to provide internet traffic to EC2 instances in private subnets.
Bastion instance (jump boxes): used to securely administer EC2 instances (using SSH/RDP) in private subnets.

How to build a highly available Bastion instance:
* High availability: at least 2x Bastion Instances in 2 public subnets in 2 AZ.
* Autoscaling Groups: minimum of 1 Bastion, if Bastions goes down, ASG will deploy a Bastion into one AZ or the other.
* Route53 running health checks on the Bastion server.

Highly available NAT instances will have a similar approach as Bastion instances above.

NAT Gateways will automatically handle failover.


## Session Manager in AWS Systems Manager

Session Manager enables secure remote login to EC2 instances - alternative to SSH/RDP but more secure.

Simple: manage both Windows/Linux inestances with the same tool
Remote Login: browser-based, run an interactive session using Powershell/Bash.
Secure:
* TLS encryption;
* No Bastion hosts.
* No opening inbound ports required.
Everything is logged
* Connection history recorded in CloudTrail.
* Keystroke logging and sent to CloudWatch/S3.

Setting up Session Manager in AWS Systems Manager service
1. Create an IAM role to enable EC2 to call Systems Manager (Policy: `AmazonEC2RoleforSSM`)
2. Launch an EC2 using the role, with a Security Group that has no rules (since we don't need to open ports)
3. Create a CloudWatch Log Group for Session Manager `SM_LogGroup`.
4. Configure Session Manager #1: Goto `Systems Manager` -> `Session Manager` -> `Preferences` -> Enter the CloudWatch Log Group name you created above.
5. Configure Session Manager #2: Choose from logging options
* Encrypt session logs with KMS
* Send session logs to an S3 bucket
* Send session logs to CloudWatch logs.
6. Start a sessions: Goto `Sessions` -> `Start a session` -> Select running EC2 instance to launch web shell.

SSM-user has root privileges by default.
You can view session history / all the commands that were run during the session including all the output.


## VPC Endpoints

VPC Endpoint enables you to privately connect VPC to supported AWS Services, without needing to go through a NAT Gateway - it goes over the private network, instead of the public network.
* Normal: VPC internal network -> NAT Gateway -> AWS S3.
* VPC Endpoint: VPC internal network -> internal gateway -> AWS S3.

Creating a VPC Endpoint
1. Create an IAM role to enable EC2 to call S3 (Policy: `AmazonS3FullAccess`)
2. Goto `EC2` -> change an attached EC2 role to the new role created above
3. Goto `VPC` -> `Endpoints` -> `Create Endpoint` -> select the S3 service gateway -> select the VPC you want to have the gateway -> select the appropriate Route Table associated with the private subnet.

You can now see the VPC Endpoint route in the chosen Route Table.
You can also SSH into private EC2 and run `aws s3 ls` to test the route.


## AWS CloudHSM

CloudHSM
* Tenancy: single-tenancy i.e. physical device is dedicated to you.
* Key control: you control all the keys i.e. only person who can access keys is yourself, not AWS.
* Symmetry: symmetric and asymmetric keys are available.
* Compliance: FIPS 140-2 | EAL-4 compliant.
* More expensive: $ charged by the hour.

AWS CloudHSM provides hardware security modules (HSMs) in a cluster. A cluster is a collection of individual HSMs that AWS CloudHSM keeps in sync. You can think of a cluster as one logical HSM. When you perform a task or operation on one HSM in a cluster, the other HSMs in that cluster are automatically kept up to date.

Creating and setting up a HSM Cluster:
1. Create a VPC + public and private subnet (so Cluster is across multiple Availability Zones for HA)
2. Create the Cluster
* Creation of Cluster will create a new Security Group with open inbound ports that CloudHSM will use to communicate with our EC2 instances.
3. Verify HSM Identity (optional)
4. Initialise the Cluster
5. Launch a client EC2 instance
6. Install and configure the client software on the instance
7. Activate the Cluster
8. Setup Users + Generate Symmetric/Asymmetric Keys

CloudHSM User Types:
1. _Precrypto Officer (PRECO)_: default account with admin/password creds -> upon password setting, you will be promoted to CO.
2. _Crypto Officer (CO)_: performs user management operations e.g. create and delete users and change user passwords.
3. _Crypto Users (CU)_: performs key and crypto management operations
* Key managent - create, delete, share, import, export cryptographic keys.
* Cryptographic operations - use cryptographic keys for encryption, decryption, signing, verifying and more.
4. _Appliance User (AU)_: perform cloning and synchronization operations.
* CloudHSM uses the AU to synchronize HSMs in the AWS CloudHSM Cluster.
* AU exists on all HSMs provided by AWS CloudHSM and has limited permissions.s

Check out https://docs.aws.amazon.com/cloudhsm/latest/userguide/hsm-users.html for more info of CloudHSM users.

```bash
# Before you can initialize a Cluster, you must download and sign a Certificate Signing Request (CSR) that is generated by the Cluster's # first HSM.

# generate private key "customerCA.key"
openssl genrsa -aes256 -out customerCA.key 2048
# generate public key (using the private key) - this is the self-signed certificate
openssl req -new -x509 -days 3652 -key customerCA.key -out customerCA.crt
# copy the cert signing request "ClusterCsr.csr" downloaded from AWS CloudHSM into your instance
nano <cluster_id>_ClusterCsr.csr
# create signed Cluster certificate, used to initialize our Cluster: take private/public keys to sign the ClusterCsr.csr
openssl x509 -req -days 3652 -in <cluster_id>_ClusterCsr.csr \
                              -CA customerCA.crt \
                              -CAkey customerCA.key \
                              -CAcreateserial \
                              -out <cluster_id>_CustomerHsmCertificate.crt

# get the software client to help administer the HSM
wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-latest.el7.x86_64.rpm
# install the client
sudo yum install -y ./cloudhsm-client-latest.el7.x86_64.rpm
# copy the public key to the local CloudHSM directory
cp customerCA.crt /opt/cloudhsm/etc/customerCA.crt

# configure the Cluster with private IP of the Cluster
sudo /opt/cloudhsm/bin/configure -a <cluster_IP>
# CONNECT TO + MANAGE THE CLUSTER using the tool "cloudhsm_mgmt_util"
/opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg

# enable end-to-end encryption
enable_e2e
# ret list of users configured on CloudHSM
listUsers

# setup PRECO and setup password
loginHSM PRECO admin password
changePswd PRECO admin <NewPassword>
listUsers
logoutHSM

# login as CO -> create CU
loginHSM CO admin acloudguru
createUser CU ryan acloudguru
listUsers
logoutHSM
quit

# start managing keys by starting "cloudhsm-client" service -> "key_mgmt_util" tool
sudo service cloudhsm-client start
/opt/cloudhsm/bin/key_mgmt_util
# login as CU -> generate symmetric key + asymmetric keypair
loginHSM -u CU -s ryan -p acloudguru
genSymKey -t 31 -s 32 -l aes256
genRSAKeyPair -m 2048 -e 65537 -l rsa2048
# generate a WRAPPING KEY to prepare for exporting symmetric and/or priv keys
genSymKey -t 31 -s 16 -sess -l export-wrapping-key
# export Symmetric / Asym privkey using the wrapping key
exSymKey -k <symmetric_key> -out aes256.key.exp -w <wrapping_key>
exportPrivateKey -k <private_key> -out rsa2048.key.exp -w <wrapping_key>
# export the Asym pubkey (no need for wrapping key)
exportPubKey -k 22 -out rsa2048.pub.exp
logoutHSM
exit
```

Exam Tip: Remember the 4 user types: PRECO | CO | CU | AU


## AWS DNS and Custom VPCs

Creating a VPC = automatically includes an AWS DNS server which is used to public DNS hostnames.
* Used for instances in your VPC which are communicating over the internet.
* DNS server uses (one of the five) reserved IP address in your VPC CIDR range - `10.0.0.2`

Using your own custom DNS server.
1. Disable the AWS DNS server: Select `your VPC` -> `actions` -> `edit DNS Resolution` -> `Uncheck checkbox`.
2. Use your own custom DNS: Goto `DHCP options set` -> `Create DHCP options set` -> fill in fields -> associate with your VPC.


## AWS Transit Gateway

VPC connectivity can be very messy. AWS Transit Gateway service helps simplify your network when you have multiple VPCs and your own datacentre and you need everything to communicate with each other (via. VPC peering).

Non-Transit Gateway
* Each VPC requires VPN connection and configuration to the On-Prem Network / Datacentre.
* VPCs require peering between each other.
* Hundreds of VPCs: difficult to manage, not scalable.

Transit Gateway
* Highly scalable: supports thousands of VPCs (hub-and-spoke architecture)
* Centralised: Transit Gateway sits between all your VPCs and Datacentre. Only need to configure once. Any VPC connected via. Transit Gateway can communicate with every other connected VPC.
* Route Tables are used to control which VPCs can communicate with each other.
* Secure: communication between VPCs are done via. AWS private network. Inter-region traffic is supported.


## AWS VPC Summary

__MAKE SURE YOU CAN BUILD A CUSTOM VPC FROM MEMORY BEFORE TAKING EXAM.__

Summary:
* Build a custom VPC with __private + public subnet__.
* Instances in private subnet have internet access via. __NAT Gateway__.
* Replace __DEFAULT Route Table__ (which all new subnets are associated with) with a __NEW Route Table__ and put a route out using __Internet Gateway__ -> Every subnet we want to make public, we would associate with that NEW Route Table.
* Create a __NAT Instance__ -> disable Src/Dest check.
    * They must be in a public subnet.
    * There must be a route out of private subent to the NAT instance for this to work.
    * Amount of traffic NAT instance supports depends on instance size. Bottleneck = increase EC2 size.
    * You can create highly availability NAT instances using ASGs, multiple subnets in different AZs, script to automate failover.
* ^__NAT Gateway__ is better than NAT Instance
    * Scale automatically up to 10Gbps
    * No patching, no associated Security Groups, automatically assigned public IP address.
    * Remember to update Route Tables when provisioning NAT Gateways.
* __Network Access Control Lists (NACL)__ 
    * Create a VPC: default NACL allows all inbound/outbount by default.
    * Custom NACL: denies all inbound/outbound by default until you add rules.
    * Each subnet in your VPC MUST be associated with a NACL. If not, it will be automatically associated with your default Netowrk ACL.
    * You can associate NACL with multiple subnets, however each subnet can have only one NACL.
    * NACLs contain a __numbered list of rules evaluated in order__, __starting with the LOWEST numbered rule first__.
    * NACLs are stateless: responses to inbound traffic are subject to the rules of outbound traffic vice versa.
    * NACLs can __block IP addresses__, Security Groups cannot.
* __Application Load Balancer__
    * You need at least 2 public subnets in order to deploy an ALB.
* __VPC Flow Logs__: monitoring network traffic across ENIs
    * You cannot enable flow logs in VPCs that are peered with your VPC unless peering is within your account.
    * You cannot tag a flow log.
    * You can't change flow log config after creating a flow log e.g. can't associate with different IAM role.
    * Not all IP traffic is monitored:
        * Traffic generated by instances when contacting AWS DNS server.
        * Traffic generated by Windows instance for AWS Windows license activation.
        * Traffic to/from instance metadata calls `169.254.169.254`.
        * DHCP traffic.
        * Traffic for reserved IP addresses for default VPC router.
* __VPC Endpoints__: Bypass NAT Gateway (public network) to access AWS service directly.

