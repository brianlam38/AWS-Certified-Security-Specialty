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
* IP #3 reserved for DNS purposes
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