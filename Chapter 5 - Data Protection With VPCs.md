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
    * _(WARNING: IN PRODUCTION, USE A BASTION HOST)_ Store private key for private EC2 on the public EC2 -> SSH into private EC2.
    * NOTE: there will be no outbound route to the public from the private EC2.
9. Provide internet connectivity to the private EC2 without placing into public subnet - for installing packages / patch OS.
    *

The first 4 IP addresses and the last IP address of each subnet CIDR block can't be used as:
* IP #1 reserved for the network address
* IP #2 reserved for the VPC router
* IP #3 reserved for DNS purposes
* IP #4 reserved for future use
* IP #LAST reserved for network broadcast address

SUBNETS: _The purpose of subnetting is to help relieve network congestion. If you have an excessive amount of traffic flow across your network, then that traffic can cause your network to run slowly. When you subnet your network, most of the network traffic will be isolated to the subnet in which it originated. Ideally, your subnet structure should mimic your network's geographic structure. Other benefits of subnetting include routing efficiency, easier network management and improving network security_

ROUTE TABLES: _Route tables contain a set of rules (routes) that are used to determine where network traffic from your subnet or gateway is directed. It allows subnets to talk to each other. Every AWS subnet you provision will automatically be attached to your default/main route table. Ideally, you should create a separate route table that is internet accessible rather than use your default/main route table as every new subnet being provisioned will be associated with the default/main route table, hence become internet accessible._