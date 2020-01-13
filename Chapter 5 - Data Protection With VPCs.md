## VPC Overview

__Virtual Private Cloud (VPC)__ lets you provision a logically isolated section of the AWS cloud where you can launch AWS resources in a virtual network that you define.
* Have complete control over the virtual networking env.
    * Selection of your own IP range.
    * Creation of subnets.
    * Config of route tables and network gateways.
* Can easily customize network config for your VPC
    * e.g. create public-facing subnet for your webservers that has access to the internet.
    * e.g. create private-facing subnet for your databases/appservers that has NO access to the internet.
* Can leverage multiple layers of security
    * Security groups, network access control lists (NACLs) to help control access to EC2s in each subnet.
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
* Instances behav as if they were on the same private network/
* You can peer VPCs with other AWS accounts as well as other VPCs in the same account.
* Peering is in a star configuration: i.e. 1 central VPC peers with 4 others.
    * NO TRANSITIVE PEERING e.g. VPC A can talk to B vice-versa, but A cannot talk to C via. B. Peering must be created between A and C.

## Setting up a VPC

