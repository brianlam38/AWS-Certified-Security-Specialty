## You have an EC2 host in a private subnet which needs to access S3. Which of the following is the most secure way to enable access to the S3 bucket?

```
>> Use an VPC Gateway Endpoint
Use Direct Connect
Use a VPN Gateway
Use a NAT Gateway
```

A VPC Gateway Endpoint enables you to __privately connect your VPC to supported AWS services__ and VPC Endpoint services powered by PrivateLink without requiring an internet gateway, NAT device, VPN connection, or AWS Direct Connect connection. Instances in your VPC do not require public IP addresses to communicate with resources in the service. Traffic between your VPC and the other service does not leave the Amazon network.

## You have a number of instances in a private subnet in your VPC, which need to access the internet. You have added a NAT Gateway to the VPC and added a Security Group rule allowing outbound internet traffic, however internet access is still not working. What could the problem be?

```
You forgot to disable source/destination checks on the NAT Gateway
You forgot to add a Security Group inbound rule to allow the response from the external website to reach your instances
>> You forgot to update the private subnet’s route table to route internet-bound traffic via the NAT gateway
You forgot to add an elastic IP address to the instances which need to access the internet
```

After you've created a NAT gateway, you must __update the route table associated with one or more of your private subnets to point Internet-bound traffic to the NAT gateway__.

* Disabling source/destination checks is only necessary for a NAT instance, not for a NAT Gateway.
* An Elastic IP is a public IP address so should not be used for a private instance.
* Security Groups are stateful so you do not need to configure an inbound rule for responses if an outbound rule already exists.

## Which of the following can be accomplished using VPC Flow Logs?

```
Routing of IP traffic into and out of your VPC, ENIs and subnets
Analysis of network packet headers for traffic flowing into and out of your VPC
Filtering of IP traffic into and out of your VPC, ENIs and subnets
>> Analysis of the IP traffic flow into and out of your VPC, ENIs and subnets
```

VPC Flow Logs is a feature that enables you to __capture information about the IP traffic going to and from network interfaces in your VPC__. Flow logs can help you with a number of tasks; for example, to troubleshoot why specific traffic is not reaching an instance, which in turn helps you diagnose overly restrictive security group rules. You can also use flow logs as a security tool to monitor the traffic that is reaching your instance.

## How can you enable instances in one VPC to communicate with instances in another VPC without sending traffic across the public internet?

```
Use a VPC Gateway Endpoint
Use a Direct Connect connection
>> Use VPC peering
Use AWS PrivateLink
```

A VPC peering connection is a networking connection between two VPCs that enables you to __route traffic between them using private IPv4 addresses or IPv6 addresses__. Instances in either VPC can communicate with each other as if they are within the same network.

## Which of the following would you use to block inbound network traffic from a known IP address range from reaching your VPC subnet?

```
>> Network ACL
AWS WAF
Security Group
VPC Flow Log
```

A Network ACL firewall for __controlling traffic in and out of one or more subnets based on IP address range, port and protocol__.

* Security Groups work on the instance level rather than on the subnet level.
* Flow Logs enable you to capture information about the IP traffic going to and from network interfaces in your VPC.
* AWS WAF is a web application firewall to protect applications from common exploits.

## How can you securely enable an EC2 instance in a private subnet to access the internet to download security patches for software running on your instance?

```
>> Use a NAT Gateway or NAT Instance
Use an Internet Gateway
Use Direct Connect
Use a VPN Gateway
```

You can use a network address translation (NAT) gateway to __enable instances in a private subnet to connect to the internet or other AWS services__, but __prevent the internet from initiating a connection with those instances__.

* Internet Gateway: Allows communication between VPC and internet
* Direct Connect: Allows communication between on-premise datacenter/office environment to AWS
* VPN Gateway: Allows communication between VPC and your VPN.

## You have configured a Network ACL to allow outbound access allowing all the EC2 instances in your subnet to download application updates accessed over the internet from a trusted third party using port 443. However your instances are still not able to download any updates. What could the problem be?

```
You need to add a rule to the Network ACL allowing inbound traffic on port 80
>> You need to add a rule to the Network ACL allowing inbound traffic on ephemeral ports 1024-65535
You need to add a rule to the Network ACL allowing inbound traffic on port 8080
You need to add a rule to the Network ACL allowing inbound traffic on port 443
```

An ephemeral port is a short-lived transport protocol port used for IP communications. If an __instance in your VPC is the client initiating a request, your network ACL must have an inbound rule to enable traffic destined for the ephemeral ports specific to the type of instance__ (Amazon Linux, Windows Server 2008, and so on). In practice, to cover the different types of clients that might initiate traffic to public-facing instances in your VPC, you can open __ephemeral ports 1024-65535__. This allows inbound return IPv4 traffic from the Internet, for requests that originate in your subnet.

## Which of the following statements is correct in relation to Security Groups? (Choose 2)

```
Security Groups are stateless
>> Security Groups are stateful
If you have configured an outbound rule allowing traffic to be sent from your EC2 instance, you will also need to configure a corresponding inbound rule to allow the incoming response to the request
>> If you have already configured an outbound rule allowing traffic to be sent from your EC2 instance, you do not need to configure a corresponding inbound rule to allow the incoming response to the request
```

__Security groups are stateful__ — if you send a request from your instance, the response traffic for that request is allowed to flow in regardless of inbound security group rules. Responses to allowed inbound traffic are allowed to flow out, regardless of outbound rules.

## You need to access the EC2 instances in your private subnet using SSH, which of the following is the most secure approach?

```
Access hosts in the private subnet using a NAT gateway
Add a Virtual private gateway and access the private subnet over a site-to-site VPN
Add a public IP address to one of the hosts in your private subnet and us that host to access all the others
>> Access hosts in the private subnet using a bastion host
```

To help protect their assets, many security-conscious enterprises require their system administrators to go through a “bastion” (or “jump”) host to gain administrative access to backend systems in protected or sensitive network segments. A __bastion host is a special-purpose instance that hosts a minimal number of administrative applications__, such as RDP for Windows or Putty for Linux-based distributions. All other unnecessary services are removed.

## You are configuring an Elastic Load Balancer for a highly secure environment, which has a strict requirement to secure all network connections end-to-end. How can you avoid exposing your data in plain text at any time?

```
Use an Application Load Balancer and terminate HTTP traffic on the EC2 Instance
Use a Network Load Balancer and terminate SSL on the ELB, then use HTTP to connect from the ELB to the instances
Use a Network Load Balancer and terminate SSL on the ELB, then use HTTPS to connect from the ELB to the instances
Use a Classic Load Balancer and terminate SSL on the ELB
>> Use a Network Load Balancer with TCP pass through and configure SSL termination on your EC2 instances
```

If you terminate SSL on the load balancer then communications between your load balancer and its target will be sent in plain text. To avoid this, __terminate SSL on your EC2 instance__ (providing end-to-end encryption).

## You have 3 VPCs (A, B and C). You have configured VPC peering between VPC A and VPC B, and between VPC A and VPC C. You now have a requirement for instances in VPC B to communicate with VPC C. What should you do

```
Configure the default routing table in VPC C to route all traffic destined for VPC B across VPC A
Configure a VPC Endpoint in VPC C and send the traffic to the VPC Endpoint
Do nothing because instances in VPC B will automatically be able to communicate with VPC C because they can both communicate with VPC A.
>> You will need to configure peering between VPC B and VPC C
```

__Transitive peering is NOT supported__, you cannot route packets directly from VPC B to VPC C through VPC A. You will need to explicitly configure peering between VPC B and VPC C.

## Your web application is running a CPU heavy workload and you want to add a Load Balancer to distribute HTTPS requests across a number of EC2 instances based on headers in the HTTP Request. Which of the following options should you select to give the best performance for your application?

```
Use a Classic Load Balancer and terminate HTTPS on the EC2 instance
Use a Classic Load Balancer and terminate SSL on the EC2 instance
Use a Network Load Balancer and terminate SSL on the EC2 instance
>> Use an Application Load Balancer and terminate SSL on the ELB
```

Terminating SSL on the Load Balancer __offloads the processing overhead involved in decrypting the network traffic to the Load Balancer__, which makes more processing power available on the EC2 instances running the application. So this is the recommended option.

## Which of the following statements is correct in relation to NACLs? (Choose 2)

```
Network ACLs are stateful
>> Network ACLs are stateless
>> A network ACL has separate inbound and outbound rules, and each rule can either allow or deny traffic
Network ACLs deny by default and you can only configure them to allow access
```

Network ACLs are __stateless__; responses to allowed inbound traffic are subject to the rules for outbound traffic (and vice versa).

