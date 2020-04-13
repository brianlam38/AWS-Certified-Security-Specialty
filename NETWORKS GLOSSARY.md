# Networks Glossary

__Dynamic Host Configuration Protocol (DHCP)__: assigns IP addresses dynamically to hosts in a PRIVATE network.

__Network Address Translation (NAT)__: method of rewriting packets to allow multiple devices on a private network to share a single PUBLIC IP address.

__Route Table__: contains a set of rules (routes) that are used to determine where network traffic from your subnet or gateway is directed. It allows subnets to talk to each other. Every AWS subnet provisioned will automaticaly be attached to your default/main route table. Ideally, you should create a separate route table that is internet accessible rather than use your default/main route table as every new subnet being provisioned will be associated with the default/main route table, thus becoming internet accessible.

__Subnets__: The purpose of subnetting is to help relieve network congestion. If you have an excessive amount of traffic flow across your network, then that traffic can cause your network to run slowly. When you subnet your network, most of the network traffic will be isolated to the subnet in which it originated. Ideally, your subnet structure should mimic your network's geographic structure. Other benefits of subnetting include routing efficiency, easier network management and improving network security.