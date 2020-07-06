# AWS Best Practices for DDoS Resiliency

Original link to resource: https://d1.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf

## DDoS Attacks

__Distributed Denial of Service (DDoS)__ is where an attacker uses multiple sources, such as distributed groups of malware infected computers, routers, IoT devices and other endpoints to orchestrate an attack against a target, preventing legitimate users from accessing the target.

Infrastructure Layer Attacks (OSI3 - Network / OSI4 - Transport)
* __UDP Reflection__
    * (1) Craft UDP packet with target IP = source IP (2) Send malicious UDP packet to intermediate server (3) intermediate server is tricked into sending UDP response packets to target.
    * Amplification factor: 64byte request to 128byte response = x2 amplification
* __SYN Flood__
    * Exploits 3-way handshake
    * (1) Send flood of SYN packets to target, but never final ACK (2) Target waits waits for response to half-open TCP 

Application Layer Attacks (OSI7 - Application)
* __HTTP Flood__
    * Send HTTP requests targeted at specific resource or emulating human interactions.
* __Cache-Busting__
    * Force CDN to bypass cache and to retrieve data from origin server for every request, causing strain on appserver.
* __WordPress XML-RPC Flood (WordPress pingback)__
    * Exploit XML-RPC API of a WordPress site.
    * (1) Attacker_WP notifies Target_WP of a site link via. pingback feature (2) Target_WP attempts to fetch Attacker_WP to verify existence of link (3) Target_WP is flooded.
* Other attacks that can impact availability
    * Scraper botes, brute-forcing, credential-stuffing.

## DDoS Mitigation Techniques

AWS Shield (Standard)
* Provided by default to AWS customers, on all AWS services in every AWS region.
* Defends against common network and transport layer DDoS attacks.

AWS Shield (Advanced)
* Access to __AWS DDoS Response Team__ (DRT) for assistance in mitigating DDoS attacks that impact application availability.
* Access to __Global Threat Environment__ dashboard, providing an overview of DDoS attacks observed and mitigated by AWS.
* Access to __AWS WAF__ at NO ADDITIONAL COST for mitigating application-layer DDoS (when used with CloudFront or ALB).
* Access to __AWS Firewall Manager__ at NO ADDITIONAL COST for automated policy enforcement.
* __Sensitive detection thresholds__ which routes traffic into DDoS mitigation system earlier and can __improve time-to-mitigate attacks__ against AWS EC2, LNB.
* __Cost Protection__ that allows you to request a limited refund of scaling-related costs that result from DDoS.
* __Enhanced service level agreement__.

Infrastructure Layer Defenses
* __EC2 Auto Scaling__
    * Sudden traffic surge -> CloudWatch alarm initiates Auto Scaling based on CPU / RAM / NetworkIO / custom metrics -> EC2 fleet size increase (increase in number of EC2s)
* __Choice of Region__
    * Choose regions that are close to internet exchanges where international carriers have a strong presence, to help give you internet capacity to mitigate much larger DDoS attacks.
* __Elastic Load Balancing__
    * Distribute traffic across many instances to reduce excess traffic.
    * ELB scales automatically: attach ELB to an Auto Scaling Group.
    * 3 types of ELB: (1) Application (web-apps) (2) Classic (3) Network (TCP-based apps).
* Leverage __AWS Edge Locations__ for Scale
    * When a user requests content that you're serving with CloudFront, they are routed to the EDGE LOCATION that provides the lowest latency. EDGE LOCATIONS are a worldwide network of data centers.
    * __Web Application Delivery at the Edge__:
        * Reduce number of TCP connections to your origin (preventing HTTP Floods).
        * Prevent SYN Floods and UDP Reflection attacks from reaching your origin as CloudFront only accepts well-formed connections.
        * When serving static content with S3, use CloudFront to protect your bucket via. __Origin Access Identity (OAI)__ to ensure users can only access S3 objects by using CloudFront URLs.
    * __Domain Name Resolution at the Edge__:
        * Route53 has features such as Traffic Flow, Latency Based Routing, Geo DNS, Health Checks and Monitoring to allow you to control how R53 responds to DNS requests, to improve app performance and prevent outages.
        * Detect anomolies in the source and volume of DNS queries and prioritize requests from users that are known to be reliable.

Application Layer Defenses
* Detect and Filter Malicious Web Requests
    * Use __AWS CloudFront__ to (1) cache static content and serve it from AWS Edge Locations (2) prevent non-web traffic from reaching your origin to reduce server load (3) automatically close connmections from slow read/write attackers
    * Use __AWS WAF__ to filter and block requests based on IP match, rate-based, regex rules defined by yourself, managed by AWS or 3rd-party marketplace rules.
    * Use __AWS Shield Advanced__ to engage AWS DDoS Response Team (DRT) to create rules to mitigate an attack that is impacting your application.
    * Use __AWS Firewall Manager__ to centrally configure and manage WAF rules across your organisation. Your AWS Organisations master account can designate an administrator account, which is authorized to create Firewall Manager policies.

## Attack Surface Reduction

Resources that are NOT EXPOSED TO THE INTERNET are more difficult to attack, limiting the options an attacker has to target your application's availability.

Blocking access to origin #1: by using __Security Groups__ and __Network Access Control Lists__.
* Security Group Example: Webapp that uses an ELB and several EC2s
    1. Create an SG for the ELB and SG for the instances.
    2. Create an ALLOW rule to permit internet traffic to ELB SG + rule to permit traffic from ELB SG to the EC2s' SG = more difficult for attacker to learn about and impact the webapp.
* NACL: Use NACLs to explicitly deny certain types of traffic e.g. deny certain CIDR ranges, protocols, signatures based off known DDoS IPs etc.
* Use __AWS Shield Advanced to register Elastic IPs as Protected Resources__. DDoS against EIPs will be detected more quickly, resulting in faster mitigation.

Blocking access to origin #2: by __only allowing requests from CloudFront__. Malicious traffic cannot bypass CF and WAF and hit your origin directly.
1. Create a Security Group, allowing only traffic from CloudFront to your ELB or EC2s.
2. Create Lambda to update SG rules dynamically, triggered by an `AmazonIPSpaceChanged` SNS topic (AWS updating their internal IP ranges).
3. Use the `X-Shared-Secret` header to validate that requests sent to your origin are coming from CloudFront.

Protectin API endpoints: by using __Amazon API Gateway__.
* Configure CF distributions to include the a custom header `x-api-key`, sent to your origin endpoint.
* Configure standard or burst rate limits for each REST API method.

## Operational Techniques

It is useful to know WHEN a DDoS attack is targeting your application so you can take mitigation steps.

Visibility
* __Amazon CloudWatch__ to monitor apps running on AWS - collect and track metrics, log files, set alarms and automatically respond to changes in your AWS resources. E.g. AWS WAF `BlockedRequests` or `CountedRequests` metrics.
* __AWS Shield Advanced__ provides additional metrics to indicate if your app is being targeted. E.g. `DDoSDetected` or volume-based metrics `DDoSAttackBitsPerSecond`, `DDoSAttackPacketsPerSecond` or
`DDoSAttackRequestsPerSecond`. Can be integrated with CloudWatch or 3rd-party tools e.g. Slack/PagerDuty.
* __VPC Flow Logs__ to capture information about the IP traffic going to and from your network interfaces in your VPC.
    * Each flow records _src ip, dest ip, src port, dest port, protocol, no. of packets and bytes transferred_. Use this info to identify anomalies in network traffic and to identify a specific attack vector. E.g. UDP reflection attacks = src port 53 for DNS reflection.

Support
* Subscribe to __Business Support__ to get 24x7 access to Cloud Support Engineers who can assist with DDoS attack issues.
* Subscribe to __Enterprise Support__ for the ability to open CRITICAL CASES and receive the FASTEST RESPONSE from a Senior Cloud Support Engineer.
* Subscribe to __AWS Shield Advanced__ to escalate cases to the __AWS DDoS Response Team (DRT)__.
* Use the __AWS Shield Engagement Lambda__ to more quickly initiate contact with the DRT. E.g. use an AWS IoT button to trigger the AWS Lambda function if you have an emergency situation (emergency panic red button).


