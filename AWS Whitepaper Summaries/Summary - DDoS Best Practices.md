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
