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


