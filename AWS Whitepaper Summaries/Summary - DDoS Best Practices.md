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

