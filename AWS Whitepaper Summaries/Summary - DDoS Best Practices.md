# AWS Best Practices for DDoS Resiliency

Original link to resource: https://d1.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf

## DDoS Attacks

__Distributed Denial of Service (DDoS)__ is where an attacker uses multiple sources, such as distributed groups of malware infected computers, routers, IoT devices and other endpoints to orchestrate an attack against a target, preventing legitimate users from accessing the target.

### Infrastructure Layer Attacks

Covers OSI3 (Network) and OSI4 (Transport) layers.

UDP reflection attacks
* Exploit that fact that UDP is a stateless protocol.
* Attack steps:
    1. Attacker crafts valid UDP packet listing target IP = source IP
    2. Attacker sends malicious UDP packet to intermediate server
    3. Intermediate server is tricked into sending UDP response packets to the target
* The intermediate server would generate a response that is several times larger than the request packet, effectively amplifying the attack traffic sent to the target IP.
* __Amplification factor__ example: 64byte request to 128byte response = x2 __Amplification

SYN flood attacks
* Exploits the TCP 3-way handshake.
* Attack steps:
    1. Attacker sends a flood of SYN packets to target, but never sends final ACK to complete 3-way handshake.
    2. Target waits for a response to half-open TCP connections and runs out of capacity to accept new TCP connections.
    3. New users cannot initiate 3-way handshake with the target server.

### Application Layer Attacks

Covers OSI7 (Application) layer.

HTTP Flood attacks
* Send HTTP requests that appear to be from a real user.

Cache-busting attacks
* A type of HTTP Flood that uses variations in query-string to circumvent CDN caching.
* Purposely force the CDN to bypass cache and contact the original server for every page request, causing strain on the appserver.

WordPress XML-RPC flood attack (WordPress pingback)
* Attacker misuses the XML-RPC API function of a website hosted on WordPress to generate a flood of HTTP requests.
* WP Pingback feature notifies that WPSite_Attacker has linked to WPSite_Target. WPSite_Target attempts to fetch WPSite_Attacker to verify existence of the link.
* The feature is misused to flood target WordPress sites.

Other attacks that can impact availability
* Scraper bots, brute forcing, credential stuffing

## DDoS Mitigation Techniques

