# Awesome DNS Security

> A curated list of awesome DNS security tools, techniques, and educational resources for developers, security professionals, and enthusiasts.

## Table of Contents
- [Overview](#overview)
- [Introduction to DNS](#introduction-to-dns)
- [DNS Security Standards](#dns-security-standards)
- [DNS Tools](#dns-tools)
- [DNS Monitoring and Analysis](#dns-monitoring-and-analysis)
- [DNS Firewalls and Filtering](#dns-firewalls-and-filtering)
- [DNS Tunneling Detection and Prevention](#dns-tunneling-detection-and-prevention)
- [DNSSEC (DNS Security Extensions)](#dnssec-dns-security-extensions)
- [DNS Amplification Attack Mitigation](#dns-amplification-attack-mitigation)
- [Educational Resources](#educational-resources)
- [Articles & Papers](#articles--papers)
- [Threat Intelligence](#threat-intelligence)
- [Additional Tools](#additional-tools)

---

## Overview
The Domain Name System (DNS) is the cornerstone of the internet’s address system. Still, its open nature makes it a frequent target for attacks such as DNS spoofing, DNS cache poisoning, amplification DDoS, and DNS tunneling. This list provides resources and tools to enhance DNS security, monitor DNS traffic, detect malicious usage, and deploy proper defenses.

---

## Introduction to DNS
DNS is a core internet protocol that translates human-readable domain names into IP addresses. To start with the basics, here are some great introductory resources:

- **[howdns.works](https://howdns.works/)** - Visual and fun explanation of DNS concepts.
- **[A warm welcome to DNS](https://powerdns.org/hello-dns/)** - Beginner-friendly introduction to DNS by PowerDNS.
- **[35C3 - Domain Name System](https://www.youtube.com/watch?v=I7060fqa-B8)** - A detailed video lecture on DNS.
- **[Let's hand write DNS messages](https://routley.io/posts/hand-writing-dns-messages/)** - Learn how DNS messages are structured at a low level.
- **[DNS for Rocket Scientists](http://www.zytrax.com/books/dns/)** - A comprehensive guide to mastering DNS.
- **[Introduction to DNS](https://www.youtube.com/watch?v=dl-C6cBoRg4)** - An introduction to DNS.
- **[Everything about DNS](https://www.youtube.com/watch?v=27r4Bzuj5NQ)** - Explaination on how DNS works.

---

## DNS Security Standards
- **[RFC 4033-4035: DNSSEC](https://tools.ietf.org/html/rfc4033)** - Defines DNS Security Extensions (DNSSEC) for authenticating DNS data.
- **[RFC 8484: DNS over HTTPS (DoH)](https://tools.ietf.org/html/rfc8484)** - Encrypt DNS requests over HTTPS to avoid eavesdropping and tampering.
- **[RFC 8310: DNS over TLS (DoT)](https://tools.ietf.org/html/rfc8310)** - DNS over TLS, another method to encrypt DNS traffic.
- **[RFC 7871: EDNS0 Client Subnet](https://tools.ietf.org/html/rfc7871)** - Preserves user privacy while using the EDNS0 client subnet option.

---

## DNS Tools
- **[dnstwist](https://github.com/elceef/dnstwist)** - Identify phishing domains and potential typo-squatting domains by generating variations of a domain name.
- **[dnsdiag](https://github.com/farrokhi/dnsdiag)** - Perform DNS diagnostics and health checks.
- **[DNSx](https://github.com/projectdiscovery/dnsx)** - Powerful DNS toolkit for resolving, brute-forcing, and DNS recon.
- **[Fierce](https://github.com/mschwager/fierce)** - DNS reconnaissance tool to find hidden servers.
- **[DSAT](https://github.com/shamimrezasohag/DSAT-DNSSecurityAnalysisTool)** - Security analysis of DNS configurations for multiple domains.
- **[Internet.nl](https://internet.nl/)** - Check whether a domain/website uses modern Internet Standards.
- **[DNS Inspect](https://dnsinspect.com/)** - A free web tool that checks your domain's servers for common DNS and mail errors and generates a report explaining how to fix them.
- **[dnssec](https://github.com/themalwarenews/dnssec)** - Performs DNS security audits and takes a DNS IP as user input, which could act as a DNS security scanner.
- **[EDUdig](https://edudig.se/)** - Web based DNS troubleshooting tool
    
---

## DNS Monitoring and Analysis
- **[dnstop](https://github.com/measurement-factory/dnstop)** - Monitor DNS traffic for analysis and statistics.
- **[Zeek (formerly Bro)](https://zeek.org/)** - Network analysis framework with a DNS analyzer for security monitoring.
- **[Case study on DNS anomaly with Zeek](https://sensorfleet.com/2020/09/29/Using-Zeek-to-find-persistent-threats-by-monitoring-DNS.html)** - Using Zeek to find persistent threats by monitoring DNS anomalies.
- **[Suricata](https://suricata.io/)** - Open-source IDS/IPS with built-in DNS logging and analysis capabilities.
- **[Passive DNS](https://www.dnsdb.info/)** - Query historical DNS records to understand domain resolution patterns.
- **[Grafana Teamplate on DNS](https://grafana.com/grafana/dashboards/17171-dns-insights-dns-threat-analysis/)** - DNS analysis template of Grafana uses the prometheus data source.
- **[ELK DNS tunneling](https://www.elastic.co/guide/en/security/current/dns-tunneling.html)**
- **[Microsoft DNS analytics with ELK](https://www.elastic.co/docs/current/integrations/microsoft_dnsserver)**
- **[DNS analysis with Graylog](https://graylog.org/post/security-log-monitoring-and-dns-request-analysis/)**

---

## Conference Talk
- **[DNS queries - Walk Softly and Carry 26 Trillion Sticks - DFIR Summit 2015](https://www.youtube.com/watch?v=F2eo1gXKtf4)** - OpenDNS case study on 71 Billion DNS queries per day
- **[DEF CON 29 -Justin Perdok - Hi Im DOMAIN Steve, Please Let Me Access VLAN2](https://www.youtube.com/watch?v=lDCoyxIhTN8)**
- **[DEF CON 29 - Tianze Ding - Vulnerability Exchange: One Domain Account For More Than Exchange Server](https://www.youtube.com/watch?v=7h38rI8KT30)**
- **[Threatpost @ Black Hat USA 2021: A New Class of DNS Vulnerabilities](https://www.youtube.com/watch?v=6Xg3of8g7uI)**
- **[How Great is the Great Firewall? Measuring China's DNS Censorship](https://www.usenix.org/conference/usenixsecurity21/presentation/hoang)**
- **[Injection Attacks Reloaded: Tunnelling Malicious Payloads over DNS](https://www.usenix.org/conference/usenixsecurity21/presentation/jeitner)**
- **[code.talks 2018 Everything about DNS you never dared to ask!](https://www.youtube.com/watch?v=O4FDdc63upo)**
- **[RSA Conference - Power of DNS as an Added Defense Against Modern Attacks](https://www.youtube.com/watch?v=5t1mUguj4_8)**
- **[mWISE Conference (from Mandiant) - Taking Over Domains - Dangling DNS](https://www.youtube.com/watch?v=vKu9pQzNu74&t=9s)**
- **[All about DNS from DNS OARC](https://www.youtube.com/@DNSOARC)**

---

## DNS Firewalls and Filtering
- **[Pi-hole](https://pi-hole.net/)** - A DNS-based filtering tool that blocks ads and malicious domains.
- **[Quad9](https://www.quad9.net/)** - Free public DNS resolver with threat filtering.
- **[Cisco Umbrella](https://umbrella.cisco.com/)** - DNS-layer security service with filtering for malware and phishing domains.

---

## DNS Tunneling Detection and Prevention
- **[Iodine](https://github.com/yarrick/iodine)** - A DNS tunneling tool for testing the security of DNS tunnels.
- **[dnscat2](https://github.com/iagox86/dnscat2)** - A tool for establishing tunnels via DNS, often used for exfiltration and backdoor communication.
- **[DNSCrypt](https://dnscrypt.info/)** - Authenticate DNS traffic to prevent man-in-the-middle attacks.

---

## DNSSEC (DNS Security Extensions)
- **[DNSViz](https://dnsviz.net/)** - A graphical tool for visualizing DNSSEC configurations and issues.
- **[OpenDNSSEC](https://www.opendnssec.org/)** - A DNSSEC key and zone management tool.
- **[PowerDNS DNSSEC](https://doc.powerdns.com/authoritative/dnssec/index.html)** - PowerDNS setup guide for enabling DNSSEC.

---

## DNS Amplification Attack Mitigation
- **[dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html)** - A caching DNS forwarder that limits the size of responses, preventing DNS amplification attacks.
- **[Anycast DNS](https://blog.cloudflare.com/anycast-dns-ddos-mitigation/)** - Mitigate DNS DDoS using Anycast technology.
- **[Rate-Limiting DNS Resolvers](https://dnsrpz.info/)** - Implement rate-limiting to prevent DNS amplification attacks.

---

## Educational Resources
- **[DNS Security Fundamentals](https://www.cloudflare.com/learning/dns/dns-security/)** - Comprehensive guide to DNS security challenges and solutions.
- **[DNS-OARC Workshops](https://www.dns-oarc.net/workshop)** - Hands-on workshops focused on operational DNS security topics.
- **[ICANN DNS Security Training](https://www.icann.org/dns-security)** - Free training on DNS operations, threats, and protocol issues.

---

## Articles & Papers
- **[The State of DNS Security Report](https://www.infoblox.com/resources/whitepapers/state-of-dns-security-report/)** - Insights into the latest DNS threats and defenses.
- **[DNS Cache Poisoning Resurgence](https://blog.apnic.net/2021/08/16/dns-cache-poisoning-resurfacing/)** - An analysis of modern DNS cache poisoning attacks.
- **[Detecting DNS Tunneling](https://dl.acm.org/doi/10.1145/3243734.3243855)** - Academic paper on techniques for DNS tunneling detection.
- **[Sub-domain Take over](https://www.hackerone.com/hackerone-community-blog/guide-subdomain-takeovers)** - A Guide To Subdomain Takeovers.
- **[DNS Evaluation](https://blog.apnic.net/2024/07/01/dns-evolution/)** - History of DNS by Geoff Huston.
- **[DNS infrastructure resilience](https://github.com/shamimrezasohag/conf-talk-slides/blob/main/slides/my_12_years_journey_of_DNS_Security_btNOG.pdf)** - A case study of 12 years of DNS infrastructure reformation.

---

## Threat Intelligence
- **[SecurityTrails](https://securitytrails.com/)** - Comprehensive threat intelligence platform with DNS and IP intelligence.
- **[DNSDB](https://www.farsightsecurity.com/solutions/dnsdb/)** - Passive DNS threat intelligence platform by Farsight Security.

---

## Additional Tools
- **[massdns](https://github.com/blechschmidt/massdns)** - High-performance DNS resolver for massive lookups.
- **[dnsrecon](https://github.com/darkoperator/dnsrecon)** - DNS enumeration tool.
- **[dnschef](https://github.com/iphelix/dnschef)** - Highly configurable DNS proxy for testing and research.

---

## Contributing
Contributions are welcome! Please open a pull request to add any new tools, articles, or educational resources.

---

## License
[MIT](LICENSE)
