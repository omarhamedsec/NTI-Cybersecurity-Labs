#  Lab 10.6.7: Using Wireshark to Examine HTTP and HTTPS Traffic

##  Lab Information
- **Lab Number:** 10.6.7
- **Title:** Using Wireshark to Examine HTTP and HTTPS Traffic
- **Program:** NTI Cyber Operations Scholarship
- **Student:** Omar Mohammad Hamed
- **Date:** 2025

---

##  Lab Objectives

### Part 1: HTTP Traffic Analysis
- Capture HTTP network traffic using tcpdump
- Analyze unencrypted HTTP communications
- Identify security vulnerabilities in HTTP protocol
- Examine plaintext credential transmission

### Part 2: HTTPS Traffic Analysis
- Capture HTTPS network traffic
- Compare encrypted vs unencrypted communications
- Understand TLS/SSL encryption mechanisms
- Analyze encrypted application data

---

## Tools & Technologies Used

**Packet Capture:**
- tcpdump (command-line packet analyzer)
- Network interface: enp0s3 (192.168.1.24)

**Traffic Analysis:**
- Wireshark (graphical protocol analyzer)
- TCP/IP protocols
- TLS/SSL encryption

**Test Websites:**
- HTTP: http://www.altoromutual.com/login.jsp
- HTTPS: https://www.netacad.com

---

##  Key Findings

### HTTP Security Vulnerabilities

**Critical Issues Identified:**
1. ⚠️ **Plaintext Credentials** - Login credentials transmitted without encryption
2. ⚠️ **Readable Form Data** - All form submissions visible in Wireshark
3. ⚠️ **No Confidentiality** - Sensitive information exposed to network observers
4. ⚠️ **MITM Susceptible** - Vulnerable to man-in-the-middle attacks
5. ⚠️ **Session Hijacking** - Authentication tokens can be intercepted

**Evidence Found:**
```
HTML Form URL Encoded Data:
- uid=Admin (username field)
- passw=Admin (password field)
- btnSubmit=Login
```

All credentials were clearly visible in Wireshark packet analysis.

---

### HTTPS Security Protections

**Security Features Observed:**
1. ✅ **Complete Encryption** - All data encrypted using TLS/SSL
2. ✅ **Certificate Authentication** - Website identity verified via SSL certificate
3. ✅ **Data Integrity** - Protection against tampering
4. ✅ **Confidentiality** - No readable credentials or sensitive data
5. ✅ **Secure Handshake** - Encrypted key exchange protocol

**Technical Observations:**
- HTTP section replaced by **TLSv1.2 Record Layer**
- Application data appears as encrypted binary
- Traffic filtered on port 443 (HTTPS standard port)
- Padlock icon indicates secure connection
- No plaintext data visible in packet capture

---

##  Comparative Analysis: HTTP vs HTTPS

| Aspect | HTTP | HTTPS |
|--------|------|-------|
| **Protocol Layer** | Application Layer (plaintext) | Application + TLS/SSL Layer (encrypted) |
| **Password Visibility** | Fully visible in Wireshark | Completely encrypted |
| **Data Format** | Readable text | Encrypted binary |
| **Port** | 80 | 443 |
| **Certificate** | None | SSL/TLS Certificate required |
| **Security** | No protection | End-to-end encryption |
| **Packet Analysis** | Form data readable | Only metadata visible |

---

##  Commands Used

### Network Interface Identification
```bash
ip address
```
**Result:**
- lo (loopback): 127.0.0.1
- enp0s3 (Ethernet): 192.168.1.24

### HTTP Traffic Capture
```bash
sudo tcpdump -i enp0s3 -s 0 -w httpdump.pcap
```
**Options:**
- `-i enp0s3`: Specifies network interface to monitor
- `-s 0`: Captures complete packets (262144 bytes)
- `-w httpdump.pcap`: Writes captured traffic to file

### HTTPS Traffic Capture
```bash
sudo tcpdump -i enp0s3 -s 0 -w httpsdump.pcap
```

### Wireshark Filter
```
tcp.port==443
```
Filters traffic to show only HTTPS connections on port 443.

---

##  Security Implications

### HTTP Vulnerabilities
- **Credential Theft:** Passwords captured in plaintext
- **Session Hijacking:** Authentication tokens can be stolen
- **Data Tampering:** Content can be modified in transit
- **Eavesdropping:** All communications visible to attackers
- **No Authentication:** Cannot verify website identity

### HTTPS Protections
- **Encrypted Transmission:** Data protected from interception
- **Certificate Validation:** Confirms website authenticity
- **Data Integrity:** Detects tampering attempts
- **Privacy Protection:** Shields browsing activity
- **Compliance:** Meets regulatory requirements (GDPR, PCI-DSS)

---

##  Key Learnings

### Why Use HTTPS?

**1. Data Encryption**
HTTPS encrypts all data transmitted between client and server using SSL/TLS protocols, preventing attackers from intercepting sensitive information.

**2. Data Integrity**
Ensures data cannot be modified during transfer. Any tampering attempt will be detected.

**3. Authentication and Trust**
Digital certificates verify website identity, helping users confirm they're communicating with legitimate sites.

**4. Privacy Protection**
User activities, browsing behavior, and form submissions are protected from network observers.

**5. Compliance Requirements**
Many regulations require HTTPS for protecting sensitive user data (GDPR, PCI-DSS, HIPAA).

**6. SEO Benefits**
Search engines prioritize HTTPS websites in rankings.

### Important Note: HTTPS Limitations

 **HTTPS alone does not guarantee trustworthiness**

**What HTTPS Does Provide:**
- Encryption of data in transit
- Verification of domain ownership
- Protection against eavesdropping

**What HTTPS Does NOT Guarantee:**
- Legitimacy of website owner
- Trustworthiness of business practices
- Protection against phishing or malicious content
- Ethical practices of site operators

**Conclusion:** HTTPS is necessary but not sufficient proof of trustworthiness. Users must remain vigilant and employ multiple methods to verify website legitimacy.

---

##  Practical Applications

### 1. Public Wi-Fi Security
HTTPS provides essential protection against:
- Packet sniffing attacks
- Session hijacking
- Credential theft by network observers

### 2. E-commerce Transactions
HTTPS is mandatory for:
- Credit card processing
- Personal information collection
- Account management
- Payment processing

### 3. Corporate Networks
Organizations should:
- Enforce HTTPS for all web applications
- Monitor for HTTP traffic containing sensitive data
- Implement SSL/TLS inspection at network boundaries
- Train employees on secure browsing practices

---

##  Screenshots

### HTTP Traffic Analysis
![HTTP Login Capture](./screenshots/01-http-login-capture.png)
*Captured HTTP login attempt showing plaintext transmission*

![Credentials in Plaintext](./screenshots/02-credentials-plaintext.png)
*Username and password clearly visible in Wireshark analysis*

### HTTPS Traffic Analysis
![HTTPS Encrypted Traffic](./screenshots/03-https-encrypted.png)
*HTTPS connection showing encrypted data transmission*

![TLS Layer](./screenshots/04-tls-layer.png)
*TLSv1.2 Record Layer replacing HTTP plaintext section*

![Protocol Comparison](./screenshots/05-comparison.png)
*Side-by-side comparison of HTTP vs HTTPS packet captures*

---

##  Lab Report

The complete lab report with detailed analysis is available:
- [Lab 10.6.7 Report.pdf](./Lab%2010.6.7%20Report.pdf)

---

## 🔧 Tools Mastered

### tcpdump
- Command-line packet capture tool
- Lightweight and efficient
- Useful for automated monitoring
- Generates pcap files for later analysis

### Wireshark
- Graphical packet analysis tool
- Detailed protocol dissection
- Advanced filtering capabilities
- Essential for network forensics

---

##  Disclaimer

This lab was conducted in a controlled environment for educational purposes only as part of the NTI Cyber Operations training program. The techniques demonstrated should only be used in authorized testing environments. Unauthorized interception of network traffic is illegal.

---

##  Contact

**Omar Hamed**
- Email: omarhamed.sec@gmail.com
- LinkedIn: [linkedin.com/in/omar-hamed-sec](https://linkedin.com/in/omar-hamed-sec)

---

[← Back to Wireshark Labs](../README.md) | [↑ Back to Main Repository](../../README.md)
