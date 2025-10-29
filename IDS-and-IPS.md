# Intrusion Detection and Prevention Systems (IDS/IPS)

## 1. Introduction
Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) are key components of modern cybersecurity. Both are used to detect malicious network activity, but they differ in response capability:

- **IDS (Intrusion Detection System)** detects and alerts about suspicious activities.
- **IPS (Intrusion Prevention System)** detects and actively blocks malicious activities in real-time.

| Feature | IDS | IPS |
|----------|-----|-----|
| Function | Detect & alert | Detect & block |
| Mode | Passive | Inline |
| Example | Snort (IDS mode) | Suricata (IPS mode) |

---

## 2. IDS/IPS Architecture
### Components
- **Sensor/Agent:** Captures traffic or logs.
- **Analyzer:** Detects attacks using rules, signatures, or anomalies.
- **Database:** Stores attack signatures or learned behavior models.
- **Console:** Displays alerts and allows management actions.
- **Response Module:** (IPS only) Blocks or drops malicious traffic.

### Types
- **Network-based IDS/IPS (NIDS/NIPS):** Monitors network packets.
- **Host-based IDS/IPS (HIDS/HIPS):** Monitors activities within a system.

---

## 3. Detection Techniques
### Signature-Based Detection
- Matches packets with known attack signatures.
- Advantage: Fast and accurate for known threats.
- Limitation: Cannot detect zero-day attacks.

### Anomaly-Based Detection
- Learns “normal” network behavior and flags deviations.
- Advantage: Detects new/unknown attacks.
- Limitation: May cause false positives.

### Hybrid Detection
Combines both methods to balance accuracy and detection capability.

---

## 4. Common IDS/IPS Solutions
### Open Source
- **Snort:** Cisco’s open-source IDS/IPS; rule-based detection.
- **Suricata:** Multi-threaded, supports TLS, HTTP/2, file extraction.
- **Zeek (Bro):** Focuses on behavioral analysis and scripting.
- **OSSEC/Wazuh:** Host-based IDS for log monitoring and integrity checking.
- **Security Onion:** Full Linux distro with Zeek, Suricata, Kibana, and Wazuh integrated.

### Commercial
- **Palo Alto Networks Threat Prevention**
- **Cisco Firepower NGIPS**
- **Fortinet FortiGate IPS**
- **Trend Micro TippingPoint**

---

## 5. Deployment Considerations
### A. Network Placement
- **Inline Mode (IPS):** Inspects and blocks packets in real time.
- **Passive Mode (IDS):** Uses SPAN or TAP to monitor traffic without affecting flow.

### B. Performance and Scalability
- Use multi-threaded IDS/IPS engines (e.g., Suricata).
- Optimize with DPDK, PF_RING, or hardware acceleration.

### C. Encrypted Traffic
- Implement SSL/TLS decryption where legal.
- Use metadata and fingerprinting for encrypted traffic detection.

### D. Logging and SIEM Integration
- Forward structured logs (EVE JSON or Zeek logs) to SIEM (Splunk, ELK, QRadar).

### E. Tuning and False Positives
- Deploy in monitor mode first.
- Whitelist trusted traffic.
- Adjust thresholds to reduce alert noise.

### F. High Availability
- Implement redundancy and fail-open/closed configurations for inline IPS devices.

---

## 6. IPS Response Techniques
- Drop or block packets.
- Reset TCP connections.
- Quarantine malicious hosts.
- Dynamic firewall rule updates.
- Rate limiting and throttling.

---

## 7. Advanced Topics
- **IDS Evasion Techniques:** Fragmentation, encoding, obfuscation.
- **Machine Learning in IDS:** Adaptive anomaly detection.
- **Fileless Malware Detection:** Memory and behavioral monitoring.
- **Deep Packet Inspection (DPI):** Examines headers and payloads for threats.
- **Cloud-based IDS:** AWS GuardDuty, Azure Defender.

---

## 8. Integration with Other Security Systems
- **SIEM:** Correlates IDS alerts with other logs.
- **SOAR:** Automates responses.
- **XDR/EDR:** Enhances endpoint-level visibility.

---

## 9. Practical Implementation Steps
1. Define goals: detection or prevention.
2. Choose IDS/IPS type: NIDS, HIDS, or both.
3. Deploy sensors on key network points.
4. Integrate with SIEM for centralized monitoring.
5. Enable rule auto-updates and tune periodically.
6. Test detection using penetration testing tools (e.g., Metasploit).

---

## 10. Advantages and Limitations
### Advantages
- Early detection of intrusions.
- Protection against known exploits.
- Detailed forensic data for incident response.

### Limitations
- False positives and negatives.
- Encrypted traffic blindness.
- Requires regular tuning and maintenance.

---

## 11. Conclusion
IDS and IPS are critical for modern network defense. Combining open-source tools like Suricata and Zeek with commercial solutions provides layered security and visibility. Regular tuning, SIEM integration, and continuous monitoring are key to effective intrusion detection and prevention.

