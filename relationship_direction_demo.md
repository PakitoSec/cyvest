# Cybersecurity Investigation Report

**Global Score:** 9.5
**Global Level:** MALICIOUS

## Statistics

- **Total Observables:** 7
- **Internal Observables:** 2
- **External Observables:** 5
- **Whitelisted Observables:** 0
- **Total Checks:** 1
- **Applied Checks:** 1
- **Total Threat Intel:** 6

### Observables by Type and Level

**FILE:**
  - INFO: 1
  - MALICIOUS: 1
**DOMAIN-NAME:**
  - MALICIOUS: 1
**IPV4-ADDR:**
  - MALICIOUS: 1
  - INFO: 2
**URL:**
  - MALICIOUS: 1

## Checks by Scope

### network_analysis

- **network_indicators** (Score: 9.5, Level: MALICIOUS)
  - Description: Network-based indicators of compromise

## Observables

### ObservableType.FILE: root_file
- **Key:** obs:file:root_file
- **Score:** 0
- **Level:** INFO
- **Internal:** False
- **Whitelisted:** False
- **Comment:** Root observable for investigation

### ObservableType.DOMAIN_NAME: c2-server.example.com
- **Key:** obs:domain-name:c2-server.example.com
- **Score:** 15.5
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RESOLVES_TO → obs:ipv4-addr:203.0.113.42
- **Threat Intelligence:**
  - virustotal: Score 7.5, Level MALICIOUS
    - Known C2 domain

### ObservableType.IPV4_ADDR: 203.0.113.42
- **Key:** obs:ipv4-addr:203.0.113.42
- **Score:** 8.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Threat Intelligence:**
  - abuseipdb: Score 8.0, Level MALICIOUS
    - Malicious IP

### ObservableType.IPV4_ADDR: 10.0.1.50
- **Key:** obs:ipv4-addr:10.0.1.50
- **Score:** 0
- **Level:** INFO
- **Internal:** True
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.COMMUNICATES_WITH ↔ obs:ipv4-addr:10.0.1.51
- **Threat Intelligence:**
  - edr: Score 0, Level INFO
    - Internal workstation

### ObservableType.IPV4_ADDR: 10.0.1.51
- **Key:** obs:ipv4-addr:10.0.1.51
- **Score:** 0
- **Level:** INFO
- **Internal:** True
- **Whitelisted:** False
- **Threat Intelligence:**
  - edr: Score 0, Level INFO
    - Internal server

### ObservableType.FILE: malware.exe
- **Key:** obs:file:malware.exe
- **Score:** 9.5
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.DOWNLOADED ← obs:domain-name:c2-server.example.com
- **Threat Intelligence:**
  - virustotal: Score 9.5, Level MALICIOUS
    - Ransomware detected

### ObservableType.URL: http://c2-server.example.com/payload
- **Key:** obs:url:http://c2-server.example.com/payload
- **Score:** 18.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:domain-name:c2-server.example.com
  - RelationshipType.CONTAINS → obs:file:malware.exe
- **Threat Intelligence:**
  - urlscan: Score 8.5, Level MALICIOUS
    - Malicious payload URL
