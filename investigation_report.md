# Cybersecurity Investigation Report

**Global Score:** 39.5
**Global Level:** MALICIOUS
**Whitelisted Investigation:** No

## Statistics

- **Total Observables:** 13
- **Internal Observables:** 1
- **External Observables:** 12
- **Whitelisted Observables:** 1
- **Total Checks:** 4
- **Applied Checks:** 4
- **Total Threat Intel:** 13

## Checks by Scope

### email

- **email_analysis**: Score: 10.0, Level: MALICIOUS
  - Description: Phishing email analysis

### network

- **url_analysis**: Score: 10.0, Level: MALICIOUS
  - Description: Malicious URLs found in email
- **infrastructure**: Score: 9.5, Level: MALICIOUS
  - Description: Malicious infrastructure identified

### file

- **malware_detection**: Score: 10.0, Level: MALICIOUS
  - Description: Malware file analysis

## Observables

### ObservableType.FILE: input-data
- **Key:** obs:file:input-data
- **Score:** 0
- **Level:** INFO
- **Internal:** False
- **Whitelisted:** False
- **Comment:** Root observable for investigation
- **Relationships:**
  - RelationshipType.RELATED_TO ↔ obs:email-message:phishing email - invoice #12345
  - RelationshipType.RELATED_TO ↔ obs:domain-name:sketchy-site.net
  - RelationshipType.RELATED_TO ↔ obs:domain-name:google.com
  - RelationshipType.RELATED_TO ↔ obs:domain-name:new-service.cloud

### ObservableType.DOMAIN_NAME: evil-phishing.com
- **Key:** obs:domain-name:evil-phishing.com
- **Score:** 9.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Threat Intelligence:**
  - VirusTotal: Score 9.0, Level MALICIOUS
    - Known phishing domain
  - AlienVault OTX: Score 8.5, Level MALICIOUS
    - Recently reported

### ObservableType.IPV4_ADDR: 185.220.101.50
- **Key:** obs:ipv4-addr:185.220.101.50
- **Score:** 9.5
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:domain-name:evil-phishing.com
- **Threat Intelligence:**
  - AbuseIPDB: Score 9.5, Level MALICIOUS
    - C2 server

### ObservableType.DOMAIN_NAME: sketchy-site.net
- **Key:** obs:domain-name:sketchy-site.net
- **Score:** 4.5
- **Level:** SUSPICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:ipv4-addr:192.168.100.5
- **Threat Intelligence:**
  - VirusTotal: Score 4.5, Level SUSPICIOUS
    - Some detections

### ObservableType.IPV4_ADDR: 192.168.100.5
- **Key:** obs:ipv4-addr:192.168.100.5
- **Score:** 3.0
- **Level:** SUSPICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Threat Intelligence:**
  - Shodan: Score 3.0, Level SUSPICIOUS

### ObservableType.EMAIL_ADDR: attacker@evil-phishing.com
- **Key:** obs:email-addr:attacker@evil-phishing.com
- **Score:** 8.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO ↔ obs:domain-name:evil-phishing.com
- **Threat Intelligence:**
  - EmailRep: Score 8.0, Level MALICIOUS
    - Suspicious sender

### ObservableType.EMAIL_ADDR: victim@company.com
- **Key:** obs:email-addr:victim@company.com
- **Score:** -1.0
- **Level:** TRUSTED
- **Internal:** True
- **Whitelisted:** False
- **Threat Intelligence:**
  - Internal Whitelist: Score -1.0, Level TRUSTED
    - Known employee

### ObservableType.EMAIL_MESSAGE: Phishing Email - Invoice #12345
- **Key:** obs:email-message:phishing email - invoice #12345
- **Score:** 10.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:email-addr:attacker@evil-phishing.com
  - RelationshipType.RELATED_TO → obs:email-addr:victim@company.com
  - RelationshipType.RELATED_TO → obs:url:https://evil-phishing.com/login
  - RelationshipType.RELATED_TO → obs:url:https://evil-phishing.com/verify
- **Threat Intelligence:**
  - Email Gateway: Score 7.0, Level MALICIOUS
    - Flagged as suspicious

### ObservableType.URL: https://evil-phishing.com/login
- **Key:** obs:url:https://evil-phishing.com/login
- **Score:** 10.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:domain-name:evil-phishing.com
- **Threat Intelligence:**
  - URLhaus: Score 9.0, Level MALICIOUS

### ObservableType.URL: https://evil-phishing.com/verify
- **Key:** obs:url:https://evil-phishing.com/verify
- **Score:** 9.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:domain-name:evil-phishing.com
- **Threat Intelligence:**
  - URLhaus: Score 8.5, Level MALICIOUS

### ObservableType.FILE: invoice.exe
- **Key:** obs:file:invoice.exe
- **Score:** 10.0
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO ← obs:url:https://evil-phishing.com/login
  - RelationshipType.RELATED_TO ↔ obs:ipv4-addr:185.220.101.50
- **Threat Intelligence:**
  - VirusTotal: Score 10.0, Level MALICIOUS
    - Detected by 45/70 engines

### ObservableType.DOMAIN_NAME: google.com
- **Key:** obs:domain-name:google.com
- **Score:** -2.0
- **Level:** TRUSTED
- **Internal:** False
- **Whitelisted:** True
- **Threat Intelligence:**
  - Internal Whitelist: Score -2.0, Level TRUSTED
    - Known good domain

### ObservableType.DOMAIN_NAME: new-service.cloud
- **Key:** obs:domain-name:new-service.cloud
- **Score:** 2.0
- **Level:** NOTABLE
- **Internal:** False
- **Whitelisted:** False
- **Threat Intelligence:**
  - Passive DNS: Score 2.0, Level NOTABLE
    - Recently registered domain
