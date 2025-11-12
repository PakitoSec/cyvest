# Cybersecurity Investigation Report

**Global Score:** 19.0
**Global Level:** MALICIOUS

## Statistics

- **Total Observables:** 4
- **Internal Observables:** 0
- **External Observables:** 4
- **Whitelisted Observables:** 0
- **Total Checks:** 2
- **Applied Checks:** 1
- **Total Threat Intel:** 4

### Observables by Type and Level

**FILE:**
  - INFO: 1
**EMAIL:**
  - INFO: 1
**URL:**
  - MALICIOUS: 1
**DOMAIN:**
  - INFO: 1

## Checks by Scope

### email_headers


### email_body

- **url_analysis** (Score: 15.5, Level: MALICIOUS)
  - Description: Analyze URLs in email body
  - Comment: Found phishing URL attempting to steal credentials

## Observables

### ObservableType.FILE: root_file
- **Key:** obs:file:root_file
- **Score:** 0
- **Level:** INFO
- **Internal:** False
- **Whitelisted:** False
- **Comment:** Root observable for investigation
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:email:suspicious@phishing-domain.com

### email: suspicious@phishing-domain.com
- **Key:** obs:email:suspicious@phishing-domain.com
- **Score:** 0
- **Level:** INFO
- **Internal:** False
- **Whitelisted:** False
- **Threat Intelligence:**
  - internal_db: Score 0, Level INFO
    - Unknown sender

### ObservableType.URL: https://fake-bank-login.com/verify
- **Key:** obs:url:https://fake-bank-login.com/verify
- **Score:** 15.5
- **Level:** MALICIOUS
- **Internal:** False
- **Whitelisted:** False
- **Relationships:**
  - RelationshipType.RELATED_TO → obs:file:root_file
  - uses → obs:domain:fake-bank-login.com
- **Threat Intelligence:**
  - virustotal: Score 8.5, Level MALICIOUS
    - Known phishing URL
  - urlscan: Score 7.0, Level MALICIOUS
    - Malicious content detected

### domain: fake-bank-login.com
- **Key:** obs:domain:fake-bank-login.com
- **Score:** 0
- **Level:** INFO
- **Internal:** False
- **Whitelisted:** False
- **Threat Intelligence:**
  - dns_lookup: Score 0, Level INFO
    - Recently registered domain (2 days old)

## Enrichments

### email_headers
- **Data:** {
  "from": "suspicious@phishing-domain.com",
  "to": "victim@company.com",
  "subject": "Urgent: Verify Your Account",
  "received": "2025-11-11 10:30:00",
  "spf": "fail",
  "dkim": "none"
}

## Containers

### email_analysis
- **Description:** Analysis of suspicious email
- **Aggregated Score:** 19.0
- **Aggregated Level:** MALICIOUS
- **Checks:** 2
- **Sub-containers:** 0
