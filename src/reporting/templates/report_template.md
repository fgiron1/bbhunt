// templates/report_template.md
# {{ title }}

**Generated:** {{ generated_date }}
**Target:** {{ target }}

## Summary

- **Total Hosts Scanned:** {{ total_hosts }}
- **Total Findings:** {{ total_findings }}
- **Severity Breakdown:**
  - Critical: {{ critical_count }}
  - High: {{ high_count }}
  - Medium: {{ medium_count }}
  - Low: {{ low_count }}
  - Info: {{ info_count }}

**Scan Duration:** {{ duration_seconds }} seconds

## Findings

{{ findings }}

## OSINT Information

### Company Information
{{ company_info }}

### Social Profiles
{{ social_profiles }}

### Email Addresses
{{ email_addresses }}

### DNS Records
{{ dns_records }}

### Certificates
{{ certificates }}

## Metadata
{{ metadata }}