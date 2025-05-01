### {{ title }}

**Severity:** {{ severity }}

{{ #if has_cvss }}**CVSS Score:** {{ cvss_score }}{{ /if }}

**Description:**
{{ description }}

**Affected Targets:**
{{ affected_targets }}

**Evidence:**
{{ evidence }}

{{ #if has_remediation }}
**Remediation:**
{{ remediation }}
{{ /if }}

{{ #if has_references }}
**References:**
{{ references }}
{{ /if }}

{{ #if has_tags }}
**Tags:** {{ tags }}
{{ /if }}