// templates/finding_template.md
### {{ title }}

**Severity:** {{ severity }}
{{ #if cvss_score }}**CVSS Score:** {{ cvss_score }}{{ /if }}

**Description:**
{{ description }}

**Affected Targets:**
{{ #each affected_targets }}
- {{ this }}
{{ /each }}

**Evidence:**
{{ evidence_description }}

{{ #if has_request_response }}
**Request:**
{{ request }}