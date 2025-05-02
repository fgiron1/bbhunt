#!/bin/bash
# Audible Bug Bounty Hunting Script
# This script uses the BBHunt framework to perform a security assessment of Audible properties
# following their bug bounty program guidelines

# Configuration - MODIFY THESE VALUES
H1_USERNAME="your_hackerone_username"  # Your HackerOne username
OUTPUT_DIR="./audible_hunt_$(date +%Y%m%d)"
TARGET="audible.com"
SCAN_LEVEL="standard"  # Options: basic, standard, thorough
THREADS=2  # Max concurrent tasks

# Create directories
mkdir -p "$OUTPUT_DIR"/{recon,scan,reports}
echo "Output directory created at $OUTPUT_DIR"

# Set up User-Agent for all requests
export BBHUNT_GLOBAL_USER_AGENT="audibleresearcher_${H1_USERNAME}"
echo "Using User-Agent: $BBHUNT_GLOBAL_USER_AGENT"

# Print banner
echo "======================================================"
echo "  AUDIBLE BUG BOUNTY HUNT USING BBHUNT FRAMEWORK"
echo "======================================================"
echo "Target: $TARGET"
echo "Scan Level: $SCAN_LEVEL"
echo "Date: $(date)"
echo "======================================================"

# Step 1: Build BBHunt if needed
if [ ! -f "./target/release/bbhunt" ]; then
    echo "[+] Building BBHunt framework..."
    cargo build --release
    if [ $? -ne 0 ]; then
        echo "[!] Failed to build BBHunt"
        exit 1
    fi
fi

# Step 2: Set up the Audible profile
echo "[+] Setting up Audible bug bounty profile..."
./target/release/bbhunt profile set audible || {
    echo "[!] Audible profile not found, creating it..."
    
    # Create audible profile with proper scope
    ./target/release/bbhunt profile create audible \
        --description "Profile for Audible bug bounty program with proper scope and rate limits"
    
    # Configure scope according to program guidelines
    cat > "$OUTPUT_DIR/audible-scope.toml" << EOF
[profile]
name = "audible"
description = "Audible bug bounty program profile"
tags = ["audible", "bug-bounty"]
enabled = true

[profile.resource_limits]
max_concurrent_tasks = ${THREADS}
max_requests_per_second = 5  # Audible rate limit is 5 req/sec
timeout_seconds = 600
max_memory_mb = 2048
max_cpu_percent = 50
scan_mode = "${SCAN_LEVEL}"
risk_level = "medium"

[profile.scope]
include_domains = [
    "*.audible.*"
]

exclude_domains = [
    "help.audible.com",
    "newsletters.audible.com",
    "www.audiblecareers.com",
    "www.audible.com/ep/podcast-development-program",
    "www.audiblehub.com/submit",
    "www.audible.ca/blog/en"
]

exclude_paths = [
    "/careers",
    "/jobs",
    "/podcast-development-program"
]

follow_out_of_scope_redirects = false
max_crawl_depth = 3

[profile.http]
user_agent = "audibleresearcher_${H1_USERNAME}"

[profile.http.headers]
User-Agent = "audibleresearcher_${H1_USERNAME}"
Accept-Language = "en-US,en;q=0.9"
Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
EOF

    # Import the profile
    ./target/release/bbhunt profile import "$OUTPUT_DIR/audible-scope.toml"
    ./target/release/bbhunt profile set audible
}

# Step 3: Create and set up target
echo "[+] Setting up Audible target..."
./target/release/bbhunt target add audible-bounty --domain audible.com || {
    echo "[*] Target already exists, continuing..."
}

# Step 4: Initial passive reconnaissance (safer approach)
echo "[+] Running passive reconnaissance..."
./target/release/bbhunt run subdomain_enum audible-bounty \
    --options '{"passive_only": true}' \
    > "$OUTPUT_DIR/recon/passive-recon.log"

# Extract discovered subdomains
echo "[+] Extracting passive reconnaissance results..."
grep -E "audible" "$OUTPUT_DIR/recon/passive-recon.log" | sort -u > "$OUTPUT_DIR/recon/passive-domains.txt"
echo "[*] Found $(wc -l < "$OUTPUT_DIR/recon/passive-domains.txt") domains (passive)"

# Step 5: Run targeted active reconnaissance
echo "[+] Running active reconnaissance..."
./target/release/bbhunt run subdomain_enum audible-bounty \
    --options '{"passive_only": false}' \
    > "$OUTPUT_DIR/recon/active-recon.log"

# Extract discovered subdomains
echo "[+] Extracting active reconnaissance results..."
grep -E "audible" "$OUTPUT_DIR/recon/active-recon.log" | sort -u > "$OUTPUT_DIR/recon/active-domains.txt"
echo "[*] Found $(wc -l < "$OUTPUT_DIR/recon/active-domains.txt") domains (active)"

# Step 6: Filter domains based on scope
echo "[+] Filtering domains to ensure they're in scope..."
./target/release/bbhunt filter-scope \
    --input "$OUTPUT_DIR/recon/active-domains.txt" \
    --output "$OUTPUT_DIR/recon/in-scope-domains.txt"

echo "[*] In-scope domains: $(wc -l < "$OUTPUT_DIR/recon/in-scope-domains.txt")"

# Step 7: Probe for live HTTP services
echo "[+] Probing for live HTTP services..."
if command -v httpx &> /dev/null; then
    httpx -l "$OUTPUT_DIR/recon/in-scope-domains.txt" \
        -title -tech-detect -status-code \
        -threads 50 -rate-limit 5 \
        -H "User-Agent: audibleresearcher_${H1_USERNAME}" \
        -o "$OUTPUT_DIR/recon/live-http-servers.txt"
else
    echo "[!] httpx not found, using basic HTTP check with curl..."
    while read domain; do
        if curl -s --head --max-time 5 "https://$domain" | grep -q "2"; then
            echo "$domain" >> "$OUTPUT_DIR/recon/live-http-servers.txt"
        fi
    done < "$OUTPUT_DIR/recon/in-scope-domains.txt"
fi

echo "[*] Live HTTP servers: $(wc -l < "$OUTPUT_DIR/recon/live-http-servers.txt" 2>/dev/null || echo "0")"

# Step 8: Create scan tasks
echo "[+] Generating vulnerability scan tasks..."

# Generate task definitions
cat > "$OUTPUT_DIR/scan/scan-tasks.json" << EOF
[
EOF

# Add web scan tasks for each live domain
COUNT=0
while read domain; do
    COUNT=$((COUNT+1))
    
    # Add comma if not the first entry
    if [ "$COUNT" -gt 1 ]; then
        echo "," >> "$OUTPUT_DIR/scan/scan-tasks.json"
    fi
    
    # Format the URL properly
    if [[ $domain == http* ]]; then
        URL="$domain"
    else
        URL="https://$domain"
    fi
    
    # Add task definition
    cat >> "$OUTPUT_DIR/scan/scan-tasks.json" << EOF
  {
    "id": "webscan-${COUNT}",
    "plugin": "web_scan",
    "target": "${URL}",
    "options": {
      "mode": "${SCAN_LEVEL}"
    },
    "dependencies": []
  }
EOF
done < "$OUTPUT_DIR/recon/live-http-servers.txt"

# Close JSON array
echo "" >> "$OUTPUT_DIR/scan/scan-tasks.json"
echo "]" >> "$OUTPUT_DIR/scan/scan-tasks.json"

# Step 9: Run vulnerability scans
echo "[+] Running vulnerability scans..."
./target/release/bbhunt parallel \
    --tasks "$OUTPUT_DIR/scan/scan-tasks.json" \
    --output "$OUTPUT_DIR/scan/scan-results.json" \
    --concurrent ${THREADS}

# Step 10: Generate report
echo "[+] Generating final report..."
./target/release/bbhunt report \
    --target audible-bounty \
    --format json md html \
    --output "$OUTPUT_DIR/reports" \
    --title "Audible Bug Bounty Security Assessment $(date +%Y-%m-%d)"

# Create a summary of results
echo "[+] Creating summary of findings..."
if command -v jq &> /dev/null && [ -f "$OUTPUT_DIR/scan/scan-results.json" ]; then
    # Count vulnerabilities by severity
    VULN_CRITICAL=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.critical // 0' "$OUTPUT_DIR/scan/scan-results.json" | jq -s 'add')
    VULN_HIGH=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.high // 0' "$OUTPUT_DIR/scan/scan-results.json" | jq -s 'add')
    VULN_MEDIUM=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.medium // 0' "$OUTPUT_DIR/scan/scan-results.json" | jq -s 'add')
    VULN_LOW=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.low // 0' "$OUTPUT_DIR/scan/scan-results.json" | jq -s 'add')
    VULN_INFO=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.info // 0' "$OUTPUT_DIR/scan/scan-results.json" | jq -s 'add')
    
    # Create summary file
    cat > "$OUTPUT_DIR/SUMMARY.md" << EOF
# Audible Bug Bounty Scan Summary

- **Date:** $(date)
- **Target:** $TARGET
- **Scan Level:** $SCAN_LEVEL

## Statistics
- Discovered domains: $(wc -l < "$OUTPUT_DIR/recon/active-domains.txt" 2>/dev/null || echo "0")
- In-scope domains: $(wc -l < "$OUTPUT_DIR/recon/in-scope-domains.txt" 2>/dev/null || echo "0")
- Live HTTP servers: $(wc -l < "$OUTPUT_DIR/recon/live-http-servers.txt" 2>/dev/null || echo "0")

## Vulnerability Summary
- Critical: ${VULN_CRITICAL:-0}
- High: ${VULN_HIGH:-0}
- Medium: ${VULN_MEDIUM:-0}
- Low: ${VULN_LOW:-0}
- Info: ${VULN_INFO:-0}

## Reports
Full reports can be found in the \`reports\` directory.

## Next Steps
1. Manually verify all findings to eliminate false positives
2. Prepare vulnerability reports according to Audible's reporting guidelines
3. Submit findings through HackerOne
EOF

    echo "[*] Summary created at $OUTPUT_DIR/SUMMARY.md"
    
    # Display most critical findings
    if [ "${VULN_CRITICAL:-0}" -gt 0 ] || [ "${VULN_HIGH:-0}" -gt 0 ]; then
        echo "[!] CRITICAL AND HIGH SEVERITY FINDINGS DETECTED!"
        echo "[!] Please verify these findings manually before reporting:"
        
        jq -r '.[] | select(.result != null) | 
            .result.data.vulnerabilities[] | 
            select(.severity == "Critical" or .severity == "High") | 
            "- [" + .severity + "] " + .name + " on " + .url' \
            "$OUTPUT_DIR/scan/scan-results.json" | sort -u | head -10
    fi
else
    echo "[!] jq command not found or scan results not available - skipping vulnerability summary"
fi

echo "======================================================"
echo "  BUG BOUNTY HUNT COMPLETED"
echo "  Results saved to: $OUTPUT_DIR"
echo "======================================================"
echo ""
echo "IMPORTANT: Always manually verify all findings before reporting!"
echo "Remember to follow Audible's bug bounty program rules:"
echo "- Only report issues in scope"
echo "- Do not access or modify other user's data"
echo "- No social engineering, phishing, or physical attacks"
echo "- No denial of service attacks"
echo "- Maintain confidentiality of findings"