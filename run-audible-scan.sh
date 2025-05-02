#!/bin/bash
# run_audible_scan.sh - Automated script for Audible bug bounty hunting with BBHunt
# Uses the profile-based configuration system for scope management

set -e  # Exit on any error

# Configuration - modify these as needed
H1_USERNAME="yourh1username"  # Replace with your actual HackerOne username
OUTPUT_DIR="./audible-results"
SCAN_DATE=$(date +"%Y%m%d-%H%M%S")
SCAN_MODE="standard"  # Options: basic, standard, thorough
THREADS=2

# Create necessary directories
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/recon"
mkdir -p "$OUTPUT_DIR/scan"
mkdir -p "$OUTPUT_DIR/reports"

echo "=========================================="
echo "  Audible Bug Bounty Scan with BBHunt"
echo "=========================================="
echo "Starting scan at $(date)"
echo "Using H1 username: $H1_USERNAME"
echo "Output directory: $OUTPUT_DIR"
echo "Scan mode: $SCAN_MODE"
echo "=========================================="

# 1. Check if BBHunt is properly built
if [ ! -f "./target/release/bbhunt" ]; then
    echo "[!] BBHunt binary not found. Building now..."
    cargo build --release
    if [ $? -ne 0 ]; then
        echo "[!] Failed to build BBHunt"
        exit 1
    fi
fi

# 2. Update the Audible profile with proper username
echo "[+] Customizing Audible profile with your username..."
PROFILE_PATH="./profiles/audible.toml"

# Check if profile exists
if [ -f "$PROFILE_PATH" ]; then
    # Update the username in the profile
    sed -i.bak "s/audibleresearcher_yourh1username/audibleresearcher_${H1_USERNAME}/g" "$PROFILE_PATH"
    echo "[+] Updated profile with H1 username: $H1_USERNAME"
else
    echo "[!] Audible profile not found at $PROFILE_PATH"
    exit 1
fi

# 3. Run BBHunt with the Audible profile
echo "[+] Setting the Audible profile as active..."
./target/release/bbhunt profile set audible

# 4. Create target if it doesn't exist
echo "[+] Setting up target..."
./target/release/bbhunt target add audible-bounty --domain audible.com --profile audible || \
  echo "Target already exists, continuing..."

# 5. Run passive reconnaissance first (safer)
echo "[+] Running passive reconnaissance..."
./target/release/bbhunt run subdomain_enum audible-bounty \
  --options '{"passive_only": true}' \
  --profile audible \
  > "$OUTPUT_DIR/recon/passive-recon.log" 2>&1

echo "[+] Found subdomains (passive):"
grep -i "audible" "$OUTPUT_DIR/recon/passive-recon.log" | sort -u > "$OUTPUT_DIR/recon/passive-domains.txt"
cat "$OUTPUT_DIR/recon/passive-domains.txt"

# 6. Run targeted active reconnaissance
echo "[+] Running targeted active reconnaissance..."
./target/release/bbhunt run subdomain_enum audible-bounty \
  --options '{"passive_only": false}' \
  --profile audible \
  > "$OUTPUT_DIR/recon/active-recon.log" 2>&1

echo "[+] Found subdomains (active):"
grep -i "audible" "$OUTPUT_DIR/recon/active-recon.log" | sort -u > "$OUTPUT_DIR/recon/active-domains.txt"
cat "$OUTPUT_DIR/recon/active-domains.txt"

# 7. Filter domains to ensure they're in scope
echo "[+] Filtering domains based on scope configuration..."
./target/release/bbhunt filter-scope \
  --input "$OUTPUT_DIR/recon/active-domains.txt" \
  --output "$OUTPUT_DIR/recon/in-scope-domains.txt" \
  --profile audible

echo "[+] In-scope domains:"
cat "$OUTPUT_DIR/recon/in-scope-domains.txt"

# 8. Probe for HTTP servers
echo "[+] Probing for HTTP servers..."
if command -v httpx &> /dev/null; then
    httpx -l "$OUTPUT_DIR/recon/in-scope-domains.txt" \
      -o "$OUTPUT_DIR/recon/live-http-servers.txt" \
      -title -tech-detect -status-code \
      -threads 50 -rate-limit 5 \
      -H "User-Agent: audibleresearcher_${H1_USERNAME}"
else
    echo "[!] httpx not found, using basic HTTP check..."
    while read domain; do
        if curl -s --head --max-time 5 "https://$domain" | grep -q "200 OK"; then
            echo "$domain" >> "$OUTPUT_DIR/recon/live-http-servers.txt"
        fi
    done < "$OUTPUT_DIR/recon/in-scope-domains.txt"
fi

echo "[+] Live HTTP servers:"
cat "$OUTPUT_DIR/recon/live-http-servers.txt"

# 9. Create scan tasks from discovered domains
echo "[+] Generating vulnerability scan tasks..."
cat > "$OUTPUT_DIR/scan/scan-tasks.json" << EOL
[
EOL

# Add a task for each discovered domain
while read domain; do
    cat >> "$OUTPUT_DIR/scan/scan-tasks.json" << EOL
  {
    "id": "webscan-${domain}",
    "plugin": "web_scan",
    "target": "https://${domain}",
    "options": {
      "mode": "${SCAN_MODE}"
    },
    "dependencies": []
  },
EOL
done < "$OUTPUT_DIR/recon/live-http-servers.txt"

# Remove trailing comma from last entry and close the array
sed -i.bak '$ s/,$//' "$OUTPUT_DIR/scan/scan-tasks.json"
echo "]" >> "$OUTPUT_DIR/scan/scan-tasks.json"

# 10. Run parallel scan tasks with the profile system
echo "[+] Running vulnerability scans with profile settings..."
./target/release/bbhunt parallel \
  --tasks "$OUTPUT_DIR/scan/scan-tasks.json" \
  --output "$OUTPUT_DIR/scan/scan-results.json" \
  --concurrent ${THREADS} \
  --profile audible

# 11. Generate comprehensive report
echo "[+] Generating final report..."
./target/release/bbhunt report \
  --target audible-bounty \
  --format json md html \
  --output "$OUTPUT_DIR/reports" \
  --title "Audible Bug Bounty Scan Report - $SCAN_DATE" \
  --profile audible

echo "=========================================="
echo "  Scan completed at $(date)"
echo "  Reports available in: $OUTPUT_DIR/reports"
echo "=========================================="

# Optional: Generate summary of findings by severity
if [ -f "$OUTPUT_DIR/scan/scan-results.json" ]; then
    echo "[+] Vulnerability summary:"
    
    # Count by severity
    if command -v jq &> /dev/null; then
        CRIT_COUNT=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.critical // 0' "$OUTPUT_DIR/scan/scan-results.json" | awk '{sum += $1} END {print sum}')
        HIGH_COUNT=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.high // 0' "$OUTPUT_DIR/scan/scan-results.json" | awk '{sum += $1} END {print sum}')
        MED_COUNT=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.medium // 0' "$OUTPUT_DIR/scan/scan-results.json" | awk '{sum += $1} END {print sum}')
        LOW_COUNT=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.low // 0' "$OUTPUT_DIR/scan/scan-results.json" | awk '{sum += $1} END {print sum}')
        INFO_COUNT=$(jq -r '.[] | select(.result != null) | .result.data.severity_counts.info // 0' "$OUTPUT_DIR/scan/scan-results.json" | awk '{sum += $1} END {print sum}')
        
        echo "  Critical: ${CRIT_COUNT:-0}"
        echo "  High:     ${HIGH_COUNT:-0}"
        echo "  Medium:   ${MED_COUNT:-0}"
        echo "  Low:      ${LOW_COUNT:-0}"
        echo "  Info:     ${INFO_COUNT:-0}"
        
        # If any vulnerabilities found, list the top 5
        TOTAL=$((${CRIT_COUNT:-0} + ${HIGH_COUNT:-0} + ${MED_COUNT:-0} + ${LOW_COUNT:-0} + ${INFO_COUNT:-0}))
        if [ "$TOTAL" -gt 0 ]; then
            echo ""
            echo "[+] Top findings (up to 5):"
            jq -r '.[] | select(.result != null) | .result.data.vulnerabilities[] | select(.severity == "critical" or .severity == "high") | "  - [\(.severity | ascii_upcase)] \(.name) on \(.url)"' \
               "$OUTPUT_DIR/scan/scan-results.json" | sort | head -5
        fi
    else
        echo "  Install jq for better vulnerability summary analysis"
    fi
fi

# Create a summary file
cat > "$OUTPUT_DIR/SUMMARY.md" << EOL
# Audible Bug Bounty Scan Summary

- **Date:** $(date)
- **Profile:** audible
- **Mode:** ${SCAN_MODE}
- **HackerOne Username:** ${H1_USERNAME}

## Statistics

- Discovered domains: $(wc -l < "$OUTPUT_DIR/recon/active-domains.txt" 2>/dev/null || echo "0")
- In-scope domains: $(wc -l < "$OUTPUT_DIR/recon/in-scope-domains.txt" 2>/dev/null || echo "0") 
- Live HTTP servers: $(wc -l < "$OUTPUT_DIR/recon/live-http-servers.txt" 2>/dev/null || echo "0")
EOL

if [ -f "$OUTPUT_DIR/scan/scan-results.json" ] && command -v jq &> /dev/null; then
    cat >> "$OUTPUT_DIR/SUMMARY.md" << EOL
- Vulnerabilities found: $TOTAL
  - Critical: ${CRIT_COUNT:-0}
  - High:     ${HIGH_COUNT:-0}
  - Medium:   ${MED_COUNT:-0}
  - Low:      ${LOW_COUNT:-0}
  - Info:     ${INFO_COUNT:-0}
EOL
fi

cat >> "$OUTPUT_DIR/SUMMARY.md" << EOL

## Reports

- Reports are available in: \`$OUTPUT_DIR/reports\`

## Next Steps

1. Review the generated reports in detail
2. Verify potential vulnerabilities manually
3. Prepare submissions for the bug bounty program
4. Consider focused testing on specific high-value targets

EOL

echo "[+] Created summary file: $OUTPUT_DIR/SUMMARY.md"
echo ""
echo "All done! Happy bug hunting!"#!/bin/bash
# run_audible_scan.sh - Automated script for Audible bug bounty hunting with BBHunt
# Uses the profile-based configuration system for scope management

set -e  # Exit on any error

# Configuration - modify these as needed
H1_USERNAME="yourh1username"  # Replace with your actual HackerOne username
OUTPUT_DIR="./audible-results"
SCAN_DATE=$(date +"%Y%m%d-%H%M%S")
SCAN_MODE="standard"  # Options: basic, standard, thorough
THREADS=2

# Create necessary directories
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/recon"
mkdir -p "$OUTPUT_DIR/scan"
mkdir -p "$OUTPUT_DIR/reports"

echo "=========================================="
echo "  Audible Bug Bounty Scan with BBHunt"
echo "=========================================="
echo "Starting scan at $(date)"
echo "Using H1 username: $H1_USERNAME"
echo "Output directory: $OUTPUT_DIR"
echo "Scan mode: $SCAN_MODE"
echo "=========================================="

# 1. Check if BBHunt is properly built
if [ ! -f "./target/release/bbhunt" ]; then
    echo "[!] BBHunt binary not found. Building now..."
    cargo build --release
    if [ $? -ne 0 ]; then
        echo "[!] Failed to build BBHunt"
        exit 1
    fi
fi

# 2. Initialize profile system if not already initialized
if [ ! -d "$HOME/.bbhunt/config/profiles" ]; then
    echo "[+] Initializing profile system..."
    ./target/release/bbhunt profile init
fi

# 3. Update the Audible profile with proper username
echo "[+] Creating/updating Audible profile..."
cat > "$HOME/.bbhunt/config/profiles/audible.toml" << EOL
# Audible bug bounty profile - Generated $(date)
[profile]
name = "audible"
description = "Profile for Audible bug bounty program"
tags = ["audible", "amazon", "bug-bounty"]
enabled = true

# Resource limits
[profile.resource_limits]
max_concurrent_tasks = ${THREADS}
max_requests_per_second = 5  # Audible limit
timeout_seconds = 600
max_memory_mb = 2048
max_cpu_percent = 50
scan_mode = "${SCAN_MODE}"
risk_level = "medium"

# Scope configuration - central definition of in/out of scope
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

# Global HTTP settings for all tools
[profile.http]
user_agent = "audibleresearcher_${H1_USERNAME}"

# Global headers for all requests
[profile.http.headers]
User-Agent = "audibleresearcher_${H1_USERNAME}"
Accept-Language = "en-US,en;q=0.9"
Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
EOL

# 4. Set the Audible profile as active
echo "[+] Setting Audible profile as active..."
./target/release/bbhunt profile set audible

# 5. Create target if it doesn't exist
echo "[+] Setting up target..."
./target/release/bbhunt target add audible-bounty --domain audible.com || \
  echo "Target already exists, continuing..."

# 6. Run passive reconnaissance first (safer)
echo "[+] Running passive reconnaissance..."
./target/release/bbhunt run subdomain_enum audible-bounty \
  --options '{"passive_only": true}' \
  > "$OUTPUT_DIR/recon/passive-recon.log" 2>&1

echo "[+] Found subdomains (passive):"
grep -i "audible" "$OUTPUT_DIR/recon/passive-recon.log" | sort -u > "$OUTPUT_DIR/recon/passive-domains.txt"
cat "$OUTPUT_DIR/recon/passive-domains.txt"

# 7. Run targeted active reconnaissance
echo "[+] Running targeted active reconnaissance..."
./target/release/bbhunt run subdomain_enum audible-bounty \
  --options '{"passive_only": false}' \
  > "$OUTPUT_DIR/recon/active-recon.log" 2>&1

echo "[+] Found subdomains (active):"
grep -i "audible" "$OUTPUT_DIR/recon/active-recon.log" | sort -u > "$OUTPUT_DIR/recon/active-domains.txt"
cat "$OUTPUT_DIR/recon/active-domains.txt"

# 8. Filter domains to ensure they're in scope
echo "[+] Filtering domains based on scope configuration..."
./target/release/bbhunt filter-scope \
  --input "$OUTPUT_DIR/recon/active-domains.txt" \
  --output "$OUTPUT_DIR/recon/in-scope-domains.txt" \
  --profile audible

echo "[+] In-scope domains:"
cat "$OUTPUT_DIR/recon/in-scope-domains.txt"

# 9. Probe for HTTP servers
echo "[+] Probing for HTTP servers..."
if command -v httpx &> /dev/null; then
    httpx -l "$OUTPUT_DIR/recon/in-scope-domains.txt" \
      -o "$OUTPUT_DIR/recon/live-http-servers.txt" \
      -title -tech-detect -status-code \
      -threads 50 -rate-limit 5 \
      -H "User-Agent: audibleresearcher_${H1_USERNAME}"
else
    echo "[!] httpx not found, using basic HTTP check..."
    while read domain; do
        if curl -s --head --max-time 5 "https://$domain" | grep -q "200 OK"; then
            echo "$domain" >> "$OUTPUT_DIR/recon/live-http-servers.txt"
        fi
    done < "$OUTPUT_DIR/recon/in-scope-domains.txt"
fi

echo "[+] Live HTTP servers:"
cat "$OUTPUT_DIR/recon/live-http-servers.txt"

# 10. Run vulnerability scanning with Nuclei
echo "[+] Running vulnerability scanning with Nuclei..."
if command -v nuclei &> /dev/null; then
    nuclei -l "$OUTPUT_DIR/recon/live-http-servers.txt" \
      -o "$OUTPUT_DIR/scan/vulnerabilities.json" \
      -tags cve,oast,injection,sqli,xss,ssrf,idor,redirect \
      -exclude-tags dos,fuzz,brute-force,misc,default-logins,exposures \
      -severity critical,high,medium,low \
      -rate-limit 5 \
      -c 10 \
      -timeout 10 \
      -retries 1 \
      -silent \
      -json \
      -H "User-Agent: audibleresearcher_${H1_USERNAME}"
else
    echo "[!] Nuclei not found. Please install Nuclei to perform vulnerability scanning."
    echo "    https://github.com/projectdiscovery/nuclei"
fi

# 11. Generate comprehensive report
echo "[+] Generating final report..."
./target/release/bbhunt report \
  --target audible-bounty \
  --format json md html \
  --output "$OUTPUT_DIR/reports" \
  --title "Audible Bug Bounty Scan Report - $SCAN_DATE"

echo "=========================================="
echo "  Scan completed at $(date)"
echo "  Reports available in: $OUTPUT_DIR/reports"
echo "=========================================="

# Optional: Generate summary of findings by severity
if [ -f "$OUTPUT_DIR/scan/vulnerabilities.json" ]; then
    echo "[+] Vulnerability summary:"
    
    # Count by severity
    if command -v jq &> /dev/null; then
        echo "Critical: $(grep -c '"severity":"critical"' "$OUTPUT_DIR/scan/vulnerabilities.json")"
        echo "High: $(grep -c '"severity":"high"' "$OUTPUT_DIR/scan/vulnerabilities.json")"
        echo "Medium: $(grep -c '"severity":"medium"' "$OUTPUT_DIR/scan/vulnerabilities.json")"
        echo "Low: $(grep -c '"severity":"low"' "$OUTPUT_DIR/scan/vulnerabilities.json")"
        echo "Info: $(grep -c '"severity":"info"' "$OUTPUT_DIR/scan/vulnerabilities.json")"
    else
        echo "Install jq for better vulnerability summary analysis"
    fi
fi