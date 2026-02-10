#!/bin/bash

# Automated Reconnaissance Script
# Author: Security Researcher
# Description: Comprehensive subdomain enumeration, HTTP probing, port scanning, URL collection, and JS analysis

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        AUTOMATED RECONNAISSANCE FRAMEWORK   v1            ║
║                    SurfaceMapper                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Function to print status messages
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if target is provided
if [ -z "$1" ]; then
    print_error "Usage: $0 <target.com> [subs.txt]"
    echo -e "${YELLOW}Example:${NC} $0 example.com"
    echo -e "${YELLOW}   or  :${NC} $0 example.com subs.txt"
    exit 1
fi

TARGET="$1"
SUBS_FILE="${2:-subs.txt}"

# Create organized directory structure
WORKSPACE="${TARGET}_recon_$(date +%Y%m%d_%H%M%S)"
print_status "Creating workspace: ${WORKSPACE}"
mkdir -p "${WORKSPACE}"/{httpx,ports,urls,js,sensitive}

cd "${WORKSPACE}" || exit

# Copy subs.txt if provided as second argument
if [ "$2" ]; then
    if [ -f "../${SUBS_FILE}" ]; then
        cp "../${SUBS_FILE}" subs.txt
        print_success "Copied ${SUBS_FILE} to workspace"
    else
        print_error "File ${SUBS_FILE} not found!"
        exit 1
    fi
elif [ -f "../subs.txt" ]; then
    cp ../subs.txt .
    print_success "Copied subs.txt to workspace"
else
    print_warning "No subs.txt found. Please ensure subs.txt exists in the parent directory or provide it as second argument."
    exit 1
fi

# Check if subs.txt has content
if [ ! -s "subs.txt" ]; then
    print_error "subs.txt is empty!"
    exit 1
fi

TOTAL_SUBS=$(wc -l < subs.txt)
print_success "Loaded ${TOTAL_SUBS} subdomains"

echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}           PHASE 1: HTTP/HTTPS ENUMERATION${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Phase 1: HTTP/HTTPS Probing
print_status "Running httpx to identify live hosts..."
cat subs.txt | httpx -ports 80,443,3000,3001,4000,5000,5601,7001,7002,8000,8008,8010,8080,8081,8083,8090,8100,8180,8200,8443,8500,8888,9000,9001,9043,9090,9200,9443,10000 -threads 200 -silent > httpx/live.txt
LIVE_COUNT=$(wc -l < httpx/live.txt)
print_success "Found ${LIVE_COUNT} live endpoints → httpx/live.txt"

print_status "Collecting detailed HTTP information (status, server, content-length, title)..."
cat subs.txt | httpx -ports 80,443,3000,3001,4000,5000,5601,7001,7002,8000,8008,8010,8080,8081,8083,8090,8100,8180,8200,8443,8500,8888,9000,9001,9043,9090,9200,9443,10000 -threads 200 -sc -server -cl -title -td -silent > httpx/status.txt
print_success "Detailed HTTP info saved → httpx/status.txt"

echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}           PHASE 2: PORT SCANNING${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Phase 2: Port Scanning with Naabu
print_status "Starting comprehensive port scan (excluding common ports 80,443,21,22,25)..."
print_warning "This may take some time depending on the number of hosts..."
naabu -list subs.txt -exclude-ports 80,443,21,22,25 -silent -o ports/naabu-full.txt 2>/dev/null

if [ -s "ports/naabu-full.txt" ]; then
    PORTS_COUNT=$(wc -l < ports/naabu-full.txt)
    print_success "Port scan complete: ${PORTS_COUNT} results → ports/naabu-full.txt"
else
    print_warning "No additional ports found or naabu not installed"
fi

print_status "Running detailed nmap service detection on discovered ports..."
naabu -list subs.txt -exclude-ports 80,443,21,22,25 -c 50 -nmap-cli 'nmap -sV' -silent > ports/port_status.txt 2>/dev/null

if [ -s "ports/port_status.txt" ]; then
    PORT_STATUS_COUNT=$(wc -l < ports/port_status.txt)
    print_success "Service detection complete: ${PORT_STATUS_COUNT} results → ports/port_status.txt"
else
    print_warning "No service detection results"
fi

echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}           PHASE 3: URL COLLECTION${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Phase 3: URL Collection from multiple sources
print_status "Collecting URLs from GAU (GetAllUrls) for ALL subdomains..."
print_warning "Processing $(wc -l < subs.txt) subdomains - this may take a while..."
cat subs.txt | gau --subs --blacklist png,jpg,jpeg,gif,mp3,mp4,svg,woff,woff2,etf,eof,otf,css,exe,ttf,eot 2>/dev/null > urls/url-gau.txt
GAU_COUNT=$(wc -l < urls/url-gau.txt)
print_success "GAU collected ${GAU_COUNT} URLs → urls/url-gau.txt"

print_status "Collecting URLs from Wayback Machine for ALL subdomains..."
cat subs.txt | while read -r domain; do
    echo -ne "\r${BLUE}[*]${NC} Processing wayback: ${domain}...                    "
    waybackurls "${domain}" 2>/dev/null >> urls/urls_wayback.txt
done
echo ""
WAYBACK_COUNT=$(wc -l < urls/urls_wayback.txt)
print_success "Wayback collected ${WAYBACK_COUNT} URLs → urls/urls_wayback.txt"

print_status "Collecting URLs from URLFinder for ALL subdomains..."
cat subs.txt | while read -r domain; do
    echo -ne "\r${BLUE}[*]${NC} Processing urlfinder: ${domain}...                    "
    urlfinder -d "${domain}" 2>/dev/null >> urls/urls_urlfinder_raw.txt
done
echo ""
sort -u urls/urls_urlfinder_raw.txt > urls/urls_urlfinder.txt
rm -f urls/urls_urlfinder_raw.txt
URLFINDER_COUNT=$(wc -l < urls/urls_urlfinder.txt)
print_success "URLFinder collected ${URLFINDER_COUNT} URLs → urls/urls_urlfinder.txt"

print_status "Collecting 200 status URLs from GAU for ALL subdomains..."
cat subs.txt | gau --mc 200 2>/dev/null | urldedupe > urls/urls_gau_200.txt
GAU200_COUNT=$(wc -l < urls/urls_gau_200.txt)
print_success "GAU (200 status) collected ${GAU200_COUNT} URLs → urls/urls_gau_200.txt"

echo ""
print_status "Merging all collected URLs..."
cat urls/url-gau.txt urls/urls_wayback.txt urls/urls_urlfinder.txt urls/urls_gau_200.txt > urls/all_urls_raw.txt
RAW_COUNT=$(wc -l < urls/all_urls_raw.txt)
print_success "Total raw URLs: ${RAW_COUNT}"

print_status "Deduplicating URLs with URO..."
cat urls/all_urls_raw.txt | uro > urls/uniq_urls.txt
UNIQ_COUNT=$(wc -l < urls/uniq_urls.txt)
print_success "Unique URLs: ${UNIQ_COUNT} → urls/uniq_urls.txt"

print_status "Filtering interesting file extensions (php, asp, aspx, jsp, jspx)..."
cat urls/uniq_urls.txt | grep -Ei "\.php|\.asp|\.aspx|\.jsp|\.jspx" > urls/interest.txt
INTEREST_COUNT=$(wc -l < urls/interest.txt)
print_success "Interesting files: ${INTEREST_COUNT} → urls/interest.txt"

echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}           PHASE 4: PARAMETER EXTRACTION${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Phase 4: Parameter Extraction
print_status "Extracting URL parameters..."
cat urls/uniq_urls.txt | grep '=' | urldedupe > urls/params.txt
PARAMS_COUNT=$(wc -l < urls/params.txt)
print_success "Parameters extracted: ${PARAMS_COUNT} → urls/params.txt"

# Alternative parameter extraction
print_status "Creating alternative parameter format..."
cat urls/uniq_urls.txt | sed 's/=.*/=/' | sort -u > urls/params_template.txt
PARAMS_TEMPLATE_COUNT=$(wc -l < urls/params_template.txt)
print_success "Parameter templates: ${PARAMS_TEMPLATE_COUNT} → urls/params_template.txt"

echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}           PHASE 5: JAVASCRIPT FILE ANALYSIS${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Phase 5: JavaScript File Discovery and Analysis
print_status "Crawling for JavaScript files with Katana on ALL subdomains..."
print_warning "Processing all subdomains - this will take time..."
cat subs.txt | katana -d 3 -silent 2>/dev/null | grep -E "\.js$" > js/js_files.txt
JS_COUNT=$(wc -l < js/js_files.txt)
print_success "JavaScript files found: ${JS_COUNT} → js/js_files.txt"

if [ -s "js/js_files.txt" ]; then
    print_status "Scanning JavaScript files for sensitive information..."
    
    # Download JS files and search for secrets
    mkdir -p js/downloads
    JS_ANALYZED=0
    
    while IFS= read -r js_url; do
        JS_ANALYZED=$((JS_ANALYZED + 1))
        echo -ne "\r${BLUE}[*]${NC} Analyzing JS file ${JS_ANALYZED}/${JS_COUNT}...                    "
        curl -sk "$js_url" 2>/dev/null | grep -rEi "aws_access_key|aws_secret_key|api key|apikey|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|json|gcp|htaccess|\.env|ssh key|\.git|access key|secret token|oauth_token|oauth_token_secret|bearer|authorization|private key|client_secret" >> js/secrets_raw.txt 2>/dev/null
    done < js/js_files.txt
    
    echo ""
    
    if [ -s "js/secrets_raw.txt" ]; then
        sort -u js/secrets_raw.txt > sensitive/secrets.txt
        rm js/secrets_raw.txt
        SECRETS_COUNT=$(wc -l < sensitive/secrets.txt)
        print_success "Potential secrets found: ${SECRETS_COUNT} → sensitive/secrets.txt"
        print_warning "⚠️  REVIEW THESE MANUALLY - May contain false positives!"
    else
        print_warning "No secrets found in JavaScript files"
    fi
else
    print_warning "No JavaScript files found to analyze"
fi

echo ""
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}           PHASE 6: FINAL REPORT GENERATION${NC}"
echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Generate Summary Report
REPORT_FILE="RECON_SUMMARY.txt"
print_status "Generating reconnaissance summary report..."

cat > "${REPORT_FILE}" << EOF
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║                  RECONNAISSANCE SUMMARY REPORT                        ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

Target: ${TARGET}
Date: $(date)
Workspace: ${WORKSPACE}

═══════════════════════════════════════════════════════════════════════

📊 STATISTICS OVERVIEW
═══════════════════════════════════════════════════════════════════════

Subdomains Processed:        ${TOTAL_SUBS}
Live Endpoints Found:         ${LIVE_COUNT}
Open Ports Discovered:        ${PORTS_COUNT:-0}
Service Detection Results:    ${PORT_STATUS_COUNT:-0}
Total URLs Collected:         ${RAW_COUNT}
Unique URLs:                  ${UNIQ_COUNT}
Interesting Files:            ${INTEREST_COUNT}
URL Parameters:               ${PARAMS_COUNT}
JavaScript Files:             ${JS_COUNT}
Potential Secrets:            ${SECRETS_COUNT:-0}

═══════════════════════════════════════════════════════════════════════

📁 OUTPUT FILES STRUCTURE
═══════════════════════════════════════════════════════════════════════

${WORKSPACE}/
├── httpx/
│   ├── live.txt              (Live HTTP/HTTPS endpoints)
│   └── status.txt            (Detailed HTTP response info)
├── ports/
│   ├── naabu-full.txt        (Port scan results with service detection)
│   └── port_status.txt       (Nmap service version detection)
├── urls/
│   ├── url-gau.txt           (URLs from GAU)
│   ├── urls_wayback.txt      (URLs from Wayback Machine)
│   ├── urls_urlfinder.txt    (URLs from URLFinder)
│   ├── urls_gau_200.txt      (200 status URLs from GAU)
│   ├── all_urls_raw.txt      (All URLs combined - raw)
│   ├── uniq_urls.txt         (Deduplicated unique URLs)
│   ├── interest.txt          (Interesting file extensions)
│   ├── params.txt            (URLs with parameters)
│   └── params_template.txt   (Parameter templates)
├── js/
│   └── js_files.txt          (Discovered JavaScript files)
├── sensitive/
│   └── secrets.txt           (Potential secrets from JS files)
└── RECON_SUMMARY.txt         (This report)

═══════════════════════════════════════════════════════════════════════

🎯 NEXT STEPS RECOMMENDATIONS
═══════════════════════════════════════════════════════════════════════

1. Review httpx/status.txt for interesting status codes and technologies
2. Examine ports/naabu-full.txt for unusual open ports and services
3. Test urls/params.txt for injection vulnerabilities (SQLi, XSS, etc.)
4. Analyze urls/interest.txt for potential file inclusion vulnerabilities
5. Review sensitive/secrets.txt for exposed credentials (MANUAL REVIEW!)
6. Examine js/js_files.txt for endpoints and API keys
7. Run nuclei/other scanners on httpx/live.txt for known vulnerabilities

═══════════════════════════════════════════════════════════════════════

⚠️  SECURITY NOTICE
═══════════════════════════════════════════════════════════════════════

This reconnaissance was performed for authorized security testing only.
Ensure you have proper authorization before conducting any further testing.
Always follow responsible disclosure practices.

═══════════════════════════════════════════════════════════════════════
EOF

print_success "Summary report generated → ${REPORT_FILE}"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}           ✓ RECONNAISSANCE COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

cat "${REPORT_FILE}"

echo ""
print_success "All results saved in: ${WORKSPACE}/"
print_status "Review the RECON_SUMMARY.txt file for detailed information"

echo ""
echo -e "${CYAN}Happy Hunting! 🎯${NC}"
echo ""
