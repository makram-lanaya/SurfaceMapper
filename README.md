# 🔍 Recon & Enumeration Bash Script

SurfaceMapper is a lightweight Bash-based reconnaissance tool designed for attack surface mapping during bug bounty hunting and web penetration testing.

⚠️ Note: This tool does not perform subdomain enumeration by itself.
You must provide a list of subdomains collected using external tools

## Features
- Subdomain enumeration
- Live endpoint detection
- Open ports & service detection
- URL & parameter extraction
- JavaScript & interesting files discovery
- Potential secrets detection

 
## Workflow

This tool does not perform subdomain enumeration by itself.
You must first collect subdomains using external tools, then provide them as input.

### Step 1: Collect Subdomains
Use any subdomain enumeration tools you prefer, such as:
+ subfinder<br>
+ assetfinder<br>
+ amass<br>
+ findomain<br>

Save all discovered subdomains into a file named ``subs.txt``

### Step 2: Run SurfaceMapper

Once you have your subdomains list, run the script by providing: <br>

+ The target domain
+ The subdomains file
## Usage
```bash
./SurfaceMapper.sh target.com subs.txt
``` 
