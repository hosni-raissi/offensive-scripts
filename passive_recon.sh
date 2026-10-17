#!/bin/bash

# ==========================================
# Redstorm: Passive Reconnaissance Module
# v4.1 - Single Organized Report + Raw Artifacts
# Author: Hosni Raissi (merged/improved)
# ==========================================

# 1. Input Validation
if [ -z "$1" ]; then
  echo -e "\e[31m[!] Usage: $0 <target.com>\e[0m"
  exit 1
fi

TARGET=$1
OUT_DIR="recon_${TARGET//./_}"
REPORT="recon_report.txt"

# 2. Setup Workspace
mkdir -p "$OUT_DIR"
cd "$OUT_DIR" || exit
mkdir -p logs

echo -e "\e[32m[+] Starting Parallel Passive Subdomain Enumeration for $TARGET\e[0m"
echo "---------------------------------------------------"

# 3. Execution Phase (PARALLEL)
echo "[*] Launching scanners in the background..."

subfinder -d "$TARGET" -all -silent -o subfinder.txt > logs/subfinder.log 2>&1 &
findomain -t "$TARGET" -q -u findomain.txt > logs/findomain.log 2>&1 &
amass enum -passive -d "$TARGET" -o amass_passive.txt > logs/amass.log 2>&1 &
assetfinder --subs-only "$TARGET" > assetfinder.txt 2> logs/assetfinder.log &
(curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt) > logs/crtsh.log 2>&1 &

echo "[*] All scanners launched. Waiting for them to finish..."
wait
echo -e "\e[32m[+] All parallel scans completed!\e[0m"
echo "---------------------------------------------------"

# 4. Aggregation Phase
echo "[+] Merging and deduplicating results..."

cat subfinder.txt findomain.txt amass_passive.txt crtsh.txt assetfinder.txt 2>/dev/null \
  | grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" \
  | sort -u > unique_subs.txt

TOTAL_SUBS=$(wc -l < unique_subs.txt)

# 5. Probing Phase
echo "[*] Probing for live web servers & extracting metadata..."

httpx -l unique_subs.txt -silent \
  -status-code -title -tech-detect -web-server -ip -cname \
  -follow-redirects -timeout 10 -threads 50 \
  -json -o live_webservers.json

if [ -f live_webservers.json ]; then
  TOTAL_LIVE=$(wc -l < live_webservers.json)
  jq -r '.url // empty' live_webservers.json > live_urls.txt
else
  TOTAL_LIVE=0
  touch live_webservers.json
  : > live_urls.txt
fi

# 6. Build ONE organized report
echo "[+] Building final report..."

emit() {
  local title="$1"
  local content
  content=$(cat)
  echo "==============================================================="
  echo "  $title"
  echo "==============================================================="
  if [ -z "$content" ]; then
    echo "(none found)"
  else
    echo "$content"
  fi
  echo
}

{
  echo "==============================================================="
  echo "  REDSTORM RECON REPORT"
  echo "  Target : $TARGET"
  echo "  Date   : $(date '+%Y-%m-%d %H:%M:%S')"
  echo "  Unique subdomains : $TOTAL_SUBS"
  echo "  Live web servers  : $TOTAL_LIVE"
  echo "==============================================================="
  echo

  # --- A. Clean summary table (URL | Status | Title | Tech)
  jq -r '[.url, (.status_code|tostring), (.title // "-"),
          (if ((.tech // []) | length) > 0 then (.tech | join(", ")) else "-" end)]
         | @tsv' live_webservers.json \
    | sort | column -t -s $'\t' \
    | emit "A. LIVE WEB SERVERS  (URL   STATUS   TITLE   TECH)"

  # --- B. Hosts NOT behind Cloudflare (direct/CDN exposure)
  jq -r 'select(((.cdn_name // "") | ascii_downcase) != "cloudflare")
         | "\(.url) -> \(.host_ip // .host // "-") [\(.webserver // "-")]"' live_webservers.json \
    | sort -u \
    | emit "B. HOSTS NOT BEHIND CLOUDFLARE (direct backend / other CDN exposure)"

  # --- C. High-value targets: API / Dev / Staging / Admin / CI
  jq -r 'select((.url + " " + (.title // ""))
           | test("api|dev|stg|stage|staging|test|admin|internal|beta|graphql|swagger|jenkins|(^|[./-])ci([./-]|$)"; "i"))
         | "\(.url) [\(.status_code)] (\(.title // "-"))"' live_webservers.json \
    | sort -u \
    | emit "C. HIGH-VALUE TARGETS (api / dev / staging / admin / internal / ci ...)"

  # --- D. 401 / 403 hosts (candidates for endpoint fuzzing)
  jq -r 'select(.status_code == 401 or .status_code == 403)
         | "\(.url) [\(.status_code)] (\(.title // "-"))"' live_webservers.json \
    | sort -u \
    | emit "D. 401 / 403 HOSTS (fuzz: /api-docs, /swagger, /v1, ...)"

  # --- E. CNAME records (third-party services)
  jq -r 'select(((.cname // []) | length) > 0)
         | "\(.input // .url) -> \(.cname | join(", ")) [\(.status_code)]"' live_webservers.json \
    | sort -u \
    | emit "E. CNAME RECORDS (third-party services)"

  # --- F. Possible subdomain takeover candidates (verify manually!)
  jq -r 'select((((.cname // []) | join(" ")) | ascii_downcase)
           | test("github\\.io|herokuapp\\.com|herokudns\\.com|azurewebsites\\.net|cloudapp\\.net|trafficmanager\\.net|amazonaws\\.com|fastly\\.net|pantheonsite\\.io|myshopify\\.com|tumblr\\.com|ghost\\.io|surge\\.sh|netlify\\.app|vercel\\.app|webflow\\.io|wpengine"))
         | "\(.input // .url) -> \(.cname | join(", "))"' live_webservers.json \
    | sort -u \
    | emit "F. POSSIBLE TAKEOVER CANDIDATES (CNAME match only — confirm manually)"

} > "$REPORT"

# 7. Cleanup: keep useful raw artifacts
rm -f subfinder.txt findomain.txt amass_passive.txt assetfinder.txt crtsh.txt all_subs.txt
# Keep:
#   unique_subs.txt
#   live_webservers.json
#   live_urls.txt
#   logs/

echo "---------------------------------------------------"
echo -e "\e[32m[+] Done! Organized report:\e[0m"
echo -e "\e[32m    $(pwd)/$REPORT\e[0m"
echo -e "\e[32m[+] Raw subdomains: $(pwd)/unique_subs.txt\e[0m"
echo -e "\e[32m[+] Live JSON      : $(pwd)/live_webservers.json\e[0m"
echo -e "\e[32m[+] Live URLs      : $(pwd)/live_urls.txt\e[0m"
echo -e "\e[32m[+] Logs           : $(pwd)/logs/\e[0m"
