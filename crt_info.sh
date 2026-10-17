#!/usr/bin/env bash

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

USER_AGENT="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
OUTPUT_FILE="crt_${TARGET//./_}.json"

echo "[*] Fetching CT logs for: $TARGET ..."
RESPONSE=$(curl -s -A "$USER_AGENT" "https://crt.sh/?q=%25.${TARGET}&output=json")

# Validate that response is valid JSON and not an HTML timeout/error page
if ! echo "$RESPONSE" | jq empty > /dev/null 2>&1; then
    echo "[!] Query timed out or crt.sh returned an HTML error. Retrying without wildcard..."
    RESPONSE=$(curl -s -A "$USER_AGENT" "https://crt.sh/?q=${TARGET}&output=json")
    
    if ! echo "$RESPONSE" | jq empty > /dev/null 2>&1; then
        echo "[!] crt.sh is currently unavailable or rate-limiting requests."
        exit 1
    fi
fi

# Save the raw JSON data
echo "$RESPONSE" > "$OUTPUT_FILE"
TOTAL_RECORDS=$(echo "$RESPONSE" | jq '. | length')
echo "[+] Successfully saved $TOTAL_RECORDS certificate records to $OUTPUT_FILE"

# Print deduplicated hostnames/subdomains discovered in the certificates
echo -e "\n[+] Discovered Unique Domains/Subdomains:"
echo "$RESPONSE" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
