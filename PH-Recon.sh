#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/PH-Recon/resolvers.txt"
telegram_token="<YOUR_TELEGRAM_BOT_TOKEN>"
telegram_chat_id="<YOUR_TELEGRAM_CHAT_ID>"

report_path="/root/PH-Recon/vulnerability_report.txt"
echo "Vulnerability Report - $(date)" > $report_path

send_telegram_message() {
    message=$1
    curl -s -X POST https://api.telegram.org/bot$telegram_token/sendMessage -d chat_id=$telegram_chat_id -d text="$message" > /dev/null
}

process_domain() {
    domain=$1
    base_path="/root/PH-Recon/$domain"

    echo "Processing domain: $domain"
    send_telegram_message "Processing domain: $domain"

    mkdir -p $base_path/{subdomain,scan,url,gf,xss,sql,dri,js_url,Secret-api,git_dork,Subomain-Takeover,Subomain-Screenshots,Special_subdomain/scan} \
             $base_path/scan/{nuclei,jaeles,new-nuclei,my-jaeles,Php-My-Admin} \
             $base_path/url/{gaplus-urls,waybackurls,hakrawler-urls,gospider-url,all_spiderparamters,all-url,final-url,valid_urls} \
             $base_path/gf \
             $base_path/scan/jaeles/{url,my-url}

    echo "[*] Starting subdomain enumeration for $domain..."
    subfinder -d $domain -all -o $base_path/subdomain/subfinder.txt
    assetfinder -subs-only $domain | tee $base_path/subdomain/assetfinder.txt
    findomain -t $domain | tee $base_path/subdomain/findomain.txt
    amass enum -passive -d $domain -o $base_path/subdomain/amass_sub_passive.txt
    curl --insecure --silent "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e 's/\/.*//' -e 's/^www\.//' | sed "/@/d" | sed -e 's/\.$//' | sort -u | tee $base_path/subdomain/web.archive.txt
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee $base_path/subdomain/crtsub.txt
    curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee $base_path/subdomain/riddlersub.txt
    curl -s https://dns.bufferover.run/dns?q=.$domain |jq -r .FDNS_A[]|cut -d',' -f2|sort -u | tee $base_path/subdomain/bufferoversub.txt
    curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "(([http|https]:\/\/)?([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee $base_path/subdomain/jldcsub.txt
    sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
openssl x509 -noout -text -in <(
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
-connect $domain:443 ) ) | grep -Po '(([http|https]:\/\/)?([\w.-]*)\.([\w]*)\.([A-z]))\w+' | tee $base_path/subdomain/altnamesub.txt
    cat $base_path/subdomain/*.txt > $base_path/subdomain/allsub.txt
    cat $base_path/subdomain/allsub.txt | uniq -u | grep $domain | tee -a $base_path/subdomain/all_srot_sub.txt

    echo "[*] Resolving active subdomains for $domain..."
    httpx -l $base_path/subdomain/all_srot_sub.txt -threads 150 -o $base_path/subdomain/good/active_subdomain.txt

    echo "[*] Checking subdomain takeover for $domain..."
    subzy run --targets $base_path/subdomain/good/active_subdomain.txt | tee -a $base_path/Subomain-Takeover/sub_poc.txt
    if [ -s $base_path/Subomain-Takeover/sub_poc.txt ]; then
        msg="[Subdomain Takeover] Found for $domain: $base_path/Subomain-Takeover/sub_poc.txt"
        echo "$msg" >> $report_path
        send_telegram_message "$msg"
    fi

    echo "[*] Scanning open ports for $domain..."
    naabu -list $base_path/subdomain/good/active_subdomain.txt -top-ports 1000 -exclude-ports 80,443,21,22,25 -o $base_path/scan/open-port.txt
    if grep -q -i "open" $base_path/scan/open-port.txt; then
        msg="[Open Ports] Found for $domain: $base_path/scan/open-port.txt"
        echo "$msg" >> $report_path
        send_telegram_message "$msg"
    fi

    echo "[*] Running vulnerability scans for $domain..."
    nuclei -l $base_path/subdomain/good/active_subdomain.txt -t /root/nuclei-templates/ -c 50 -o $base_path/scan/new-nuclei/All.txt -v
    if [ -s $base_path/scan/new-nuclei/All.txt ]; then
        msg="[Nuclei Vulnerabilities] Found for $domain: $base_path/scan/new-nuclei/All.txt"
        echo "$msg" >> $report_path
        send_telegram_message "$msg"
    fi

    jaeles scan -c 50 -s /root/templates/jaeles-signatures -U $base_path/subdomain/good/active_subdomain.txt -o $base_path/scan/jaeles/ -v
    if [ -s $base_path/scan/jaeles/jaeles.log ]; then
        msg="[Jaeles Vulnerabilities] Found for $domain: $base_path/scan/jaeles/"
        echo "$msg" >> $report_path
        send_telegram_message "$msg"
    fi

    echo "[*] Running XSS detection for $domain..."
    cat $base_path/url/valid_urls.txt | Gxss -o $base_path/xss/gxss.txt
    cat $base_path/xss/gxss.txt | dalfox pipe | tee $base_path/xss/dalfox_xss.txt
    if [ -s $base_path/xss/dalfox_xss.txt ]; then
        msg="[XSS Vulnerabilities] Found for $domain: $base_path/xss/dalfox_xss.txt"
        echo "$msg" >> $report_path
        send_telegram_message "$msg"
    fi

    echo "[*] Running SQL injection checks for $domain..."
    sqlmap -m $base_path/url/valid_urls.txt --batch --risk 3 --level 3 --threads 5 --tamper=randomcase,space2comment,appendnullbyte --random-agent | tee -a $base_path/sql/sqlmap_sql_url.txt
    if grep -q -i "is vulnerable" $base_path/sql/sqlmap_sql_url.txt || grep -q -i "found" $base_path/sql/sqlmap_sql_url.txt; then
        msg="[SQL Injection] Vulnerability found for $domain: $base_path/sql/sqlmap_sql_url.txt"
        echo "$msg" >> $report_path
        send_telegram_message "$msg"
    else
        echo "[SQL Injection] No vulnerabilities found for $domain" >> $report_path
    fi

    echo "[*] Checking for Cloudflare-protected domains for $domain..."
    cf-check -d $base_path/subdomain/good/active_subdomain.txt | tee -a $base_path/subdomain/good/cloudflare_check.txt
    if [ -s $base_path/subdomain/good/cloudflare_check.txt ]; then
        msg="[Cloudflare Protection] Found for $domain: $base_path/subdomain/good/cloudflare_check.txt"
        echo "$msg" >> $report_path
        send_telegram_message "$msg"
    fi

    echo "Finished processing $domain!"
}

if [ ! -f "$host" ]; then
    echo "Error: Host file not found!"
    exit 1
fi

for domain in $(cat $host); do
    process_domain $domain
done

# Summary report
echo "\nVulnerability Scan Completed. Check detailed results at $report_path."
send_telegram_message "Vulnerability Scan Completed. Check detailed results at $report_path."
