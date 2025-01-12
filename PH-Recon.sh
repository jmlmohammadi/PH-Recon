#!/bin/bash

host=$1
wordlist="/root/wordlist/SecLists/Discovery/DNS/dns-Jhaddix.txt"
resolver="/root/PH-Recon/resolvers.txt"

process_domain() {
    domain=$1
    base_path="/root/PH-Recon/$domain"

    echo "Processing domain: $domain"

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

    echo "[*] Scanning open ports for $domain..."
    naabu -list $base_path/subdomain/good/active_subdomain.txt -top-ports 1000 -exclude-ports 80,443,21,22,25 -o $base_path/scan/open-port.txt
    naabu -list $base_path/subdomain/good/active_subdomain.txt -p - -exclude-ports 80,443,21,22,25 -o $base_path/scan/filter-all-open-port.txt

    echo "[*] Taking web screenshots for $domain..."
    httpx -l $base_path/subdomain/good/active_subdomain.txt

    echo "[*] Checking for Cloudflare-protected domains for $domain..."
    cf-check -d $base_path/subdomain/good/active_subdomain.txt | tee -a $base_path/subdomain/good/cloudflare_check.txt

    echo "[*] Running vulnerability scans for $domain..."
    nuclei -l $base_path/subdomain/good/active_subdomain.txt -t /root/nuclei-templates/ -c 50 -o $base_path/scan/new-nuclei/All.txt -v
    jaeles scan -c 50 -s /root/templates/jaeles-signatures -U $base_path/subdomain/good/active_subdomain.txt -o $base_path/scan/jaeles/ -v

    echo "[*] Discovering URLs for $domain..."
    cat $base_path/subdomain/good/active_subdomain.txt | gauplus -t 40 | tee -a $base_path/url/gaplus-urls.txt
    cat $base_path/subdomain/good/active_subdomain.txt | waybackurls | tee $base_path/url/waybackurls.txt
    cat $base_path/subdomain/good/active_subdomain.txt | hakrawler | tee -a $base_path/url/hakrawler-urls.txt
    gospider -S $base_path/subdomain/good/active_subdomain.txt -c 10 -d 1 --other-source | grep -o 'https\?://[^ ]\+' > $base_path/url/gospider-url.txt
    cat $base_path/subdomain/good/active_subdomain.txt | xargs -n 1 -I {} python3 /root/OK-VPS/tools/ParamSpider/paramspider.py --domain {} --level high  | grep -o 'https\?://[^ ]\+' > $base_path/url/all_spiderparamters.txt
    cd $base_path/url && ./web_archive_urls.sh $base_path/subdomain/good/active_subdomain.txt
    cat $base_path/url/*.txt > $base_path/url/all-url.txt
    cat $base_path/url/all-url.txt | sort --unique | grep '\?.*=' | grep $domain | uro | tee $base_path/url/final-url.txt
    cat $base_path/url/final-url.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.svg|\.css|\.ico" | sed 's/:88//g;s/:443//g' | sort -u > $base_path/url/valid_urls.txt

    echo "[*] Extracting URL endpoints for $domain..."
    cat $base_path/url/final-url.txt | cut -d "/" -f4- >> $base_path/url/url_endpoints.txt

    echo "[*] Applying GF patterns for $domain..."
    gf xss $base_path/url/valid_urls.txt | tee $base_path/gf/xss.txt
    gf my-lfi $base_path/url/valid_urls.txt | tee $base_path/gf/my-lfi.txt
    gf sqli $base_path/url/valid_urls.txt | tee $base_path/gf/sqli.txt
    gf lfi $base_path/url/valid_urls.txt |  tee $base_path/gf/lfi.txt
    gf redirect $base_path/url/valid_urls.txt |  tee $base_path/gf/rmy-lfiedirect.txt
    gf aws-keys $base_path/url/valid_urls.txt |  tee $base_path/gf/aws-keys-json.txt
    gf interestingsubs $base_path/subdomain/good/active_subdomain.txt |  tee $base_path/gf/interestingsubs.txt
    gf s3-buckets $base_path/url/valid_urls.txt |  tee $base_path/gf/s3-buckets.txt
    gf servers $base_path/url/valid_urls.txt |  tee $base_path/gf/servers.txt
    gf debug-pages $base_path/url/valid_urls.txt |  tee $base_path/gf/debug-pages.txt
    gf debug_logic $base_path/url/valid_urls.txt |  tee $base_path/gf/debug_logic.txt
    gf img-traversal $base_path/url/valid_urls.txt |  tee $base_path/gf/img-traversal.txt
    gf php-sources $base_path/url/valid_urls.txt |  tee $base_path/gf/php-sources.txt
    gf upload-fields $base_path/url/valid_urls.txt |  tee $base_path/gf/upload-fields.txt
    gf php-errors $base_path/url/valid_urls.txt |  tee $base_path/gf/php-errors.txt
    gf http-auth $base_path/url/valid_urls.txt |  tee $base_path/gf/http-auth.txt
    gf idor $base_path/url/valid_urls.txt |  tee $base_path/gf/idor.txt
    gf interestingparams $base_path/url/valid_urls.txt |  tee $base_path/gf/interestingparams.txt
    gf interestingEXT $base_path/url/valid_urls.txt |  tee $base_path/gf/interestingEXT.txt
    gf rce $base_path/url/valid_urls.txt |  tee $base_path/gf/rce.txt

    echo "[*] Running SQL injection checks for $domain..."
    mrco24-error-sql -f $base_path/url/valid_urls.txt -t 40 -o $base_path/sql/error-sql-injection.txt -v
    sqlmap -m $base_path/url/valid_urls.txt --batch --risk 3 --level 3 --threads 5 --tamper=randomcase,space2comment,appendnullbyte --random-agent | tee -a $base_path/sql/sqlmap_sql_url.txt

    echo "[*] Running XSS detection for $domain..."
    cat $base_path/url/valid_urls.txt | Gxss -o $base_path/xss/gxss.txt
    cat $base_path/url/valid_urls.txt | kxss | tee -a  $base_path/xss/kxss_url.txt
    cat $base_path/xss/kxss_url.txt | sed 's/.*on//' | sed 's/=.*/=/' > $base_path/xss/kxss_url_active.txt
    cat $base_path/xss/kxss_url_active.txt | dalfox pipe | tee $base_path/xss/kxss_dalfoxss.txt
    cat $base_path/xss/gxss.txt | dalfox pipe | tee $base_path/xss/gxss_dalfoxss.txt
    cat $base_path/subdomain/good/active_subdomain.txt | /root/OK-VPS/tools/findom-xss/./findom-xss.sh

    echo "[*] Running directory traversal for $domain..."
    mrco24-lfi -f $base_path/url/valid_urls.txt -p /root/wordlist/mrco24-wordlist/lfi_payloads.txt -t 50 -o $base_path/scan/lfi.txt

    echo "[*] Running Blind XSS checks for $domain..."
    nuclei -l $base_path/url/valid_urls.txt -t /root/templates/Best-Mrco24/header_blind_xss.yaml -c 100 -o $base_path/xss/header_blind_xss.txt -v

    echo "[*] Fuzzing endpoints for $domain..."
    dirsearch -l $base_path/subdomain/good/active_subdomain.txt -w $base_path/url/url_endpoints.txt -i 200,301,302 | tee -a $base_path/dri/Endpoint_Dir.txt

    echo "[*] Fuzzing active directories for $domain..."
    dirsearch -l $base_path/subdomain/good/active_subdomain.txt > $base_path/dri/dri_activ.txt

    echo "Finished processing $domain!"
}

if [ ! -f "$host" ]; then
    echo "Error: Host file not found!"
    exit 1
fi

for domain in $(cat $host); do
    process_domain $domain
done
