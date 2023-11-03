#!/bin/bash

# Author: Manuel Lopez Torrecillas aka Loop-Man (https://github.com/Loop-Man)
# Objective: Search for the ip hidden by CDNs or WAFs

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

# Source the Global Configuration with variables and API keys
. global.conf
. API.conf


if [ ! "$VIRUSTOTAL_API_ID" ] || [ ! "$CENSYS_API_ID" ] || [ ! "$CENSYS_API_SECRET" ]; then
	echo -e "\n${redColour}[!] You must enter your VirusTotal and Censys API \
Key into the code${endColour}\n"
	exit 1
fi

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT


function ctrl_c(){
    echo -e "\n\n${yellowColour}[*]${endColour}${grayColour} Exiting in a \
controlled way${endColour}\n"
    exit 0
}


function banner(){

    echo -e "\n${yellowColour}    __         __    _           __________         __________  _   __";
    echo -e "   / /_  ___  / /_  (_)___  ____/ /_  __/ /_  ___  / ____/ __ \/ | / /";
    echo -e "  / __ \/ _ \/ __ \/ / __ \/ __  / / / / __ \/ _ \/ /   / / / /  |/ / ";
    echo -e " / /_/ /  __/ / / / / / / / /_/ / / / / / / /  __/ /___/ /_/ / /|  /  ";
    echo -e "/_.___/\___/_/ /_/_/_/ /_/\__,_/ /_/ /_/ /_/\___/\____/_____/_/ |_/   ";
    echo -e "                                                                      ${endColour}\n";

}

function helpPanel(){
    echo -e "\n Usage: $0 -d DOMAIN \n"
    echo -e "\t -d DOMAIN: Search by DNS history"
    echo -e "\t -i: Search by DNS history, ssl certificate, subdomains"
    echo -e "\t -c: Search by Censys API"
    echo -e "\t -f FILE: search by DNS history on every domain in the file"
    echo -e "\t -h: Print this message"
}

virustotal_AS_owner(){

    local IP="$1"
    curl --retry 3 -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/ip_addresses/$IP" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "$LOCATION/$DOMAIN/.logs/${IP}_virustotal_report.json"
    jq -r '.data.attributes.as_owner' "$LOCATION/$DOMAIN/.logs/${IP}_virustotal_report.json" \
        > "$LOCATION/$DOMAIN/.logs/${IP}_virustotal_AS_owner.txt"
    cat "$LOCATION/$DOMAIN/.logs/${IP}_virustotal_AS_owner.txt"
}

get_dns_a_records() {

    RESOLVER="8.8.8.8"
    echo -e "\n${yellowColour}[*]${endColour}${grayColour} DNS A records of the \
$DOMAIN${endColour}\n"
    dns_a_records=($(dig +short A "$DOMAIN" @"$RESOLVER"))
    for dns_a in "${dns_a_records[@]}"; do
        echo "$dns_a"
    done
}

get_dns_a_records_and_AS_owner() {

    RESOLVER="8.8.8.8"
    echo -e "\n${yellowColour}[*]${endColour}${grayColour} DNS A records of the \
$DOMAIN with owner of the Autonomous System ${endColour}\n"
    dns_a_records=($(dig +short A "$DOMAIN" @"$RESOLVER"))
    for dns_a in "${dns_a_records[@]}"; do
        echo "$dns_a Autonomous System owner: $(virustotal_AS_owner $dns_a)"
    done
}


virustotal_dns_history() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} History of DNS \
resolutions for the $DOMAIN${endColour}\n"
   # echo "DOMAIN: $DOMAIN"
   # echo "LOCATION: $LOCATION"
    curl --retry 3 -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/resolutions?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "$LOCATION/$DOMAIN/virustotal_resolutions.json"
    jq -r '.data[].attributes.ip_address' "${LOCATION}/${DOMAIN}/virustotal_resolutions.json" \
        > "$LOCATION/$DOMAIN/IP.txt"
    cat "${LOCATION}/${DOMAIN}/IP.txt" | sort
}

virustotal_dns_history_intensive() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Intensive collect \
DNS resolutions history for $DOMAIN${endColour}\n"
    curl --retry 3 -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/resolutions?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_resolutions.json"
    jq -r '.data[].attributes.ip_address' "${LOCATION}/${DOMAIN}/virustotal_resolutions.json" \
        > "${LOCATION}/${DOMAIN}/IP.txt"
    jq -r '.links.next' "${LOCATION}/${DOMAIN}/virustotal_resolutions.json" \
        > "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"

    while [ -s "${LOCATION}/${DOMAIN}/virustotal_url_next.txt" ]; do
        curl --retry 3 -s -m 5 -k --request GET --url "$(cat "${LOCATION}/${DOMAIN}/virustotal_url_next.txt")" \
            --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_resolutions_temp.json"
        jq -r '.links.next' "${LOCATION}/${DOMAIN}/virustotal_resolutions_temp.json" \
            > "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"
        jq -r '.data[].attributes.ip_address' "${LOCATION}/${DOMAIN}/virustotal_resolutions_temp.json" \
            >> "${LOCATION}/${DOMAIN}/IP.txt"

        # Combine JSON files
        jq -s '.[0].data + .[1].data | {data: .}' "${LOCATION}/${DOMAIN}/virustotal_resolutions.json" \
            "${LOCATION}/${DOMAIN}/virustotal_resolutions_temp.json" > "${LOCATION}/${DOMAIN}/virustotal_resolutions_combined.json"
        mv "${LOCATION}/${DOMAIN}/virustotal_resolutions_combined.json" \
            "${LOCATION}/${DOMAIN}/virustotal_resolutions.json"
    done
    rm -rf "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"
    rm -rf "${LOCATION}/${DOMAIN}/virustotal_resolutions_temp.json"
    cat "${LOCATION}/${DOMAIN}/IP.txt" | sort
}

virustotal_certificates_history() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Fingerprint sha256 of \
ssl certificates history in virustotal${endColour}\n"
    curl --retry 3 -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/historical_ssl_certificates?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json"
    jq -r '.data[].attributes.thumbprint_sha256' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json" \
        > "${LOCATION}/${DOMAIN}/sha256_certificates.txt"
    cat "${LOCATION}/${DOMAIN}/sha256_certificates.txt"
}

virustotal_certificates_history_intensive() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Fingerprint sha256 of \
ssl certificates history in virustotal${endColour}\n"
    curl --retry 3 -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/historical_ssl_certificates?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json"
    jq -r '.links.next' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json" \
        > "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"
    jq -r '.data[].attributes.thumbprint_sha256' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json" \
        > "${LOCATION}/${DOMAIN}/sha256_certificates.txt"

    while [ -s "${LOCATION}/${DOMAIN}/virustotal_url_next.txt" ]; do
        curl --retry 3 -s -m 5 -k --request GET --url "$(cat "${LOCATION}/${DOMAIN}/virustotal_url_next.txt")" \
            --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates_temp.json"
        jq -r '.links.next' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates_temp.json" \
            > "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"
        jq -r '.data[].attributes.thumbprint_sha256' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates_temp.json" \
            >> "${LOCATION}/${DOMAIN}/sha256_certificates.txt"

        # Combine JSON files
        jq -s '.[0].data + .[1].data | {data: .}' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json" \
            "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates_temp.json" \
            > "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates_combined.json"
        mv "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates_combined.json" \
            "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json"
    done
    rm -rf "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"
    rm -rf "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates_temp.json"
    cat "${LOCATION}/${DOMAIN}/sha256_certificates.txt"
}

virustotal_search_IP_by_certificates(){

    echo "test"

}

virustotal_search_IP_by_subdomains(){

    echo "test"

}


censys_search_IP_by_certificates() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Fingerprint sha256 of \
ssl certificates history in censys${endColour}\n"
    curl --retry 3 -s -X GET -H "Content-Type: application/json" -H "Host: $CENSYS_DOMAIN_API" \
        -H "Referer: $CENSYS_URL_API" -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
        --url "$CENSYS_URL_API/v2/certificates/search?q=$DOMAIN" \
        | jq -r '.result.hits | .[].fingerprint_sha256' \
        > "${LOCATION}/${DOMAIN}/sha256_certificates.txt"

    if [ -z "$(cat "${LOCATION}/${DOMAIN}/sha256_certificates.txt")" ]; then
        echo -e "\n${redColour}[*]No certificates found in censys${endColour}\n"
    else
        for sha256 in $(cat "${LOCATION}/${DOMAIN}/sha256_certificates.txt" \
            | sort | uniq); do
            curl --retry 3 -s -X GET -H "Content-Type: application/json" \
                -H "Host: $CENSYS_DOMAIN_API" -H "Referer: $CENSYS_URL_API" \
                -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
                --url "$CENSYS_URL_API/v2/hosts/search?q=services.tls.certificates.leaf_data.\
                fingerprint%3A+$sha256+or+services.tls.certificates.chain.fingerprint%3A+$sha256" \
                | jq -r '.result.hits | .[].ip' >> "${LOCATION}/${DOMAIN}/IP.txt"
        done
        if [ -z "$(cat "${LOCATION}/${DOMAIN}/IP.txt")" ]; then
            echo -e "\n${redColour}[*]No IP found in censys for the certificates${endColour}\n"
        else
            cat "${LOCATION}/${DOMAIN}/IP.txt"
        fi
    fi
}

validation_lines_http() {
    
    if [ ! -s "$LOCATION/$DOMAIN/IP.txt" ]; then
        echo -e "\n${redColour}[*]${endColour}${grayColour}The list of IP to validate is empty${endColour}\n"
        return 1
    fi
    local OUTPUT_DIR="$LOCATION/$DOMAIN/validation_http"

    if [ ! -d "$OUTPUT_DIR" ];then
        mkdir -p "$OUTPUT_DIR"
    fi

    local real_validation_http=$(curl --retry 3 -L -s -m 10 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
        -H "$CONNECTION_HEADER" http://$DOMAIN \
        | tee "$OUTPUT_DIR/real_validation_http.html")

    
    # Check if the request is empty
    
    if [ -z "$real_validation_http" ]; then
        echo -e "\n${redColour}[*]${endColour}${grayColour}HTTP validation failed (Empty original request)${endColour}\n"
        return 1
    fi


    echo -e "\n${yellowColour}[*]${endColour}${grayColour} IP validation per line in HTTP${endColour}\n"

    for testIP in $(cat "$LOCATION/$DOMAIN/IP.txt" | sort | uniq);
    do
        local test_validation_http=$(curl --retry 1 -L -s -m 1 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
            -H "$CONNECTION_HEADER" --resolve *:80:$testIP http://$DOMAIN \
            | tee "$OUTPUT_DIR/test_validation_http_$testIP.html")

        if [ -z "$test_validation_http" ]; then
            echo "$testIP Percentage: 0%"
            continue
        fi

        # Extract the title from the real validation
        title1=$(grep -oP '(?<=<title>).*?(?=</title>)' "$OUTPUT_DIR/real_validation_http.html")

        # Extract the title from the current test validatin
        title2=$(grep -oP '(?<=<title>).*?(?=</title>)' "$OUTPUT_DIR/test_validation_http_$testIP.html")

        # Check that both titles are not empty and the first title is contained in the second
        if [[ -n "$title1" && -n "$title2" ]]; then
            if [[ "$title2" == *"$title1"* ]]; then
                echo "$testIP Percentage: 100%"
                echo "$testIP" >> "$LOCATION/$DOMAIN/IP_validate.tmp"
                continue
            fi
        fi
        

        local difference=$(diff -U 0 <(echo "$real_validation_http") <(echo "$test_validation_http") | grep -a -v ^@ | wc -l) 2> /dev/null
        local lines=$(echo -e "$real_validation_http\n$test_validation_http" | wc -l) 2> /dev/null

        # Check if $lines is 0 and continue with the next iteration.
        if [ "$lines" -eq 0 ]; then
            echo "$testIP Percentage: Not Applicable%"
            continue
        fi
        local percent=$(((lines-difference)*100/lines))
        local percent=$(( percent < 0 ? 0 : percent )) # Ensure that the percentage is not negative, and if it is put 0%
        echo "$testIP Percentage: $percent%"
        if (( $percent > 75 )); then
            echo $testIP >> "$LOCATION/$DOMAIN/IP_validate.tmp"
        fi
    done
    # DEBUG
    #rm -rf "$OUTPUT_DIR/real_validation_http.html" "$OUTPUT_DIR/test_validation_http_*"
}

validation_lines_https() {
    
    if [ ! -s "$LOCATION/$DOMAIN/IP.txt" ]; then
        echo -e "\n${redColour}[*]${endColour}${grayColour}The list of IP to validate is empty${endColour}\n"
        return 1
    fi
    local OUTPUT_DIR="$LOCATION/$DOMAIN/validation_https"

    if [ ! -d "$OUTPUT_DIR" ];then
        mkdir -p "$OUTPUT_DIR"
    fi

    local real_validation_https=$(curl --retry 3 -L -s -m 10 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
        -H "$CONNECTION_HEADER" https://$DOMAIN \
        | tee "$OUTPUT_DIR/real_validation_https.html")

    
    # Check if the request is empty
    
    if [ -z "$real_validation_https" ]; then
        echo -e "\n${redColour}[*]${endColour}${grayColour}HTTPS validation failed (Empty original request)${endColour}\n"
        return 1
    fi


    echo -e "\n${yellowColour}[*]${endColour}${grayColour} IP validation per line in HTTPS${endColour}\n"

    for testIP in $(cat "$LOCATION/$DOMAIN/IP.txt" | sort | uniq);
    do
        local test_validation_https=$(curl --retry 1 -L -s -m 1 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
            -H "$CONNECTION_HEADER" --resolve *:443:$testIP https://$DOMAIN \
            | tee "$OUTPUT_DIR/test_validation_https_$testIP.html")

        if [ -z "$test_validation_https" ]; then
            echo "$testIP Percentage: 0%"
            continue
        fi

        # Extract the title from the real validation
        title1=$(grep -oP '(?<=<title>).*?(?=</title>)' "$OUTPUT_DIR/real_validation_https.html")

        # Extract the title from the current test validatin
        title2=$(grep -oP '(?<=<title>).*?(?=</title>)' "$OUTPUT_DIR/test_validation_https_$testIP.html")

        # Check that both titles are not empty and the first title is contained in the second
        if [[ -n "$title1" && -n "$title2" ]]; then
            if [[ "$title2" == *"$title1"* ]]; then
                echo "$testIP Percentage: 100%"
                echo "$testIP" >> "$LOCATION/$DOMAIN/IP_validate.tmp"
                continue
            fi
        fi

        local difference=$(diff -U 0 <(echo "$real_validation_https") <(echo "$test_validation_https") | grep -a -v ^@ | wc -l) 2> /dev/null
        local lines=$(echo -e "$real_validation_https\n$test_validation_https" | wc -l) 2> /dev/null

        # Check if $lines is 0 and continue with the next iteration.
        if [ "$lines" -eq 0 ]; then
            echo "$testIP Percentage: Not Applicable%"
            continue
        fi
        local percent=$(((lines-difference)*100/lines))
        local percent=$(( percent < 0 ? 0 : percent )) # Ensure that the percentage is not negative, and if it is put 0%
        echo "$testIP Percentage: $percent%"
        if (( $percent > 75 )); then
            echo $testIP >> "$LOCATION/$DOMAIN/IP_validate.tmp"
        fi
    done
    # DEBUG
    #rm -rf "$OUTPUT_DIR/real_validation_https.html" "$OUTPUT_DIR/test_validation_https_*"
}

read_and_normalize_html() {
    local file_path=$1
    local text

    # Extracting text from HTML tags and normalising it
    text=$(xmllint --html --xpath "//text()" "$file_path" 2>/dev/null | tr '[:upper:]' '[:lower:]' | awk '{$1=$1};1')

    echo "$text"
}

similarity_percentage() {
    local text1=$1
    local text2=$2

    local words1=$(echo "$text1" | tr ' ' '\n')
    local words2=$(echo "$text2" | tr ' ' '\n')

    local common_words=$(echo -e "$words1\n$words2" | sort | uniq -d | wc -l)
    local total_words=$(echo -e "$words1\n$words2" | sort | uniq | wc -l)

    local similarity=$(awk -v c=$common_words -v t=$total_words 'BEGIN { print (c / t) * 100 }')
    local integer_similarity=$(printf "%.0f" "$similarity")
    echo "$integer_similarity"
}

validation_content_http() {

    if [ ! -s "$LOCATION/$DOMAIN/IP.txt" ]; then
        echo -e "\n${redColour}[*]${endColour}${grayColour}The list of IP to validate is empty${endColour}\n"
        return 1
    fi
    local INPUT_DIR="$LOCATION/$DOMAIN/validation_http"

    if [ ! -d "$INPUT_DIR" ];then
        echo -e "\n${redColour}[*]${endColour}${grayColour}HTTP validation failed (Empty original request)${endColour}\n"
        return 1
    fi

    local text1=$(read_and_normalize_html "$INPUT_DIR/real_validation_http.html" | tee "$INPUT_DIR/real_normalize_http.txt")
    
    echo -e "\n${yellowColour}[*]${endColour}${grayColour} IP validation by HTLM content in HTTP${endColour}\n"

    for file in "$INPUT_DIR"/test_validation_http_*.html
    do
        if [ -f "$file" ]; then
            # Extrae la IP del nombre del archivo
            filename=$(basename "$file")  # Obtiene solo el nombre del archivo, sin la ruta
            local testIP=$(echo $filename | sed -E 's/test_validation_http_([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.html/\1/')
            local text2=$(read_and_normalize_html "$INPUT_DIR/$filename" | tee "$INPUT_DIR/test_normalize_http_$testIP.txt")

            local similarity=$(similarity_percentage "$text1" "$text2")
            if [[ $similarity -gt 75 ]]; then
                echo $testIP >> "$LOCATION/$DOMAIN/IP_validate.tmp"
            fi
            echo "$testIP Similarity HTML content: $similarity%"

        fi
    done

    #DEBUG
    #rm -rf "$INPUT_DIR/real_normalize_http.txt" "$INPUT_DIR/test_normalize_http_*"
}

validation_content_https() {

    if [ ! -s "$LOCATION/$DOMAIN/IP.txt" ]; then
        echo -e "\n${redColour}[*]${endColour}${grayColour}The list of IP to validate is empty${endColour}\n"
        return 1
    fi
    local INPUT_DIR="$LOCATION/$DOMAIN/validation_https"

    if [ ! -d "$INPUT_DIR" ];then
        echo -e "\n${redColour}[*]${endColour}${grayColour}HTTPS validation failed (Empty original request)${endColour}\n"
        return 1
    fi

    local text1=$(read_and_normalize_html "$INPUT_DIR/real_validation_https.html" | tee "$INPUT_DIR/real_normalize_https.txt")
    
    echo -e "\n${yellowColour}[*]${endColour}${grayColour} IP validation by HTLM content in HTTPS${endColour}\n"

    for file in "$INPUT_DIR"/test_validation_https_*.html
    do
        if [ -f "$file" ]; then
            # Extrae la IP del nombre del archivo
            filename=$(basename "$file")  # Obtiene solo el nombre del archivo, sin la ruta
            local testIP=$(echo $filename | sed -E 's/test_validation_https_([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.html/\1/')
            local text2=$(read_and_normalize_html "$INPUT_DIR/$filename" | tee "$INPUT_DIR/test_normalize_https_$testIP.txt")

            local similarity=$(similarity_percentage "$text1" "$text2")
            if [[ $similarity -gt 75 ]]; then
                echo $testIP >> "$LOCATION/$DOMAIN/IP_validate.tmp"
            fi
            echo "$testIP Similarity HTML content: $similarity%"

        fi
    done

    #DEBUG
    #rm -rf "$INPUT_DIR/real_normalize_https.txt" "$INPUT_DIR/test_normalize_https_*"
}

sort_and_uniq_IP_file(){

    if [ -s "$LOCATION/$DOMAIN/IP_validate.tmp" ]; then 
        cat "$LOCATION/$DOMAIN/IP_validate.tmp" | sort | uniq > "$LOCATION/$DOMAIN/IP_validate.txt"
        #DEBUG 
        rm -rf "$LOCATION/$DOMAIN/IP_validate.tmp"
    fi
} 

remove_ips_from_file() {
    
    local file=$1
    if [ -s "$file" ]; then
        for ip_to_delete in "${dns_a_records[@]}"; do
            # Remove the IP from the file if it is in the file
            sed -i "/^$ip_to_delete$/d" "$file"
        done
    fi
}

show_validated_ip(){

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Valid IP set${endColour}\n"
    if [ -s "$LOCATION/$DOMAIN/IP_validate.txt" ]; then
        cat "$LOCATION/$DOMAIN/IP_validate.txt"
    else
        echo -e "\n${redColour}[*]${endColour}${grayColour}The validated IP list is empty${endColour}\n"
        #exit 1
    fi
} 

show_validated_ip_and_AS_owner(){

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Valid IP set with \
owner of the Autonomous System to which the IP belongs${endColour}\n"

    if [ -s "$LOCATION/$DOMAIN/IP_validate.txt" ]; then

        for IP_with_AS_owner in $(cat "$LOCATION/$DOMAIN/IP_validate.txt"); do
            echo "$IP_with_AS_owner Autonomous System owner: $(virustotal_AS_owner $IP_with_AS_owner)"
        done
    else
        echo -e "\n${redColour}[*]${endColour}${grayColour}The validated IP list is empty${endColour}\n"
        #exit 1
    fi
} 

cdn_validation_by_PTR_register(){

    # List of the names of the 20 most popular CDNs
    local IP=$1

    # Perform a PTR lookup to get the associated host name
    local hostname=$(dig +short -x "$IP")

    # Check if the host name contains the name of a known CDN
    local is_cdn=false
    for cdn in "${cdns[@]}"; do
        if [[ $hostname == *"$cdn"* ]]; then
            is_cdn=true
            echo "$IP CDN detected: $cdn"
            break
        fi
    done

}

cdn_validation_by_whois(){

    # List of the names of the 20 most popular CDNs
    local IP=$1

    # Perform a PTR lookup to get the associated host name
    local whois=$(whois "$IP")

    # Check if the host name contains the name of a known CDN
    local is_cdn=false
    for cdn in "${cdns[@]}"; do
        if [[ $whois == *"$cdn"* ]]; then
            is_cdn=true
            echo "$IP CDN detected: $cdn"
            break
        fi
    done

} 

cdn_validation_by_headers_and_cookies_name(){

    local IP=$1
    declare -A cdn_patterns
    cdn_patterns=(
        ["akamai"]="AKAMAICDN|AKAMAIEDGESERVERID|Server: AkamaiGHost|X-Akamai-Edgescape|X-Akamai-Request-ID"
        ["cloudfront"]="AWSALB|AWSALBCORS|Server: CloudFront|X-Amz-Cf-"
        ["cloudflare"]="__cfduid|__cfruid|Server: cloudflare|CF-RAY|cf-cache-status|CF-Cache-Status|CF-Connecting-IP"
        ["fastly"]="_fastly_session|X-Fastly-Request-ID"
        ["imperva"]="incap_ses_|visid_incap_|X-CDN: Imperva|Imperva"
        ["keycdn"]="X-Edge-Location|Server: keycdn-engine|X-Edge-IP"
        ["sucuri"]="sucuri_cloudproxy_uuid_|X-Sucuri-ID|X-Sucuri-Cache"
        ["stackpath"]="Server: StackPath"
        ["limelight"]="Server: LLNW|X-Limelight-Edge-IP|X-Limelight-Edge-Hostname"
        ["azureedge"]="Server: AzureEdge|X-Azure-Ref"
        ["googleusercontent"]="Server: UploadServer|X-GUploader-UploadID|X-Goog-Upload-Status"
        ["rackspace"]="X-Cache-Hits"
        ["cachefly"]="Server: Flywheel|X-FLY-Region"
        ["cdn77"]="Server: CDN77"
        ["cdnetworks"]="Server: CDNetworks|X-Daa-Tunnel|X-CDN"
        ["leaseweb"]="Server: LeaseWeb CDN"
        ["bunnycdn"]="Server: BunnyCDN|X-Bunny-Server|X-Bunny-Cache"
        ["gcorelabs"]="Server: G-Core Labs|X-GCore-RequestID|X-GCore-Server"
        ["quantil"]="Server: QUANTIL|X-CDN-Geo|X-CDN-Origin"
        ["belugacdn"]="Server: BelugaCDN|X-Beluga-Server|X-Beluga-Request-ID"
        ["cdnvideo"]="Server: CDNvideo|X-CDN-Location"
        ["highwinds"]="Server: Highwinds"
        ["chinacache"]="Server: ChinaCache|X-CC-Distributed"
        ["edgecast"]="Server: ECD"
        ["aryaka"]="Server: Aryaka|X-Aryaka-Edge-Server"
        ["onapp"]="Server: OnApp"
        ["cachenetworks"]="Server: CacheNetworks|X-CacheNetworks"
        ["metacdn"]="Server: MetaCDN|X-MetaCDN"
        ["ngenix"]="Server: NGENIX"
        ["section.io"]="Server: section.io|X-Section-Id"
        ["spacecdn"]="Server: SpaceCDN"
    )

# Get http headers
    headers=$(curl --retry 3 -L -sI -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" \
        -H "$ACCEPT_LANGUAGE" -H "$CONNECTION_HEADER" --resolve *:443:$IP https://$DOMAIN)

    # Detect CDN
    detected_cdn=""
    for cdn in "${!cdn_patterns[@]}"; do
        pattern=${cdn_patterns[$cdn]}
        if echo "$headers" | grep -iqE "$pattern"; then
            detected_cdn=$cdn
            break
        fi
    done

    # Print the result
    if [ -n "$detected_cdn" ]; then
        echo "$IP CDN detected: $detected_cdn"
    else
        echo -e "${greenColour}[!] $IP Potential CDN bypass${endColour}\n"
        echo "$IP" >> $results_file
    fi

}

cdn_validation(){

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Looking up the CDN${endColour}\n"
    if [ -s "$LOCATION/$DOMAIN/IP_validate.txt" ]; then  
        for cdn_search in $(cat "$LOCATION/$DOMAIN/IP_validate.txt"); do
            
            local cdn_validation_PTR=$(cdn_validation_by_PTR_register $cdn_search)
            if [[ -z "${cdn_validation_PTR}" ]]; then
                local cdn_validation_whois=$(cdn_validation_by_whois $cdn_search)
                if [[ -z "${cdn_validation_whois}" ]]; then
                    local cdn_headers_validation=$(cdn_validation_by_headers_and_cookies_name $cdn_search)
                    echo "$cdn_headers_validation"
                else
                    echo "$cdn_validation_whois"
                fi
            else
                echo "$cdn_validation_PTR"
            fi
        done
    else
        echo -e "\n${redColour}[*]${endColour}${grayColour}The validated IP list is empty${endColour}\n"
    fi
}


flag_domain() {
    DOMAIN="$1"
    LOCATION="$2"

    banner
    get_dns_a_records
    virustotal_dns_history
    validation_lines_http
    validation_lines_https
    validation_content_http
    validation_content_https
    sort_and_uniq_IP_file
    remove_ips_from_file "$LOCATION/$DOMAIN/IP_validate.txt"
    show_validated_ip
    cdn_validation
}

flag_intensive() {
    DOMAIN="$1"
    LOCATION="$2"

    banner
    get_dns_a_records_and_AS_owner
    virustotal_dns_history_intensive
    virustotal_certificates_history_intensive
    validation_lines_http  
    validation_lines_https
    validation_content_http
    validation_content_https
    sort_and_uniq_IP_file
    remove_ips_from_file "$LOCATION/$DOMAIN/IP_validate.txt"
    show_validated_ip_and_AS_owner
    cdn_validation
}

flag_censys(){
    DOMAIN="$1"
    LOCATION="$2"

    banner
    get_dns_a_records
    virustotal_dns_history
    virustotal_certificates_history
    censys_search_IP_by_certificates
    validation_lines_http
    validation_lines_https
    validation_content_http
    validation_content_https
    sort_and_uniq_IP_file
    remove_ips_from_file "$LOCATION/$DOMAIN/IP_validate.txt"
    show_validated_ip
    cdn_validation
}

flag_all(){
    DOMAIN="$1"
    LOCATION="$2"

    banner
    get_dns_a_records_and_AS_owner
    virustotal_dns_history_intensive
    virustotal_certificates_history_intensive
    censys_search_IP_by_certificates
    validation_lines_http
    validation_lines_https
    validation_content_http
    validation_content_https
    sort_and_uniq_IP_file
    remove_ips_from_file "$LOCATION/$DOMAIN/IP_validate.txt"
    show_validated_ip_and_AS_owner
    cdn_validation
} 

DOMAIN=''
FLAG_INTENSIVE=false
FLAG_CENSYS=false
VERBOSE=0

while getopts ':d:icf:h?' option
do
    case "${option}"
        in
        d) DOMAIN=${OPTARG};;
        i) FLAG_INTENSIVE=true;;
        c) FLAG_CENSYS=true;;
        f) DOM_FILE=${OPTARG};;
        v) VERBOSE=1;;
        h|?) banner ; helpPanel ; exit 0;;
        *) banner ; echo -e "\nUnknown flag: -$OPTARG\n" 1>&2 ; usage;;
    esac
done

# Process domain
if [ -z "$DOMAIN" ] && [ -z "$DOM_FILE" ] ; then
    echo "No domain(-d) or file(-f) argument supplied"
	banner ; helpPanel
	exit 1
fi

# Main function to execute the search
function main_logic(){

    # File to store the results
    timestamp="$(date +%F)"
    if [ ! -d results ]; then
        mkdir results
    fi
    results_file="results/results-$timestamp-$DOMAIN.txt"

    # Store the domain in the results file
    echo "Potential CDN Bypass for: $DOMAIN" >> $results_file

    TOPDOMAIN=$(echo $DOMAIN | awk -F'.' '{print $(NF-1)"."$NF}')
    if [ ! -d scans ]; then
        mkdir scans
    fi
    LOCATION="$(pwd)/scans"
    SCAN_PATH="scans"

    if [ ! -d "$LOCATION/$DOMAIN" ];then
        mkdir "$SCAN_PATH/$DOMAIN"
    fi
    if [ ! -d "$LOCATION/$DOMAIN/.logs" ];then
        mkdir "$SCAN_PATH/$DOMAIN/.logs"
    fi
    
    # If the domain does not have DNS resolution the script will jump the domain and continue with the next.
    dns_a_records_check=$(dig +short A "$DOMAIN" @8.8.8.8)
    if [ -z "$dns_a_records_check" ]; then
    	banner
    	echo -e "\n${redColour}[*]No resolution DNS found for $DOMAIN${endColour}\n"
    	return
    fi

    # Main logic

    # the domain is always mandatory, and then there are 4 options, one that is only domain,
    # one that is intense, one that is censys and one with both.
    # It could be done with an If of the first and its two options inside then an else and the last option.
    # OPTION1
    if [ "$FLAG_INTENSIVE" = true ]; then
      if [ "$FLAG_CENSYS" = true ]; then
       # echo "Executing Option 1 and Option 2"
        flag_all "$DOMAIN" "$LOCATION"
      else
       # echo "Executing Option 1 only"
        flag_intensive "$DOMAIN" "$LOCATION"
      fi
    else
      if [ "$FLAG_CENSYS" = true ]; then
       # echo "Executing Option 2 only"
        flag_censys "$DOMAIN" "$LOCATION"
      else
       # echo "No options selected"
        flag_domain "$DOMAIN" "$LOCATION"
      fi
    fi
    echo "" >> $results_file
}


if [ -n "$DOMAIN" ];then
    main_logic $DOMAIN
else
    for DOMAIN in $(cat "$DOM_FILE"); do
        main_logic $DOMAIN
    done
fi

exit 0