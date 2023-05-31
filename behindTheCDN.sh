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

# File to store the results
timestamp="$(date +%s)"
results_file="results-$timestamp.txt"

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
    curl -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/ip_addresses/$IP" \
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
    curl -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/resolutions?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "$LOCATION/$DOMAIN/virustotal_resolutions.json"
    jq -r '.data[].attributes.ip_address' "${LOCATION}/${DOMAIN}/virustotal_resolutions.json" \
        > "$LOCATION/$DOMAIN/IP.txt"
    cat "${LOCATION}/${DOMAIN}/IP.txt" | sort
}

virustotal_dns_history_intensive() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Intensive collect \
DNS resolutions history for $DOMAIN${endColour}\n"
    curl -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/resolutions?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_resolutions.json"
    jq -r '.data[].attributes.ip_address' "${LOCATION}/${DOMAIN}/virustotal_resolutions.json" \
        > "${LOCATION}/${DOMAIN}/IP.txt"
    jq -r '.links.next' "${LOCATION}/${DOMAIN}/virustotal_resolutions.json" \
        > "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"

    while [ -s "${LOCATION}/${DOMAIN}/virustotal_url_next.txt" ]; do
        curl -s -m 5 -k --request GET --url "$(cat "${LOCATION}/${DOMAIN}/virustotal_url_next.txt")" \
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
    curl -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/historical_ssl_certificates?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json"
    jq -r '.data[].attributes.thumbprint_sha256' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json" \
        > "${LOCATION}/${DOMAIN}/sha256_certificates.txt"
    cat "${LOCATION}/${DOMAIN}/sha256_certificates.txt"
}

virustotal_certificates_history_intensive() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} Fingerprint sha256 of \
ssl certificates history in virustotal${endColour}\n"
    curl -s -m 5 -k --request GET --url "https://www.virustotal.com/api/v3/domains/$DOMAIN/historical_ssl_certificates?limit=40" \
        --header "x-apikey: $VIRUSTOTAL_API_ID" > "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json"
    jq -r '.links.next' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json" \
        > "${LOCATION}/${DOMAIN}/virustotal_url_next.txt"
    jq -r '.data[].attributes.thumbprint_sha256' "${LOCATION}/${DOMAIN}/virustotal_historical_ssl_certificates.json" \
        > "${LOCATION}/${DOMAIN}/sha256_certificates.txt"

    while [ -s "${LOCATION}/${DOMAIN}/virustotal_url_next.txt" ]; do
        curl -s -m 5 -k --request GET --url "$(cat "${LOCATION}/${DOMAIN}/virustotal_url_next.txt")" \
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
    curl -s -X GET -H "Content-Type: application/json" -H "Host: $CENSYS_DOMAIN_API" \
        -H "Referer: $CENSYS_URL_API" -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
        --url "$CENSYS_URL_API/v2/certificates/search?q=$DOMAIN" \
        | jq -r '.result.hits | .[].fingerprint_sha256' \
        > "${LOCATION}/${DOMAIN}/sha256_certificates.txt"

    if [ -z "$(cat "${LOCATION}/${DOMAIN}/sha256_certificates.txt")" ]; then
        echo -e "\n\t${redColour}[*]No certificates found in censys${endColour}\n"
    else
        for sha256 in $(cat "${LOCATION}/${DOMAIN}/sha256_certificates.txt" \
            | sort | uniq); do
            curl -s -X GET -H "Content-Type: application/json" \
                -H "Host: $CENSYS_DOMAIN_API" -H "Referer: $CENSYS_URL_API" \
                -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
                --url "$CENSYS_URL_API/v2/hosts/search?q=services.tls.certificates.leaf_data.\
                fingerprint%3A+$sha256+or+services.tls.certificates.chain.fingerprint%3A+$sha256" \
                | jq -r '.result.hits | .[].ip' >> "${LOCATION}/${DOMAIN}/IP.txt"
        done
        if [ -z "$(cat "${LOCATION}/${DOMAIN}/IP.txt")" ]; then
            echo -e "\n\t${redColour}[*]No IP found in censys for the certificates${endColour}\n"
        else
            cat "${LOCATION}/${DOMAIN}/IP.txt"
        fi
    fi
}

validation_lines(){

    if [ ! -s "$LOCATION/$DOMAIN/IP.txt" ]
    then
        echo -e "\n\t${redColour}[*]${endColour}${grayColour}The list of IP to \
validate is empty${endColour}\n"
        #exit 1
    else
        curl -s -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
            -H "$CONNECTION_HEADER" https://$DOMAIN > "$LOCATION/$DOMAIN/real_validation.txt"

        #DEBUG
        cat "$LOCATION/$DOMAIN/real_validation.txt" > "$LOCATION/$DOMAIN/.logs/real_html.html"
        curl -L -s -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
            -H "$CONNECTION_HEADER" https://$DOMAIN > "$LOCATION/$DOMAIN/.logs/real_html_with_redirect.html"

        if [ -s "$LOCATION/$DOMAIN/real_validation.txt" ]; then
            echo -e "\n${yellowColour}[*]${endColour}${grayColour} IP validation per line without redirects${endColour}\n"
            for testIP in $(cat "$LOCATION/$DOMAIN/IP.txt" | sort | uniq);
            do
                curl -s -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
                    -H "$CONNECTION_HEADER" --resolve *:443:$testIP https://$DOMAIN \
                    > "$LOCATION/$DOMAIN/test_validation.txt"

                #DEBUG
                cat "$LOCATION/$DOMAIN/test_validation.txt" > "$LOCATION/$DOMAIN/.logs/$testIP.html"
                curl -L -s -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" -H "$ACCEPT_LANGUAGE" \
                    -H "$CONNECTION_HEADER" --resolve *:443:$testIP https://$DOMAIN \
                    > "$LOCATION/$DOMAIN/.logs/$testIP-with-redirect.html"

                difference=$(diff -U 0 "$LOCATION/$DOMAIN/real_validation.txt" "$LOCATION/$DOMAIN/test_validation.txt" \
                    | grep -a -v ^@ | wc -l) 2> /dev/null
                lines=$(cat "$LOCATION/$DOMAIN/real_validation.txt" "$LOCATION/$DOMAIN/test_validation.txt" \
                    | wc -l) 2> /dev/null
                # Check if $lines is 0 and set it to 1
                if [ "$lines" -eq 0 ]; then
                    lines=1
                fi
                percent=$(((lines-difference)*100/lines))
                percent=$(( percent < 0 ? 0 : percent )) # Ensure that the percentage is not negative.
                echo "$testIP Percentage: $percent%"
                if (( $percent > 65 )); then
                    echo $testIP >> "$LOCATION/$DOMAIN/IP_validate.tmp"
                fi
            done
            rm -rf "$LOCATION/$DOMAIN/real_validation.txt" "$LOCATION/$DOMAIN/test_validation.txt"
        fi
    fi

}

## Optimised version

validation_lines_test() {
    if [ ! -s "${LOCATION}/${DOMAIN}/IP.txt" ]; then
        echo -e "\n\t${redColour}[*]${endColour}${grayColour} The list of IP to validate is empty.${endColour}\n"
        #exit 1
    else

        curl_opts=(-s -m 5 -k -X GET -H ""$USER_AGENT"" -H ""$ACCEPT_HEADER"" -H ""$ACCEPT_LANGUAGE"" -H "$CONNECTION")

        curl "${curl_opts[@]}" "https://${DOMAIN}" > "${LOCATION}/${DOMAIN}/real_validation.txt"

        echo -e "\n${yellowColour}[*]${endColour}${grayColour} IP validation per line without redirects${endColour}\n"
        while read -r testIP; do
            curl "${curl_opts[@]}" --resolve "*:443:${testIP}" "https://${DOMAIN}" > "${LOCATION}/${DOMAIN}/test_validation.txt"

            difference=$(diff -U 0 "${LOCATION}/${DOMAIN}/real_validation.txt" "${LOCATION}/${DOMAIN}/test_validation.txt" | grep -a -v ^@ | wc -l)
            lines=$(cat "${LOCATION}/${DOMAIN}/real_validation.txt" "${LOCATION}/${DOMAIN}/test_validation.txt" | wc -l)
            percent=$(((lines - difference) * 100 / lines))
            percent=$((percent < 0 ? 0 : percent))

            echo "$testIP Percentage: $percent%"
            if ((percent > 65)); then
                echo "$testIP" >> "${LOCATION}/${DOMAIN}/IP_validate.tmp"
            fi
        done < "${LOCATION}/${DOMAIN}/IP.txt"

        rm -rf "${LOCATION}/${DOMAIN}/real_validation.txt" "${LOCATION}/${DOMAIN}/test_validation.txt"
    fi
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

validation_content() {

    echo -e "\n${yellowColour}[*]${endColour}${grayColour} IP validation by content with redirects${endColour}\n"
   # curl -L -s -m 5 -k -X GET -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Connection: keep-alive' --resolve *:443:$(dig +short A "$DOMAIN" @"$RESOLVER") https://$DOMAIN > "$LOCATION/$DOMAIN/real_validation.txt"
    curl -L -s -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" \
        -H "$ACCEPT_LANGUAGE" -H "$CONNECTION_HEADER" https://$DOMAIN > "$LOCATION/$DOMAIN/real_validation.txt"
    local text1=$(read_and_normalize_html "$LOCATION/$DOMAIN/real_validation.txt")

    #DEBUG
    echo $text1 > "$LOCATION/$DOMAIN/.logs/read_and_normalize_html_real_request.txt"

    for testIP in $(cat "$LOCATION/$DOMAIN/IP.txt" | sort | uniq);
    do
        curl -L -s -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" \
            -H "$ACCEPT_LANGUAGE" -H "$CONNECTION_HEADER" --resolve *:443:$testIP \
            https://$DOMAIN > "$LOCATION/$DOMAIN/test_validation.txt"
        local text2=$(read_and_normalize_html "$LOCATION/$DOMAIN/test_validation.txt")

        #DEBUG
        echo $text2 > "$LOCATION/$DOMAIN/.logs/read_and_normalize_html_$testIP.txt" 

        local similarity=$(similarity_percentage "$text1" "$text2")
        if [[ $similarity -gt 75 ]]; then
            echo $testIP >> "$LOCATION/$DOMAIN/IP_validate.tmp"
        fi
        echo "$testIP Similarity HTML content: $similarity%"
    done
    rm -rf "$LOCATION/$DOMAIN/real_validation.txt" "$LOCATION/$DOMAIN/test_validation.txt"
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
        echo -e "\n\t${redColour}[*]${endColour}${grayColour}The validated IP list is empty${endColour}\n"
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
        echo -e "\n\t${redColour}[*]${endColour}${grayColour}The validated IP list is empty${endColour}\n"
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
        ["fastly"]="_fastly_session|X-Served-By|X-Fastly-Request-ID"
        ["imperva"]="incap_ses_|visid_incap_|X-CDN: Imperva|Imperva"
        ["keycdn"]="X-Edge-Location|X-Cache-Key|Server: keycdn-engine|X-Edge-IP|X-Edge-Server"
        ["sucuri"]="sucuri_cloudproxy_uuid_|X-Sucuri-ID|X-XSS-Protection: 1; mode=block; Sucuri|X-Sucuri-Cache|X-Content-Type-Options: nosniff; Sucuri"
        ["stackpath"]="Server: StackPath|X-HW|X-Edge-Server"
        ["limelight"]="Server: LLNW|X-Limelight-Edge-IP|X-Limelight-Edge-Hostname"
        ["azureedge"]="Server: AzureEdge|X-Edge-Location|X-Azure-Ref"
        ["googleusercontent"]="Server: UploadServer|X-GUploader-UploadID|X-Goog-Upload-Status"
        ["rackspace"]="X-Cache-Hits"
        ["cachefly"]="Server: Flywheel|X-FLY-Region"
        ["cdn77"]="Server: CDN77|X-Edge-Server|X-Edge-Location|X-Cache-Status"
        ["cdnetworks"]="Server: CDNetworks|X-Daa-Tunnel|X-CDN|X-Edge-Server"
        ["leaseweb"]="Server: LeaseWeb CDN|X-Edge-Server"
        ["ovh"]="Server: OVHcdn|X-CDN-POP|X-CDN-TTL|X-Cache"
        ["bunnycdn"]="Server: BunnyCDN|X-Bunny-Server|X-Bunny-Cache"
        ["gcorelabs"]="Server: G-Core Labs|X-GCore-RequestID|X-GCore-Server"
        ["quantil"]="Server: QUANTIL|X-CDN-Geo|X-CDN-Origin"
        ["belugacdn"]="Server: BelugaCDN|X-Beluga-Server|X-Beluga-Request-ID"
        ["cdnvideo"]="Server: CDNvideo|X-Edge-Server|X-CDN-Location"
        ["highwinds"]="Server: Highwinds|X-HW|X-Cache"
        ["chinacache"]="Server: ChinaCache|X-CC-Distributed"
        ["edgecast"]="Server: ECD|X-Edge-Server"
        ["aryaka"]="Server: Aryaka|X-Aryaka-Edge-Server"
        ["onapp"]="Server: OnApp|X-Edge-Server"
        ["cachenetworks"]="Server: CacheNetworks|X-CacheNetworks"
        ["metacdn"]="Server: MetaCDN|X-MetaCDN"
        ["ngenix"]="Server: NGENIX|X-Edge-Server"
        ["section.io"]="Server: section.io|X-Section-Id"
        ["spacecdn"]="Server: SpaceCDN|X-Edge-Server"
    )

    # Get http headers
    headers=$(curl -L -sI -m 5 -k -X GET -H "$USER_AGENT" -H "$ACCEPT_HEADER" \
        -H "$ACCEPT_LANGUAGE" -H "$CONNECTION_HEADER" --resolve *:443:$IP https://$DOMAIN)

    # Check error request
   # if [ $? -ne 0 ]; then
   #     echo "Error request"
   #     return
   # fi

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
                local cdn_headers_validation=$(cdn_validation_by_headers_and_cookies_name $cdn_search)
                if [[ -z "${cdn_headers_validation}" ]]; then
                    local cdn_validation_whois=$(cdn_validation_by_whois $cdn_search)
                    echo "$cdn_validation_whois"
                else
                    echo "$cdn_headers_validation"
                fi
            else
                echo "$cdn_validation_PTR"
            fi
        done
    else
        echo "The validated IP list is empty"
    fi
}


flag_domain() {
    DOMAIN="$1"
    LOCATION="$2"

    banner
    get_dns_a_records
    virustotal_dns_history
    validation_lines
    validation_content
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
    validation_lines
    validation_content
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
    validation_lines
    validation_content
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
    validation_lines
    validation_content
    sort_and_uniq_IP_file
    remove_ips_from_file "$LOCATION/$DOMAIN/IP_validate.txt"
    show_validated_ip
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

    # Store the domain in the results file
    echo "Bypass for: $DOMAIN" >> $results_file

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

# OPTION2: As an easier to scale option to the future but more rare option, it can be done with a case.

#case "$FLAG_INTENSIVE-$FLAG_CENSYS" in
#  "true-true")
#    echo "Executing true-true"
#    flag_all "$DOMAIN" "$LOCATION"
#    ;;
#  "true-false")
#    echo "Executing true-false"
#    flag_intensive "$DOMAIN" "$LOCATION"
#    ;;
#  "false-true")
#    echo "Executing false-true"
#    flag_censys "$DOMAIN" "$LOCATION"
#    ;;
#  "false-false")
#    echo "Executing false-false"
#    flag_domain "$DOMAIN" "$LOCATION"
#    ;;
#  *)
#    echo "No options selected or invalid combination"
#    # Execute default function or handle error
#    ;;
#esac
