# BehindTheCDN
Script to find the IP address behind a CDN/WAF  
**IMPORTANT: The script make use of the API of VirusTotal and Censys, so you need those APIs**  
- VirusTotal API: https://www.virustotal.com/gui/user/username/apikey  
- Censys API: https://www.search.censys.io/account/api
- Shodan API: https://developer.shodan.io/api/requirements

# Prerequisites
- bash
- curl
- jq

# Instalation
`git clone https://github.com/Loop-Man/BehindTheCDN` 

# Configuration
Set the APIs for virus total and Censys on the `API.conf` file 
```conf
VIRUSTOTAL_API_ID="" # Virustotal API Key (https://www.virustotal.com/gui/user/<username>/apikey)
CENSYS_API_ID="" # Censys API ID (https://search.censys.io/account/api)
CENSYS_API_SECRET="" # Censys API SECRET de censys aquí (https://search.censys.io/account/api)
SHODAN_API="" # Shodan API key (https://developer.shodan.io/api/requirements)
```

# Use
## Add permissions to execute file
`chmod u+x behindTheCDN.sh`
## Basic option
The basic option allows you to search for a particular domain  
`./behindTheCDN.sh -d example.com` 
## Intensive mode
This option allows you to launch more queries and search by DNS history, ssl certificates  
`./behindTheCDN.sh -d example.com -i` 
## Censys
This option allows you to search using the censys API  
`./behindTheCDN.sh -d example.com -c` 
## File
This option allows you to indicate a file with domains to look for a possible bypass  
`./behindTheCDN.sh -f domains.txt` 
## Combine
All options can be combined and use it at the same time  
`./behindTheCDN.sh -d example.com -i -c`  
`./behindTheCDN.sh -f domains.txt -i -c`  

# Results
The script by default writes the output to a file with a timestamp in a folder called `results`
