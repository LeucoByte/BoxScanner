#!/bin/bash

BLACK="\e[30m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
WHITE="\e[37m"
RESET="\e[0m"


error() {
    echo -e "${RED}[-] $1${RESET}"
}

information() {
    echo -e "${CYAN}[*] $1${RESET}"
}

warning() {
    echo -e "${YELLOW}[!] $1${RESET}"
}

success() {
    echo -e "${BLUE}[+] $1${RESET}"
}

show_help() {
	cat <<- EOF
	Usage: $0 [OPTIONS]

	Options:
	  --target TARGET           Target host or IP to scan
	  --threads THREADS         Number of concurrent threads (default: 200)
	  --dns-wordlist FILE       Wordlist for DNS/subdomain enumeration
	  --web-wordlist FILE       Wordlist for web directory/file enumeration
	  --extensions EXT          File extensions for Gobuster DIR (comma-separated, e.g., php,txt)
	  --ignore-codes CODES      HTTP status codes to ignore (comma-separated, e.g., 404,302)
	  --output DIR              Output directory for all results (default: ./TARGET)
	  --proxy PROXY             Proxy to use for scans (e.g., http://127.0.0.1:8080)
	  -h, --help                Show this help message and exit

	Example:
	  $0 --target http://era.htb --threads 200 \
	     --dns-wordlist /usr/share/seclists/Discovery/DNS/namelist.txt \
	     --web-wordlist /usr/share/wordlists/dirb/common.txt \
	     --extensions php,html --ignore-codes 404,302 --output scans
	EOF
}

validate_target(){
	if [[ "$TARGET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then #if its an ip
		IFS=. read -r n1 n2 n3 n4 <<< "$TARGET"
		if [[ "$n1" -le 255 && "$n2" -le 255 && "$n3" -le 255 && "$n4" -le 255 ]]; then
			IP_TARGET="$TARGET"
			success "The target is valid."
			return 0
		else
			error "Invalid target, the IP octet is out of range."
			exit 1
		fi
	elif [[ $TARGET =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then #if its a web with optional sudmain
		WEB_TARGET="$TARGET"
		return 0
	else
		error "Inavlid target format."
		exit 1
	fi	
}

check_host_up(){
	information "Checking the current status of $TARGET..."
	
	if ping -c 1 "$TARGET" &>/dev/null; then
		success "$TARGET seems to be UP."
		if [[ -n "$WEB_TARGET" ]]; then
		    IP_TARGET=$(ping -c 1 "$WEB_TARGET" | grep '64 bytes' | awk '{gsub(/[():]/,"",$5); print $5}')
		fi
	else
		error "$TARGET seems to be DOWN."
		exit 1
    	fi
}

open_ports=()
nmap_scan(){
        scan=$(nmap -sS -sV -p- --open --min-rate 5000 -n -Pn "$TARGET")
        
        if [[ -z "$scan" ]]; then
        	warning "No open ports found on $TARGET."
        	return 0;
	fi
	
	NMAP_DIR="$OUT_DIR/nmap/scan"
	mkdir -p "$NMAP_DIR" || { error "Cannot create $NMAP_DIR"; return 1; }
        echo "$scan" >> "$NMAP_DIR/full_scan_print.txt"
        
        NMAP_FILE="$NMAP_DIR/pretty_print_scan.txt"
        echo "" > "$NMAP_FILE"
	echo "Open ports found:" >> "$NMAP_FILE"
        echo "" >> "$NMAP_FILE"
	printf "%-8s %-12s %s\n" "PORT" "SERVICE" "VERSION" >> "$NMAP_FILE"
        
        while read -r line; do
                port=$(echo "$line" | awk -F/ '{print $1}')
                service=$(echo "$line" | awk '{print $3}')
                version=$(echo "$line" | awk '{print substr($0, index($0,$4))}')
                version=${version:-"unknown"}
                
                open_ports+=("$port")
                
                if [[ $port -eq 80 ]]; then
                        has_web_80=1
                fi
                if [[ $port -eq 443 ]]; then
                        has_web_443=1
                fi

                printf "%-8s %-12s %s\n" "$port" "$service" "$version" >> "$NMAP_FILE"
        done < <(echo "$scan" | grep "open" | grep -v "^#")
}

nmap_vuln(){
	ports=$(IFS=, ; echo "${open_ports[*]}")
	vuln_scan=$(nmap -sV -p"$ports" --script vuln "$TARGET")
        
        if [[ -z "$vuln_scan" ]]; then
        	warning "No vulns have been found on $TARGET."
        	return 0;
	fi
	
	NMAP_VULNDIR="$OUT_DIR/nmap/vulns"
	mkdir -p "$NMAP_VULNDIR" || { error "Cannot create $NMAP_VULNDIR"; return 1; }
	echo > "$NMAP_VULNDIR/full_vulns_scan_print.txt"
        echo "$vuln_scan" >> "$NMAP_VULNDIR/full_vulns_scan_print.txt"
	success "Vulnerability scan completed."
	
}

add_to_hosts_if_not_resolve() {
    for full_url in "$@"; do
        host=$(echo "$full_url" | awk -F[/:] '{print $4}')
        existing_line=$(grep -w "$IP_TARGET" /etc/hosts)
        
        if [[ -n "$existing_line" ]]; then
            if ! echo "$existing_line" | grep -qw "$host"; then
                sed -i "s|^$IP_TARGET.*|$existing_line $host|" /etc/hosts
                success "Added $host to existing /etc/hosts line for $IP_TARGET"
            fi
        else
            echo "$IP_TARGET $host" >> /etc/hosts
            warning "Seems that $host does not resolve. Adding to /etc/hosts..."
        fi
    done
}

host_scan(){
	urls_to_scan=()
	if [[ $has_web_80 -eq 1 && $has_web_443 -eq 1 ]]; then
	    redirect=$(curl -s -I http://"$TARGET" 2>/dev/null | grep -i "Location:" | head -n1 | awk '{print $2}' | tr -d '\r')
	    if [[ -n "$redirect" ]]; then
		urls_to_scan+=("$redirect")
	    else
		urls_to_scan+=("http://$TARGET")
		urls_to_scan+=("https://$TARGET")
	    fi
	elif [[ $has_web_80 -eq 1 ]]; then
	    redirect=$(curl -s -I http://"$TARGET" 2>/dev/null | grep -i "Location:" | head -n1 | awk '{print $2}' | tr -d '\r')
	    if [[ -n "$redirect" ]]; then
		urls_to_scan+=("$redirect")
	    else
		urls_to_scan+=("http://$TARGET")
	    fi
	elif [[ $has_web_443 -eq 1 ]]; then
	    redirect=$(curl -s -I https://"$TARGET" 2>/dev/null | grep -i "Location:" | head -n1 | awk '{print $2}' | tr -d '\r')
	    if [[ -n "$redirect" ]]; then
		urls_to_scan+=("$redirect")
	    else
		urls_to_scan+=("https://$TARGET")
	    fi
	fi
	
	add_to_hosts_if_not_resolve "${urls_to_scan[@]}"
	
	for url in "${urls_to_scan[@]}"; do
	    information "Scanning $url with the wordlist $WEB_WORDLIST..."
	    
	    a=$(gobuster dir -u "$url" -w  "$WEB_WORDLIST" -t "$THREADS" ${IGNORE_CODES:+-s "$IGNORE_CODES"} ${EXTENSIONS:+-x "$EXTENSIONS"} 2>&1)
	    b=$(echo "$a" | grep Status: | awk '{print $1, $3}' | tr -d '/' | tr -d ')')
	    c=$(echo "$a" | awk -v base="$url" '{
		n = split($0, arr, /\//);
		for(i=2; i<=n; i++){
		    ruta = arr[i];
		    match(ruta, /\(Status: [0-9]+/);
		    if(RLENGTH>0){
		        status = substr(ruta, RSTART+8, RLENGTH-8);
		        gsub(/\)/,"",status);
		        gsub(/\s.*$/,"",ruta);
		        print base ruta, status;
		    }
		}
	    }')
	    
	    if [[ -z "$b" ]]; then
        	warning "No routes found on $url with the wordlist proportionated."
        	continue;
            else
            	success "Web scan completed on $url"
            	GOBUSTER_DIR="$OUT_DIR/gobuster/web"
		mkdir -p "$GOBUSTER_DIR" || { error "Cannot create $GOBUSTER_DIR"; return 1; }
		[[ ! -f "$GOBUSTER_DIR/full_webs_print.txt" ]] && : > "$GOBUSTER_DIR/full_webs_print.txt"
		echo "" >> "$GOBUSTER_DIR/full_webs_print.txt"
    		[[ ! -f "$GOBUSTER_DIR/pretty_print_webs.txt" ]] && : > "$GOBUSTER_DIR/pretty_print_webs.txt"
		echo "" >> "$GOBUSTER_DIR/pretty_print_webs.txt"
		echo "$a" >> "$GOBUSTER_DIR/full_webs_print.txt" 
		echo "$c" >> "$GOBUSTER_DIR/pretty_print_webs.txt"
	    fi
	    
	done
}

subdomains_to_scan=()
discover_vhost(){
	for url in "${urls_to_scan[@]}"; do
		a=$(gobuster vhost -u "$url" -w "$DNS_WORDLIST" -t "$THREADS" --append-domain)
		b=$(echo "$a" | tail -n +16 | head -n -3 | awk '{print $1, $3}')
			if [[ "$url" =~ ^https:// ]]; then
				c=$(echo "https://$b")
			else
				c=$(echo "http://$b")
			fi
		
		if [[ -z "$b" ]]; then
        		warning "No DNS found on $url with the wordlist proportionated."
			continue;
         	else
		 	success "Subdomain enumeration completed on $url"
		    	GOBUSTER_DIR_DNS="$OUT_DIR/gobuster/dns"
			mkdir -p "$GOBUSTER_DIR_DNS" || { error "Cannot create $GOBUSTER_DIR_DNS"; return 1; }
			[[ ! -f "$GOBUSTER_DIR_DNS/full_dns_print.txt" ]] && : > "$GOBUSTER_DIR_DNS/full_dns_print.txt"
			echo "" >> "$GOBUSTER_DIR_DNS/full_dns_print.txt"
    			[[ ! -f "$GOBUSTER_DIR_DNS/pretty_print_dns.txt" ]] && : > "$GOBUSTER_DIR_DNS/pretty_print_dns.txt"
    			echo "" >> "$GOBUSTER_DIR_DNS/pretty_print_dns.txt"
			echo "$a" >> "$GOBUSTER_DIR_DNS/full_dns_print.txt" 
			echo "$c" >> "$GOBUSTER_DIR_DNS/pretty_print_dns.txt"
			
			while read -r line; do
				subdomain=$(echo "$line" | awk '{print $1}')
				code=$(echo "$line" | awk '{print $2}')

				if [[ "$code" =~ ^(200|301|302)$ ]]; then
			    		subdomains_to_scan+=("$subdomain")
				fi
			done <<< "$c"
         	fi
		
	done	
}

vhost_scan(){
	add_to_hosts_if_not_resolve "${subdomains_to_scan[@]}"
	
	for url in "${subdomains_to_scan[@]}"; do
	    information "Scanning $url with the wordlist $WEB_WORDLIST..."
	    
	    a=$(gobuster dir -u "$url" -w  "$WEB_WORDLIST" -t "$THREADS" ${IGNORE_CODES:+-s "$IGNORE_CODES"} ${EXTENSIONS:+-x "$EXTENSIONS"} 2>&1)
	    b=$(echo "$a" | grep Status: | awk '{print $1, $3}' | tr -d '/' | tr -d ')')
	    c=$(echo "$a" | awk -v base="$url" '{
		n = split($0, arr, /\//);
		for(i=2; i<=n; i++){
		    ruta = arr[i];
		    match(ruta, /\(Status: [0-9]+/);
		    if(RLENGTH>0){
		        status = substr(ruta, RSTART+8, RLENGTH-8);
		        gsub(/\)/,"",status);
		        gsub(/\s.*$/,"",ruta);
		        print base ruta, status;
		    }
		}
	    }')
	    
	    if [[ -z "$b" ]]; then
        	warning "No routes found on $url with the wordlist proportionated."
        	continue;
            else
            	success "Subdomain scan completed on $url"
            	GOBUSTER_DIR_SUBDOMAIN="$OUT_DIR/gobuster/subdomains"
		mkdir -p "$GOBUSTER_DIR_SUBDOMAIN" || { error "Cannot create $GOBUSTER_DIR"; return 1; }
		[[ ! -f "$GOBUSTER_DIR_SUBDOMAIN/full_subdomains_print.txt" ]] && : > "$GOBUSTER_DIR_SUBDOMAIN/full_subdomains_print.txt"
		echo "" >> "$GOBUSTER_DIR_SUBDOMAIN/full_subdomains_print.txt"
    		[[ ! -f "$GOBUSTER_DIR_SUBDOMAIN/pretty_print_subdomains_scan.txt" ]] && : > "$GOBUSTER_DIR_SUBDOMAIN/pretty_print_subdomains_scan.txt"
    		echo "" >> "$GOBUSTER_DIR_SUBDOMAIN/pretty_print_subdomains_scan.txt"
		echo "$a" >> "$GOBUSTER_DIR_SUBDOMAIN/full_subdomains_print.txt" 
		echo "$c" >> "$GOBUSTER_DIR_SUBDOMAIN/pretty_print_subdomains_scan.txt"
	    fi
	    
	done
}

#detect help
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

#default values
THREADS=200
CURRENT_DIR=$(pwd)
WEB_TARGET=""
IP_TARGET=""

#params setup
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --threads | -t) THREADS="$2"; shift 2 ;;
        --dns-wordlist) DNS_WORDLIST="$2"; shift 2 ;;
        --web-wordlist) WEB_WORDLIST="$2"; shift 2 ;;
        --extensions) EXTENSIONS="$2"; shift 2 ;;
        --ignore-codes | -i) IGNORE_CODES="$2"; shift 2 ;;
        --output | -o) OUT_DIR="$CURRENT_DIR/$2"; shift 2 ;;
        --proxy) PROXY="$2"; shift 2 ;;
        *) warning "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

#check essentials params
if [[ -z "$TARGET" || -z "$DNS_WORDLIST" || -z "$WEB_WORDLIST" ]]; then
    error "Insufficient parameters: --target, --dns-wordlist and --web-wordlist are mandatory."
    show_help
    exit 1
fi

#start of the script
clear
echo ""

#tittle
echo -e "${YELLOW}██████╗  ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗${RESET}"
echo -e "${YELLOW}██╔══██╗██╔═══██╗╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║${RESET}"
echo -e "${YELLOW}██████╔╝██║   ██║ ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║${RESET}"
echo -e "${YELLOW}██╔══██╗██║   ██║ ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║${RESET}"
echo -e "${YELLOW}██████╔╝╚██████╔╝██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║${RESET}"
echo -e "${YELLOW}╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝${RESET}"
                                                           
#author things
echo -e "\n${WHITE}[@] A tool developed by Leucocito ${RESET}"
echo -e "${WHITE}[@] GitHub: https://github.com/LeucoByte${RESET}\n"

#some params
OUT_DIR="${OUT_DIR:-$CURRENT_DIR/$TARGET}"
NOTES_FILE="$OUT_DIR/notes.txt"

#validation and hosting
validate_target
echo -e ""
check_host_up
echo -e ""

#creating the main directory
information "Creating directory $OUT_DIR..."
mkdir -p "$OUT_DIR" 2>/dev/null

if [[ $? -eq 1 ]]; then
	error "Could not create directory $OUT_DIR"
	exit 1
else
	success "Directory $OUT_DIR created with success."
fi

echo ""

#nmap scan
has_web_80=0
has_web_443=0
information "Starting nmap scan in $TARGET... (this may take a while)"
nmap_scan
success "Nmap scan finished. Open ports detected: $(printf "%s, " "${open_ports[@]}" | sed 's/, $//')"
information "Performing vulnerability scan on the discovered open ports..."
nmap_vuln
success "Nmap scan has ended. Results are in the directory: $OUT_DIR/nmap"

echo ""

#web scan
if [[ $has_web_80 -eq 1 || $has_web_443 -eq 1 ]]; then
	information "Starting gobuster scan in $TARGET... (this may take a while)"
	host_scan
	success "All web scans completed successfully."
	echo ""
	information "Starting subdomain enumeration on $TARGET..."
	discover_vhost
	
	echo ""
	if [[ ${#subdomains_to_scan[@]} -eq 0 ]]; then
    		warning "No live subdomains found with status 200/301/302. Skipping subdomain scan."
	else
    		information "Scanning discovered live subdomains (HTTP 200/301/302) with the wordlist $DNS_WORDLIST"
    		vhost_scan
	fi
	
	success "Gobuster scan finished. Results are in $OUT_DIR/gobuster"
else
	error "No HTTP/HTTPS service detected on the target. Web scan cannot proceed."
fi

echo ""

if [[ ! -f "$NOTES_FILE" ]]; then
    : > "$NOTES_FILE"
    echo "An additional file named notes.txt has been created to help you take notes." >> "$NOTES_FILE"
    success "A notes file has been created at $NOTES_FILE"
fi

#finalitation
success "The script has finished successfully!"
information "Final directory structure: "
echo ""
tree --noreport "$OUT_DIR"

