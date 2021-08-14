#!/bin/sh
# inspired by @21y4d
# crafted by @wirzka
# ANSI color variables
RED='\033[1;31m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
NC='\033[0m'
origIFS="${IFS}"

printf "${GREEN}"
printf "     ____                                        \n"
printf "    /  _/___ _______  ________________  ________\n"
printf "   / // __ \/ ___/ / / / ___/ ___/ __ \/ ___/ _ \ \n"
printf " _/ // / / / /__/ /_/ / /  (__  ) /_/ / /  /  __/\n"
printf "/___/_/ /_/\___/\__,_/_/  /____/\____/_/   \___/\n${NC}"
printf "                     @wirzka                      \n"

# Start timer
elapsedStart="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"

# Parse flags
while [ $# -gt 0 ]; do
        key="$1"

        case "${key}" in
        -H | --host)
                HOST="$2"
                shift
                shift
                ;;
        -t | --type)
                TYPE="$2"
                shift
                shift
                ;;
        -d | --dns)
                DNS="$2"
                shift
                shift
                ;;
        -o | --output)
                OUTPUTDIR="$2"
                shift
                shift
                ;;
        *)
                POSITIONAL="${POSITIONAL} $1"
                shift
                ;;
        esac
done
set -- ${POSITIONAL}

# Legacy flags support, if run without -H/-t
if [ -z "${HOST}" ]; then
        HOST="$1"
fi

if [ -z "${TYPE}" ]; then
        TYPE="$2"
fi

# Set DNS or default to system DNS
if [ -n "${DNS}" ]; then
        DNSSERVER="${DNS}"
        DNSSTRING="--dns-server=${DNSSERVER}"
else
        DNSSERVER="$(grep 'nameserver' /etc/resolv.conf | grep -v '#' | head -n 1 | awk {'print $NF'})"
        DNSSTRING="--system-dns"
fi

# Set output dir or default to host-based dir
if [ -z "${OUTPUTDIR}" ]; then
        OUTPUTDIR="${HOST}"
fi

# Set path to nmap binary or default to nmap in $PATH
if [ -z "${NMAPPATH}" ] && type nmap >/dev/null 2>&1; then
        NMAPPATH="$(type nmap | awk {'print $NF'})"
else
        printf "${RED}\nNmap is not installed and -s is not used. Eject! Eject! Eject!${NC}\n\n" && REMOTE=true
fi

# Print usage menu and exit. Used when issues are encountered
# No args needed
usage() {
        echo
        printf "${GREEN}Usage:${NC} ${RED}$(basename $0) -H/--host ${NC}<TARGET-IP>${RED} -t/--type ${NC}<TYPE>${RED}\n"
        printf "${YELLOW}Optional: [-d/--dns ${NC}<DNS SERVER>${YELLOW}] [-o/--output ${NC}<OUTPUT DIRECTORY>${YELLOW}]${NC}\n\n"
        printf "${CYAN}Scan Types:\n"
        printf "${CYAN}\tPort    : ${NC}Shows all open ports ${YELLOW}\n"
        printf "${CYAN}\tScript  : ${NC}Runs a script scan on found ports ${YELLOW}\n"
        printf "${CYAN}\tUDP     : ${NC}Runs a UDP scan \"requires sudo\" ${YELLOW}\n"
        printf "${CYAN}\tVulns   : ${NC}Runs CVE scan and nmap Vulns scan on all found ports ${YELLOW}\n"
        printf "${CYAN}\tRecon   : ${NC}Suggests recon commands, then prompts to automatically run them\n"
        printf "${CYAN}\tAll     : ${NC}Runs all the scans ${YELLOW}\n"
        printf "${NC}\n"
        printf "inspired by ${PURPLE}@21y4d${NC} gently modified by ${PURPLE}@wirzka${NC}\n"
        exit 1
}

# Print initial header and set initial variables before scans start
# No args needed
header() {
        echo
        # Print scan type
        if expr "${TYPE}" : '^\([Aa]ll\)$' >/dev/null; then
                printf "${GREEN}Hail Mary on ${NC}${PURPLE}${HOST}${NC}"
        else
                printf "${GREEN}Launching a ${TYPE} scan on ${NC}${HOST}"
        fi

        if expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
                urlIP="$(host -4 -W 1 ${HOST} ${DNSSERVER} 2>/dev/null | grep ${HOST} | head -n 1 | awk {'print $NF'})"
                if [ -n "${urlIP}" ]; then
                        printf "${YELLOW} with IP ${NC}${urlIP}\n\n"
                else
                        printf ".. ${RED}Could not resolve IP of ${NC}${HOST}\n\n"
                fi
        else
                printf "\n"
        fi

        # Set $subnet variable
        if expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                subnet="$(echo "${HOST}" | cut -d "." -f 1,2,3).0"
        fi

        # Set $nmapType variable based on ping
        kernel="$(uname -s)"
        checkPing="$(checkPing "${urlIP:-$HOST}")"
        nmapType="$(echo "${checkPing}" | head -n 1)"

        # # Set if host is pingable 'for ping scans'
        # if expr "${nmapType}" : ".*-Pn$" >/dev/null; then
        #         pingable=false
        #         printf "${NC}\n"
        #         printf "${YELLOW}No ping detected.. Will not use ping scans!\n"
        #         printf "${NC}\n"
        # else
        #         pingable=true
        # fi

        # OS Detection
        ttl="$(echo "${checkPing}" | tail -n 1)"
        if [ "${ttl}" != "nmap -Pn" ]; then
                osType="$(checkOS "${ttl}")"
                printf "${NC}\n"
                printf "${GREEN}Host is likely running ${NC}${PURPLE}${osType}${NC}\n"
        fi
        echo
}

# Used Before and After each nmap scan, to keep found ports consistent across the script
# $1 is $HOST
assignPorts() {
        # Set $commonPorts based on Port scan
        # Set $allTCPPorts based on Full scan or both Port and Full scans
        if [ -f "nmap/full_TCP_$1.nmap" ]; then
                allTCPPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/full_TCP_$1.nmap" | sed 's/.$//')"
        fi

        # Set $udpPorts based on UDP scan
        if [ -f "nmap/UDP_$1.nmap" ]; then
                udpPorts="$(awk -vORS=, -F/ '/^[0-9]/{print $1}' "nmap/UDP_$1.nmap" | sed 's/.$//')"
                if [ "${udpPorts}" = "Al" ]; then
                        udpPorts=""
                fi
        fi
}

# Test whether the host is pingable, and return $nmapType and $ttl
# $1 is $HOST
checkPing() {
        # If ping is not returned within a second, then ping scan is disabled with -Pn
        if [ $kernel = "Linux" ]; then TW="W"; else TW="t"; fi
        pingTest="$(ping -c 1 -${TW} 1 "$1" 2>/dev/null | grep ttl)"
        if [ -z "${pingTest}" ]; then
                echo "${NMAPPATH} -Pn"
        else
                echo "${NMAPPATH}"
                if expr "$1" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
                        ttl="$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)"
                else
                        ttl="$(echo "${pingTest}" | cut -d " " -f 7 | cut -d "=" -f 2)"
                fi
                echo "${ttl}"
        fi
}

# Detect OS based on $ttl
# $1 is $ttl
checkOS() {
        case "$1" in
        25[456]) echo "OpenBSD/Cisco/Oracle" ;;
        12[78]) echo "Windows" ;;
        6[34]) echo "Linux" ;;
        *) echo "Some alien stuff!" ;;
        esac
}

# Print nmap progress bar
# $1 is $scanType, $2 is $percent, $3 is $elapsed, $4 is $remaining
progressBar() {
        [ -z "${2##*[!0-9]*}" ] && return 1
        [ "$(stty size | cut -d ' ' -f 2)" -le 120 ] && width=50 || width=100
        fill="$(printf "%-$((width == 100 ? $2 : ($2 / 2)))s" "#" | tr ' ' '#')"
        empty="$(printf "%-$((width - (width == 100 ? $2 : ($2 / 2))))s" " ")"
        printf "In progress: ${PURPLE}$1${NC} Scan ($3 elapsed - $4 remaining)   \n"
        printf "[${fill}>${empty}] $2%% done   \n"
        printf "\e[2A"
}

# Calculate current progress bar status based on nmap stats (with --stats-every)
# $1 is nmap command to be run, $2 is progress bar $refreshRate
nmapProgressBar() {
        refreshRate="${2:-1}"
        outputFile="$(echo $1 | sed -e 's/.*-oN \(.*\).nmap.*/\1/').nmap"
        tmpOutputFile="${outputFile}.tmp"

        # Run the nmap command
        if [ ! -e "${outputFile}" ]; then
                $1 --stats-every "${refreshRate}s" >"${tmpOutputFile}" 2>&1 &
        fi

        # Keep checking nmap stats and calling progressBar() every $refreshRate
        while { [ ! -e "${outputFile}" ] || ! grep -q "Nmap done at" "${outputFile}"; } && { [ ! -e "${tmpOutputFile}" ] || ! grep -i -q "quitting" "${tmpOutputFile}"; }; do
                scanType="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/.*undergoing \(.*\) Scan.*/\1/p}')"
                percent="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/% done/{s/.*About \(.*\)\..*% done.*/\1/p}')"
                elapsed="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/elapsed/{s/Stats: \(.*\) elapsed.*/\1/p}')"
                remaining="$(tail -n 2 "${tmpOutputFile}" 2>/dev/null | sed -ne '/remaining/{s/.* (\(.*\) remaining.*/\1/p}')"
                progressBar "${scanType:-No}" "${percent:-0}" "${elapsed:-0:00:00}" "${remaining:-0:00:00}"
                sleep "${refreshRate}"
        done
        printf "\033[0K\r\n\033[0K\r\n"

        # Print final output, remove extra nmap noise
        if [ -e "${outputFile}" ]; then
                sed -n '/PORT.*STATE.*SERVICE/,/^# Nmap/H;${x;s/^\n\|\n[^\n]*\n# Nmap.*//gp}' "${outputFile}" | awk '!/^SF(:|-).*$/' | grep -v 'service unrecognized despite'
        else
                cat "${tmpOutputFile}"
        fi
        rm -f "${tmpOutputFile}"
}

# do a full TCP SYN scan if id=0 or connect scan
portScan() {
        if [ "${USER}" != 'root' ]; then
                echo "${RED}[!] ALERT${NC}"
                echo "${RED}>${NC} Nmap needs to be run as root, otherwise it'll do a connect scan instead of a SYN scan."

                # asking if user wants to run nmap as root or not
                echo "${RED}>${NC} To sudo or not to sudo? y/n \n"
                read sudoOrNot

                # if user wants to proceed without root
                if [ $sudoOrNot != "y" ]; then
                        echo

                        printf "${YELLOW}[*] Full TCP port scan launched\n${NC}"

                        nmapProgressBar "${nmapType} -T4 -p- --max-retries 2 -vv --max-scan-delay 30 -Pn --open -oN nmap/full_TCP_${HOST}.nmap ${HOST} ${DNSSTRING}"
                        assignPorts "${HOST}"

                # in the case the user wants sudo
                else
                        echo

                        echo "${RED}>${NC} Running with sudo..."
                        sudo -v

                        printf "\n${YELLOW}[*] Full TCP port scan launched\n${NC}"
                        nmapProgressBar "sudo ${nmapType} -T4 -p- --max-retries 2 -vv --max-scan-delay 30 -Pn --open -oN nmap/full_TCP_${HOST}.nmap ${HOST} ${DNSSTRING}"
                        assignPorts "${HOST}"

                        echo
                fi
        else
                echo

                printf "${YELLOW}[*] Full TCP port scan launched\n"
                printf "${NC}\n"

                nmapProgressBar "${nmapType} -T4 -p- --max-retries 2 -vv --max-scan-delay 30 -Pn --open -oN nmap/full_TCP_${HOST}.nmap ${HOST} ${DNSSTRING}"
                assignPorts "${HOST}"

                echo
        fi
}

# Nmap version and default script scan on found ports
scriptScan() {
        printf "${YELLOW}[*] Script Scan launched on open ports\n"
        printf "${NC}\n"

        ports="${allTCPPorts}"
        if [ -z "${ports}" ]; then
                printf "${YELLOW}No ports in port scan.. Skipping!\n"
        else
                nmapProgressBar "${nmapType} -Pn -sCV -p${ports} --open -oN nmap/Script_TCP_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
        fi

        # Modify detected OS if Nmap detects a different OS
        if [ -f "nmap/Script_TCP_${HOST}.nmap" ] && grep -q "Service Info: OS:" "nmap/Script_TCP_${HOST}.nmap"; then
                serviceOS="$(sed -n '/Service Info/{s/.* \([^;]*\);.*/\1/p;q}' "nmap/Script_TCP_${HOST}.nmap")"
                if [ "${osType}" != "${serviceOS}" ]; then
                        osType="${serviceOS}"
                        printf "${NC}\n"
                        printf "${NC}\n"
                        printf "${GREEN}OS Detection modified to: ${osType}\n"
                        printf "${NC}\n"
                fi
        fi
        echo
}

# Nmap UDP scan
UDPScan() {
        printf "${YELLOW}[*] UDP port scan launched\n"
        printf "${NC}\n"

        # Ensure UDP scan runs with root priviliges
        if [ "${USER}" != 'root' ]; then
                echo "${RED}[!] ALERT${NC}"
                echo "${RED}>${NC} UDP scan needs to be run as root."
                echo "${RED}>${NC} Running with sudo..."
                sudo -v
                echo
        fi

        nmapProgressBar "sudo ${nmapType} -sU --max-retries 1 --open --open -oN nmap/UDP_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
        assignPorts "${HOST}"

        # Nmap version and default script scan on found UDP ports
        if [ -n "${udpPorts}" ]; then
                echo
                echo
                printf "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')\n"
                printf "${NC}\n"
                if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
                        sudo -v
                        nmapProgressBar "sudo nmap -Pn -sCVU --script vulners --script-args mincvss=7.0 -p${udpPorts} --open -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                else
                        sudo -v
                        nmapProgressBar "sudo nmap -Pn -sCVU -p${udpPorts} --open -oN nmap/UDP_Extra_${HOST}.nmap ${HOST} ${DNSSTRING}" 2
                fi
        else
                echo
                printf "${YELLOW}No UDP ports are open\n"
                printf "${NC}\n"
        fi
        echo
}

# Nmap vulnerability detection script scan
vulnsScan() {
        printf "${YELLOW}[!] Vulnerability Scan\n"
        printf "${NC}\n"

        # Set ports to be scanned (common or all)
        ports="${allTCPPorts}"

        # Ensure the vulners script is available, then run it with nmap
        if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
                printf "${RED}Please install 'vulners.nse' nmap script:\n"
                printf "${RED}https://github.com/vulnersCom/nmap-vulners\n"
                printf "${RED}\n"
                printf "${RED}Skipping CVE scan!\n"
                printf "${NC}\n"
        else
                printf "${YELLOW}> Running CVE scan on ${portType} ports\n"
                printf "${NC}\n"
                nmapProgressBar "nmap -sV -Pn --script vulners --script-args mincvss=7.0 -p${ports} --open -oN nmap/CVEs_${HOST}.nmap ${HOST} ${DNSSTRING}" 3
                echo
        fi

        # Nmap vulnerability detection script scan
        echo
        printf "${YELLOW}> Running Vuln scan on ${portType} ports\n"
        printf "${YELLOW}Go for a walk if the target's got a lot of ports :)\n"
        printf "${NC}\n"
        nmapProgressBar "nmap -sV -Pn --script vuln -p${ports} --open -oN nmap/Vulns_${HOST}.nmap ${HOST} ${DNSSTRING}" 3

        echo
}

# Run reconRecommend(), ask user for tools to run, then run runRecon()
recon() {
        IFS="
"
        # Run reconRecommend()
        reconRecommend "${HOST}" | tee "nmap/Recon_${HOST}.nmap"
        allRecon="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | cut -d " " -f 1 | sort | uniq)"

        # Detect any missing tools
        for tool in ${allRecon}; do
                if ! type "${tool}" >/dev/null 2>&1; then
                        missingTools="$(echo ${missingTools} ${tool} | awk '{$1=$1};1')"
                fi
        done

        # Exclude missing tools, and print help for installing them
        if [ -n "${missingTools}" ]; then
                printf "${RED}Missing tools: ${NC}${missingTools}\n"
                printf "\n${RED}You can install with:\n"
                printf "${YELLOW}sudo apt install ${missingTools} -y\n"
                printf "${NC}\n\n"

                availableRecon="$(echo "${allRecon}" | tr " " "\n" | awk -vORS=', ' '!/'"$(echo "${missingTools}" | tr " " "|")"'/' | sed 's/..$//')"
        else
                availableRecon="$(echo "${allRecon}" | tr "\n" " " | sed 's/\ /,\ /g' | sed 's/..$//')"
        fi

        secs=3
        count=0

        # Ask user for which recon tools to run, default to All if no answer is detected in 3s
        if [ -n "${availableRecon}" ]; then
                while [ "${reconCommand}" != "!" ]; do
                        printf "${YELLOW}\n"
                        printf "Which commands would you like to run?${NC}\nAll (Default), ${availableRecon}, Skip <!>\n\n"
                        while [ ${count} -lt ${secs} ]; do
                                tlimit=$((secs - count))
                                printf "\033[2K\rRunning Default in (${tlimit})s: "

                                # Waits 1 second for user's input - POSIX read -t
                                reconCommand="$(sh -c '{ { sleep 1; kill -sINT $$; } & }; exec head -n 1')"
                                count=$((count + 1))
                                [ -n "${reconCommand}" ] && break
                        done
                        if expr "${reconCommand}" : '^\([Aa]ll\)$' >/dev/null || [ -z "${reconCommand}" ]; then
                                runRecon "${HOST}" "All"
                                reconCommand="!"
                        elif expr " ${availableRecon}," : ".* ${reconCommand}," >/dev/null; then
                                runRecon "${HOST}" "${reconCommand}"
                                reconCommand="!"
                        elif [ "${reconCommand}" = "Skip" ] || [ "${reconCommand}" = "!" ]; then
                                reconCommand="!"
                                echo
                                echo
                                echo
                        else
                                printf "${NC}\n"
                                printf "${RED}Incorrect choice!\n"
                                printf "${NC}\n"
                        fi
                done
        else
                printf "${YELLOW}No Recon Recommendations found...\n"
                printf "${NC}\n"
        fi

        IFS="${origIFS}"
}

# Recommend recon tools/commands to be run on found ports
# This is just a place where you should but what you want
# to be executed.
# Everything will be executed inside the runRecon() function
reconRecommend() {
        printf "\n\n\n\n"
        printf "${YELLOW}[*] Recon Recommendations\n"
        printf "${NC}\n"
        printf "The script will execute the following commands.\n"

        IFS="
"

        # Set $ports and $file variables
        if [ -f "nmap/Script_TCP_${HOST}.nmap" ]; then
                ports="${allTCPPorts}"
                file="$(cat "nmap/Script_TCP_${HOST}.nmap" | grep "open" | grep -v "#" | sort | uniq)"
                echo "${file}"
        fi

        # FTP bruteforce attempt
        # checking if anonymous login is allowed, but maybe it's better try to bruteforce anyway, Idk
        if echo "${file}" | grep ftp | grep -v "Anonymous FTP login allowed"; then
                ftpPort="$(echo "${file}" | grep ftp | awk -F'/' '{if (NR <= 1) print $1}')"
                printf "${NC}\n"
                printf "${YELLOW}> FTP bruteforcing with default creds:\n"
                printf "${NC}\n"
                echo "hydra -s $ftpPort -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u -f \"${HOST}\" ftp | tee \"recon/ftpBruteforce_${HOST}.txt\""
        fi

        # SMTP recon
        if echo "${file}" | grep -q "25/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}> SMTP Recon:\n"
                printf "${NC}\n"
                echo "smtp-user-enum -U /usr/share/wordlists/metasploit/unix_users.txt -t \"${HOST}\" | tee \"recon/smtp_user_enum_${HOST}.txt\""

        fi

        # DNS Recon
        if echo "${file}" | grep -q "53/tcp" && [ -n "${DNSSERVER}" ]; then
                printf "${NC}\n"
                printf "${YELLOW}DNS Recon:\n"
                printf "${NC}\n"
                echo "host -l \"${HOST}\" \"${DNSSERVER}\" | tee \"recon/hostname_${HOST}.txt\""
                echo "dnsrecon -r \"${subnet}/24\" -n \"${DNSSERVER}\" | tee \"recon/dnsrecon_${HOST}.txt\""
                echo "dnsrecon -r 127.0.0.0/24 -n \"${DNSSERVER}\" | tee \"recon/dnsrecon-local_${HOST}.txt\""
                echo "dig -x \"${HOST}\" @${DNSSERVER} | tee \"recon/dig_${HOST}.txt\""

        fi

        # Web recon
        if echo "${file}" | grep -i -q http; then
                printf "${NC}\n"
                printf "${YELLOW}> Web Servers Recon:\n"
                printf "${NC}\n"

                # HTTP recon
                for line in ${file}; do
                        if echo "${line}" | grep -i -q http; then
                                port="$(echo "${line}" | cut -d "/" -f 1)"
                                if echo "${line}" | grep -q ssl/http; then
                                        urlType='https://'
                                        echo "sslscan \"${HOST}\" | tee \"recon/sslscan_${HOST}_${port}.txt\""
                                        echo "cutycapt --url=https://${HOST}:${port} --user-agent='incursore-is-on-your-track' --out=recon/screenshot_https_${HOST}_${port}.jpeg --out-format=jpeg"
                                        #echo "nikto -host \"${urlType}${HOST}:${port}\" -ssl - | tee \"recon/nikto_${HOST}_${port}.txt\""
                                else
                                        urlType='http://'
                                        echo "cutycapt --url=http://${HOST}:${port} --user-agent='incursore-is-on-your-track' --out=recon/screenshot_http_${HOST}_${port}.jpeg --out-format=jpeg"
                                        #echo "nikto -host \"${urlType}${HOST}:${port}\" | tee \"recon/nikto_${HOST}_${port}.txt\""
                                fi
                                if type ffuf >/dev/null 2>&1; then
                                        extensions="$(echo 'index' >./index && ffuf -s -w ./index:FUZZ -mc '200,302' -e '.asp,.aspx,.html,.jsp,.php' -u "${urlType}${HOST}:${port}/FUZZ" 2>/dev/null | awk -vORS=, -F 'index' '{print $2}' | sed 's/.$//' && rm ./index)"
                                        echo "ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '${extensions}' -u \"${urlType}${HOST}:${port}/FUZZ\" | tee \"recon/ffuf_${HOST}_${port}.txt\""
                                fi
                        fi
                done

                # CMS recon
                if [ -f "nmap/Script_TCP_${HOST}.nmap" ]; then
                        cms="$(grep http-generator "nmap/Script_TCP_${HOST}.nmap" | cut -d " " -f 2)"
                        if [ -n "${cms}" ]; then
                                for line in ${cms}; do
                                        port="$(sed -n 'H;x;s/\/.*'"${line}"'.*//p' "nmap/Script_TCP_${HOST}.nmap")"

                                        # case returns 0 by default (no match), so ! case returns 1
                                        if ! case "${cms}" in Joomla | WordPress | Drupal) false ;; esac then
                                                printf "${NC}\n"
                                                printf "${YELLOW}[>>] CMS Recon:\n"
                                                printf "${NC}\n"
                                        fi
                                        case "${cms}" in
                                        Joomla!) echo "joomscan --url \"${HOST}:${port}\" | tee \"recon/joomscan_${HOST}_${port}.txt\"" ;;
                                        WordPress) echo "wpscan --url \"${HOST}:${port}\" --enumerate p | tee \"recon/wpscan_${HOST}_${port}.txt\"" ;;
                                        Drupal) echo "droopescan scan drupal -u \"${HOST}:${port}\" | tee \"recon/droopescan_${HOST}_${port}.txt\"" ;;
                                        esac
                                done
                        fi
                fi
        fi

        # SNMP recon
        if [ -f "nmap/UDP_Extra_${HOST}.nmap" ] && grep -q "161/udp.*open" "nmap/UDP_Extra_${HOST}.nmap"; then
                printf "${NC}\n"
                printf "${YELLOW}> SNMP Recon:\n"
                printf "${NC}\n"
                echo "snmp-check \"${HOST}\" -c public | tee \"recon/snmpcheck_${HOST}.txt\""
                echo "snmpwalk -Os -c public -v1 \"${HOST}\" | tee \"recon/snmpwalk_${HOST}.txt\""

        fi

        # LDAP recon
        if echo "${file}" | grep -q "389/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}> LDAP Recon:\n"
                printf "${NC}\n"
                echo "ldapsearch -x -h \"${HOST}\" -s base | tee \"recon/ldapsearch_${HOST}.txt\""
                echo "ldapsearch -x -h \"${HOST}\" -b \"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d ' ' -f2)\" | tee \"recon/ldapsearch_DC_${HOST}.txt\""
                echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(grep rootDomainNamingContext \"recon/ldapsearch_${HOST}.txt\" | cut -d \\" \\" -f2)\"' \"${HOST}\" -oN \"recon/nmap_ldap_${HOST}.txt\""

        fi

        # SMB recon
        if echo "${file}" | grep -q "445/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}> SMB Recon:\n"
                printf "${NC}\n"
                echo "smbmap -H \"${HOST}\" | tee \"recon/smbmap_${HOST}.txt\""
                echo "smbclient -L \"//${HOST}/\" -U \"guest\"% | tee \"recon/smbclient_${HOST}.txt\""
                if [ "${osType}" = "Windows" ]; then
                        echo "nmap -Pn -p445 --script vuln -oN \"recon/SMB_vulns_${HOST}.txt\" \"${HOST}\""
                elif [ "${osType}" = "Linux" ]; then
                        echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""
                fi
                echo
        elif echo "${file}" | grep -q "139/tcp" && [ "${osType}" = "Linux" ]; then
                printf "${NC}\n"
                printf "${YELLOW}SMB Recon:\n"
                printf "${NC}\n"
                echo "enum4linux -a \"${HOST}\" | tee \"recon/enum4linux_${HOST}.txt\""

        fi

        # Oracle DB recon
        if echo "${file}" | grep -q "1521/tcp"; then
                printf "${NC}\n"
                printf "${YELLOW}[+] Oracle Recon:\n"
                printf "${NC}\n"
                echo "odat sidguesser -s \"${HOST}\" -p 1521"
                echo "odat passwordguesser -s \"${HOST}\" -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"

        fi



        IFS="${origIFS}"

        echo
}

# Run chosen recon commands
runRecon() {
        echo
        printf "${GREEN}[*] Recon the target\n"
        printf "${NC}\n"

        IFS="
"

        mkdir -p recon/

        if [ "$2" = "All" ]; then
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap")"
        else
                reconCommands="$(grep "${HOST}" "nmap/Recon_${HOST}.nmap" | grep "$2")"
        fi

        # Run each line
        for line in ${reconCommands}; do
                currentScan="$(echo "${line}" | cut -d ' ' -f 1)"
                fileName="$(echo "${line}" | awk -F "recon/" '{print $2}')"
                if [ -n "${fileName}" ] && [ ! -f recon/"${fileName}" ]; then
                        printf "${NC}\n"
                        printf "${YELLOW}[+] Starting ${currentScan} session\n"
                        printf "${NC}\n"
                        eval "${line}"
                        printf "${NC}\n"
                        printf "${YELLOW}[-] Finished ${currentScan} session\n"
                        printf "${NC}\n"
                        printf "${YELLOW}--------------------------------------\n"
                fi
        done

        IFS="${origIFS}"

        echo
}

# Print footer with total elapsed time
footer() {

        printf "${GREEN}[!] Finished all scans\n"
        printf "${NC}\n\n"

        elapsedEnd="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
        elapsedSeconds=$((elapsedEnd - elapsedStart))

        if [ ${elapsedSeconds} -gt 3600 ]; then
                hours=$((elapsedSeconds / 3600))
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "${YELLOW}Completed in ${hours} hour(s), ${minutes} minute(s) and ${seconds} second(s)\n"
        elif [ ${elapsedSeconds} -gt 60 ]; then
                minutes=$(((elapsedSeconds % 3600) / 60))
                seconds=$(((elapsedSeconds % 3600) % 60))
                printf "${YELLOW}Completed in ${minutes} minute(s) and ${seconds} second(s)\n"
        else
                printf "${YELLOW}Completed in ${elapsedSeconds} seconds\n"
        fi
        printf "${NC}\n"
}

# Choose run type based on chosen flags
main() {
        assignPorts "${HOST}"

        header

        case "${TYPE}" in
        [Pp]ort) portScan "${HOST}" ;;
        [Ss]cript)
                [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan "${HOST}"
                scriptScan "${HOST}"
                ;;
        [Uu]dp) UDPScan "${HOST}" ;;
        [Vv]ulns)
                [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan "${HOST}"
                vulnsScan "${HOST}"
                ;;
        [Rr]econ)
                [ ! -f "nmap/full_TCP_${HOST}.nmap" ] && portScan "${HOST}"
                [ ! -f "nmap/Script_TCP_${HOST}.nmap" ] && scriptScan "${HOST}"
                recon "${HOST}"
                ;;
        [Aa]ll)
                portScan "${HOST}"
                scriptScan "${HOST}"
                UDPScan "${HOST}"
                vulnsScan "${HOST}"
                recon "${HOST}"
                ;;
        esac

        footer
}

# Ensure host and type are passed as arguments
if [ -z "${TYPE}" ] || [ -z "${HOST}" ]; then
        usage
fi

# Ensure $HOST is an IP or a URL
if ! expr "${HOST}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null && ! expr "${HOST}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
        printf "${RED}\n"
        printf "${RED}Invalid IP or URL!\n"
        usage
fi

# Ensure selected scan type is among available choices, then run the selected scan
if ! case "${TYPE}" in [Nn]etwork | [Pp]ort | [Ss]cript | [Ff]ull | UDP | udp | [Vv]ulns | [Rr]econ | [Aa]ll) false ;; esac then
        mkdir -p "${OUTPUTDIR}" && cd "${OUTPUTDIR}" && mkdir -p nmap/ || usage
        main | tee "incursore_${HOST}_${TYPE}.txt"
else
        printf "${RED}\n"
        printf "${RED}Invalid Type!\n"
        usage
fi
