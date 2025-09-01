# BoxScanner
BoxScanner is a basic Bash script that automates common Hack The Box reconnaissance tasks. It scans for open ports and vulnerabilities, enumerates web directories and subdomains, and organizes the output neatly into structured folders, including a notes file for your personal observations.

The script performs the following steps:
  1) Checks if the target is online.
  2) Runs Nmap to detect open ports and potential vulnerabilities.
  3) Uses Gobuster to find web directories and subdomains.
  4) Automatically adds unresolved hostnames to /etc/hosts.
  5) Creates a structured output folder:
        nmap/ → Full Nmap scans and neatly formatted results
        gobuster/ → DNS and web enumeration results.
        notes.txt → empty file for jotting down personal notes.

Make sure you have the following installed:
  - Bash
  - Nmap (sudo apt install nmap)
  - Gobuster (sudo apt install gobuster) version 3.8 recommended for proper DNS pretty print
  - Wordlists (seclists recommended)

Example with the HTB machine "Era": 
bash boxscanner.sh --target 10.10.11.79 \
                  --dns-wordlist /usr/share/seclists/Discovery/DNS/namelist.txt \
                  --web-wordlist /usr/share/wordlists/dirb/common.txt \
                  -t 200 \
                  -o era              
