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

## Installation

Clone the repository and enter the folder
``` bash
git clone https://github.com/LeucoByte/BoxScanner.git
cd BoxScanner
```
Make the script executable
``` bash
chmod +x boxscanner.sh
```
Quick test / help
``` bash
bash boxscanner.sh --help
```
Simple example usage for beginners:
```
bash boxscanner.sh --target 10.10.11.79 --dns-wordlist /path/to/your/dns/wordlist/wordlist.txt --web-wordlist /path/to/your/web/wordlist/other_wordlist.txt -o output_name
```
