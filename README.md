# Intrustion Detection System

## Description:

Simple IDS that detects port scans, SYN floods, and ICMP floods. When you close the process it logs each detected suspicious activity in a different file named 'ids_log.txt'. There is also a FLask web dashboards which allows for real-time monitoring of detetced threats.

---------------------------------------------
## Installation:

Install Kali (any linux distribution should work)

Clone the repository to download the repository

**In your first Kali terminal run:**

"pip install -r requirements.txt" to install the python packages

"sudo apt install hping3" to install SYN flood tool

"sudo apt install nmap" to install port scan tool

---------------------------------------------
## Usage:

Type "sudo python3 IDS.py" to run the IDS

**In a different Kali terminal on the same machine run:**

"sudo hping3 -S -p 80 -i u1000 127.0.0.1" - Sends SYN flood packets to the localhost (you)

"sudo ping -f 127.0.0.1" - Sends ICMP flood packets to localhost

"sudo nmap -p 1-1000 127.0.0.1" - Port scans the localhost

---------------------------------------------
## Result:

Watch your first Kali terminal as the alerts will be going off.

You can also check out the Flask dashboard by typing http://127.0.0.1:5000 in any web browser for a more readable experience



