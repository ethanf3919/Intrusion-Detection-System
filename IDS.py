#!/usr/bin/python3
"""
Author: Ethan Forrest
OS: Kali
"""

from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time
import logging
from flask import Flask, render_template, jsonify

# logging
logging.basicConfig(filename='ids_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(message)s')

# for tracking activity/alerts
port_scans = defaultdict(list)
syn_counts = defaultdict(int)
icmp_counts = defaultdict(int)
alerts = []
recent_port_scans = defaultdict(lambda: {'count': 0, 'timestamp': time.time()})

app = Flask(__name__)

# port scan detection function
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()
        
        # track ports
        port_scans[src_ip].append((dst_port, current_time))
        
        # create alert
        if current_time - recent_port_scans[src_ip]['timestamp'] < 5:
            recent_port_scans[src_ip]['count'] += 1
        else:
            if recent_port_scans[src_ip]['count'] > 0:
                alert_message = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(recent_port_scans[src_ip]['timestamp']))} - Port Scan from {src_ip} ({recent_port_scans[src_ip]['count']})"
                print(alert_message)
                logging.info(alert_message)
                alerts.append({"type": "Port Scan", "source_ip": src_ip, "count": recent_port_scans[src_ip]['count'],
                               "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(recent_port_scans[src_ip]['timestamp']))})
            
            recent_port_scans[src_ip] = {'count': 1, 'timestamp': current_time}

# syn flood detection function
def detect_syn_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == "S":  # 'S' flag for SYN
            src_ip = packet[IP].src
            syn_counts[src_ip] += 1
            if syn_counts[src_ip] > 100:  # 100 threshold for alert
                alert_message = f"Possible SYN flood from {src_ip}"
                print(alert_message)
                logging.info(alert_message)
                alerts.append({"type": "SYN Flood", "source_ip": src_ip, "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))})

# icmp flood detection function
def detect_icmp_flood(packet):
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        icmp_counts[src_ip] += 1
        
        if icmp_counts[src_ip] > 50:  # 50 threshold for alert
            alert_message = f"Possible ICMP flood from {src_ip}"
            print(alert_message)
            logging.info(alert_message)
            alerts.append({"type": "ICMP Flood", "source_ip": src_ip, "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))})

def main():
    # checks each packet with each function
    def process_packet(packet):
        detect_port_scan(packet)
        detect_syn_flood(packet)
        detect_icmp_flood(packet)

    # sniffing and apply function
    sniff(iface="lo", prn=process_packet, store=0)

"""
___________
Flask
"""

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/alerts')
def get_alerts():
    return jsonify(alerts)

def start_dashboard():
    app.run(host='0.0.0.0', port=5000)

if __name__ == "__main__":
    # flask dashboard
    from threading import Thread
    dashboard_thread = Thread(target=start_dashboard)
    dashboard_thread.daemon = True
    dashboard_thread.start()

    main()
