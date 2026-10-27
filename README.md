Network Intrusion Detection System (NIDS)

Overview

This project is a basic Network Intrusion Detection System developed using Python as part of my CodeAlpha Cybersecurity Internship.

The system uses Scapy to capture TCP packets and monitor repeated connection attempts. It tracks TCP SYN packets based on their source IP addresses and destination ports. When the number of attempts reaches a predefined threshold, the system generates an alert and saves it to a log file.

Features

Captures TCP network packets using Scapy.

Identifies TCP SYN packets.

Tracks connection attempts by source IP address and destination port.

Generates alerts when the attempt count reaches 10.

Displays alerts in the terminal.

Saves alerts in alerts.log for later review.

Technologies Used

Python

Scapy

TCP/IP networking

File handling and logging

Requirements

Python 3

Scapy

Npcap on Windows for packet capture, where required
