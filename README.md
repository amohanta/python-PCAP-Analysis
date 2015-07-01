# python-PCAP-Analysis
PCAP files are analysed using python. DNS delays, congestion window sizes, through put and good put are calculated.

SCAPY:
We have imported scapy library in python for reading the .pcap file, worked on a Linux machine.
scapy can be downloaded from http://www.secdev.org/projects/scapy/
scapy works on Python 2.X.X.
For installation - cd /path
python setup.py install


Running the script:
cd /path
python tcpstream.py test.pcap

Components:

tcpstream.py - contains the python code for Task 1.
tcpstream.txt - contains the result for Task 1.
Assignment2 - Task 2.pdf contains the result and calculation for Task 2.


Observations:

Calculation of congestion window size at sender:
Congestion window gives us the amount of data sender is willing to send based on the congestion it estimates.
We came to the conclusion that congestion window at an instant will be equivalent the amount of data it actually sends.
Our congestion window values, cwnd were taken from the number of bytes the sender transmits per transmission.

Calculation of bytes/packets sent by sender/receiver:
Flows were differentiated by their sender/receiver port numbers.
A flow is said to have begun when the sender sends a packet with SYN flag.
Lists were updated after each packet in the flow.

Calculation of Out-of-order and Retransmitted packets:
A packet is said to be out-of-order when it’s sequence number is less than the maximum of sequence numbers sent before.
If a sequence number already exists in the list of sequence numbers, it was counted as retransmitted packet. [PSH, ACK]s were ignored in this process.

Calculation of throughput and goodput:
For throughput, all the packets transmitted by sender and receiver  were considered.
For goodput, only the packets with payload barring the retransmission were considered.

