from sys import argv

script, filename = argv

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy
import scapy.all

from scapy.all import rdpcap, TCP, Raw

sPort = []
dPort = []
senderPackets = []
receiverPackets = []
senderBytes = []
receiverBytes = []
senderACK = []
receiverACK = []
outOfseqSender = []
outOfseqReceiver = []
seqNumSender = []
seqNumReceiver = []
seqNum = []
senderRetransmit = [] 
receiverRetransmit = []
retransmit = []
totalBytes = []
usefulBytes = []
usefulPackets = []
startTime = []
stopTime = []
cwnd = []
cwnd_max = []
receiverWindow = []  
SYN = 2
ACK = 16
PSH = 24
i = 0
count = 0



pcap = rdpcap(filename)

for packet in pcap:
    try:
        if packet[TCP].flags == SYN:
            sPort.append(packet[TCP].sport)
            dPort.append(packet[TCP].dport)
            senderPackets.append(0)
            receiverPackets.append(0)
            senderACK.append(0)
            receiverACK.append(0)
            outOfseqSender.append(0)
            outOfseqReceiver.append(0)
            seqNumSender.append(packet[TCP].seq)
            seqNumReceiver.append(0)
            senderBytes.append(0)
            receiverBytes.append(0)
            senderRetransmit.append(0)
            receiverRetransmit.append(0)
            startTime.append(packet.time)
            stopTime.append(0)
            totalBytes.append(len(packet))
            usefulBytes.append(0)
            usefulPackets.append(0)
            cwnd_max.append(0)
            receiverWindow.append(0)
            
            
        if packet[TCP].sport in sPort:
            
            stopTime[sPort.index(packet[TCP].sport)] = packet.time
            if packet[TCP].flags != SYN:
                totalBytes[sPort.index(packet[TCP].sport)] = totalBytes[sPort.index(packet[TCP].sport)] + len(packet)
            # Retransmission
            if packet[TCP].seq in seqNum:
                if packet[TCP].flags not in (ACK, PSH):
                    #print(packet[TCP].flags)
                    senderRetransmit[sPort.index(packet[TCP].sport)] = senderRetransmit[sPort.index(packet[TCP].sport)] + 1
            else:
                seqNum.append(packet[TCP].seq)
            # Out of Sequence at Sender
            if packet[TCP].seq < seqNumSender[sPort.index(packet[TCP].sport)]:
                outOfseqSender[sPort.index(packet[TCP].sport)] = outOfseqSender[sPort.index(packet[TCP].sport)] + 1
            else: 
                seqNumSender[sPort.index(packet[TCP].sport)] = packet[TCP].seq
                try:
                    usefulBytes[sPort.index(packet[TCP].sport)] = usefulBytes[sPort.index(packet[TCP].sport)] + len(packet[Raw])
                except:
                    pass
            
            # Number of Packets sent by the Sender
            senderPackets[sPort.index(packet[TCP].sport)] = senderPackets[sPort.index(packet[TCP].sport)] + 1
            
            # Number of ACK sent by Sender
            if packet[TCP].flags == ACK:
               senderACK[sPort.index(packet[TCP].sport)] = senderACK[sPort.index(packet[TCP].sport)] + 1
            
            try:
            # Bytes sent by the Sender
                #print(len(packet))
                senderBytes[sPort.index(packet[TCP].sport)] = senderBytes[sPort.index(packet[TCP].sport)] + len(packet[Raw])
                usefulPackets[sPort.index(packet[TCP].sport)] = usefulPackets[sPort.index(packet[TCP].sport)] + 1
                if len(packet[Raw]) > cwnd_max[sPort.index(packet[TCP].sport)]:
                    cwnd_max[sPort.index(packet[TCP].sport)] = len(packet[Raw])
            except:
                pass
    
        elif packet[TCP].sport in dPort:
            
            receiverWindow[sPort.index(packet[TCP].dport)] = receiverWindow[sPort.index(packet[TCP].dport)] + packet[TCP].window
            stopTime[sPort.index(packet[TCP].dport)] = packet.time
            totalBytes[sPort.index(packet[TCP].dport)] = totalBytes[sPort.index(packet[TCP].dport)] + len(packet)

            # Retransmission
            if packet[TCP].seq in seqNum:
                if packet[TCP].flags not in (ACK,PSH):
                    #print(packet[TCP].flags)
                    receiverRetransmit[sPort.index(packet[TCP].dport)] = receiverRetransmit[sPort.index(packet[TCP].dport)] + 1
            else:
                seqNum.append(packet[TCP].seq)

            # Out of Sequence at Receiver
            if packet[TCP].seq < seqNumReceiver[sPort.index(packet[TCP].dport)]:
                outOfseqReceiver[sPort.index(packet[TCP].dport)] = outOfseqReceiver[sPort.index(packet[TCP].dport)] + 1
            else: 
                seqNumReceiver[sPort.index(packet[TCP].dport)] = packet[TCP].seq
                try:
                    usefulBytes[sPort.index(packet[TCP].dport)] = usefulBytes[sPort.index(packet[TCP].dport)] + len(packet[Raw])
                except:
                    pass
            
            # Number of Packets sent by the Receiver                               
            receiverPackets[sPort.index(packet[TCP].dport)] = receiverPackets[sPort.index(packet[TCP].dport)] + 1
                 
            # Number of ACK sent by Receiver
            if packet[TCP].flags == ACK:
                receiverACK[sPort.index(packet[TCP].dport)] = receiverACK[sPort.index(packet[TCP].dport)] + 1
            try:
            # Bytes sent by the Receiver
                receiverBytes[sPort.index(packet[TCP].dport)] = receiverBytes[sPort.index(packet[TCP].dport)] + len(packet[Raw])
            except:
                pass
        
    except:
        continue

while i < len(sPort):
    gp = 0
    tp = 0
    rw = 0
    rw = receiverWindow[i]/receiverPackets[i]
    cwnd.append(senderBytes[i]/usefulPackets[i])
    tp = totalBytes[i]/(stopTime[i]-startTime[i])
    gp = usefulBytes[i]/(stopTime[i]-startTime[i])
    print('<begin: TCP Flow '+str(i+1))
    retransmit.append(senderRetransmit[i] + receiverRetransmit[i])
    print('# packets sent by the sender: '+str(senderPackets[i]))
    print('# packets sent by the receiver: '+str(receiverPackets[i]))
    print('# bytes sent by the sender: '+str(senderBytes[i]))
    print('# bytes receiver by the receiver: '+str(receiverBytes[i]))
    print('# ACKs sent by the sender: '+str(senderACK[i]))
    print('# ACKs sent by the receiver: '+str(receiverACK[i]))
    print('Largest congestion window size at sender: '+str(cwnd_max[i]))
    print('Average congestion window size at sender: '+str(cwnd[i]))
    print('Average receiver window size: '+str(rw))
    print('# retransmissions: '+str(retransmit[i]))
    print('# Out of Order packets: '+str(outOfseqSender[i]+outOfseqReceiver[i]))
    print('Throughput: '+str(tp))
    print('Goodput: '+str(gp))
    i = i + 1
    print('END FLOW>\n\n')



 
