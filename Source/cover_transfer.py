from scapy.all import *
import sys
import os
import argparse

parser = argparse.ArgumentParser(description='Wei & Fred COMP8505 Assignment 1 Covert Channel')
parser.add_argument('-mode',dest='mode',help='client or server')
parser.add_argument('-sIP',dest='src_ip',help='srouce ip')
parser.add_argument('-sPort', dest='src_port', help='source port')
parser.add_argument('-dIP',dest='dst_ip',help='destination ip')
parser.add_argument('-dPort',dest='dst_port',help='destination port')
args=parser.parse_args()


input_message=None
rec_que=[]

def client_input():
    "Recieve user input"
    global input_message
    input_message=input('What\' your message?')

def construct(msg):
   
    "Contrust packet"
    #msg = input_message
    sport = int(args.src_port)
    dport = int(args.dst_port)
    enc_msg = ord(msg)
    if sport | dport is not None:
        packet = IP(dst=args.dst_ip,src=args.src_ip,ttl=enc_msg)/TCP(sport=sport,dport=dport,flags="SA")
    else:
        print('Source port or destination port is not provided')
    return packet

def client():
    global input_message
    for i in input_message:
        tmp = construct(i)
        print('sending: ',i)
        send(tmp)
        time.sleep(RandNum(2,3))
        
def renovate_tcp(packet: Packet):
    flags=packet['TCP'].flags
    if flags == 0x0012:
        rec_que.append(chr(packet['IP'].ttl))
        print('Receive: ',chr(packet['IP'].ttl))
        
        print('Overall:'+''.join(rec_que))
    
def server():
    print('Receiving packets')
    sniff(filter="tcp",prn=renovate_tcp)

if args.mode == 'client':
    client_input()
    client()
elif args.mode == 'server':
    server()
