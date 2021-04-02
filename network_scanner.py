#!/usr/bin/env python3
import scapy.all as scapy
import argparse

def get_user_input():
    Parser = argparse.ArgumentParser(prog="python3 ns4.py", description="This program scans the network address")
    Parser.add_argument("-t","--target",dest="Target",help="To input IP Address")
    options= Parser.parse_args()

    if not options.Target:
        Parser.error("Please enter the IP Address, For more information use -h or --help")
    else:
        pass

    ip_address = options.Target
    scan_network(ip_address)

def scan_network(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    request_answer = scapy.srp(arp_broadcast,timeout=1,verbose=False)[0]
    clients_list = []

    for e_client in request_answer:
        clients_dict= {"IP":e_client[0].pdst,"MAC":e_client[0].hwsrc}
        clients_list.append(clients_dict)
    
    result(clients_list)

def result(clients_list):
    print("IP \t\t\t MAC Address")
    print("--------------------------------------")
    for clients in clients_list:
        print(clients["IP"],"\t\t",clients["MAC"])
        

get_user_input()
