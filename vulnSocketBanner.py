import socket
import sys
import os

def getBanner(ip, port):
    try:
        socket.setdefaulttimeout = 1
        conn = socket.socket()
        conn.connect((ip, port))
        banner = conn.recv(1024)
        return banner
    except Exception, e:
        print("[!] getBanner on "+ str(ip) +" : "+str(e))
        return

def checkVulns(banner):
    try:
        known_vulns = open("known_vulns.txt","r")
        for line in known_vulns.readlines():
            if line.strip("\n") in banner:
                print("[!!] vulnerability known : " + banner)
    except:
        return

def main():
    # for x in range(1,255):
    #     ip = "192.168.0." + str(x)
    #     getBanner(ip, 80)

    if len(sys.argv) == 2:
        ip = sys.argv[1]
    else:
        ip = "ftp.ovh.com"

    banner = getBanner(ip,21)
    checkVulns(banner)

main()