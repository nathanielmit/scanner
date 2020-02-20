import argparse
from scapy.layers.inet import traceroute
from scapy.all import *
import sys
import re

ip_format = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
ip_with_subnet = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}$")
parser = argparse.ArgumentParser(description='Port Scanner')
parser.add_argument('-filename', type=argparse.FileType('r'))
parser.add_argument('-ip', action="store", dest="ip")
parser.add_argument('-port', action="store", dest="ports")
parser.add_argument('-protocol', action="store", dest="protocols")
parser.add_argument('--traceroute', dest='tr', action='store_true')
args = parser.parse_args()

ports = [80]
protocols = ["icmp"]
tr = False
ips = []
ip = ""
output = "<html>\n<head><h1>Scan Output</h1></head>\n<body>\n"
end_output = "</body></html>"

if args.ports:
    ports=args.ports
    ports = ports.split(",")
    for i in range(len(ports)):
        ports[i] = int(ports[i])

if args.protocols:
    protocols=args.protocols
    protocols = protocols.split(",")

if args.ip:
    ip=args.ip.rstrip()
    ip = ip.split(",")
    for i in ip:
        if ip_format.match(i):
            ips.append(i)

if args.tr:
    tr = args.tr

if args.filename:
    with args.filename as f:
        ip_not_found = True
        for line in f:
            line=line.rstrip()
            if ip_format.match(line):
                ip_not_found = False
                ips.append(line)
            else:
                print(line, "is not a valid ip")
            
        if ip_not_found:
            print("There are no valid IPs in that file")

if len(sys.argv) == 1:
    print("no args, start GUI")
    # there were no arguments, use GUI

for ip in ips:
    if tr != True:
        for port in ports:
            if "tcp" in protocols:
                p=sr1(IP(dst=ip)/TCP(dport=port),timeout=2)
                if p != None:
                    output = output + "<p>" + ip + " at port " + str(port) + " using TCP is open!</p>\n"
                    output = output + "<p>\n" + str(p.show(dump=True)) + "\n</p>\n"
                else:
                    output = output + "<p>" + ip + " at port " + str(port) + " using TCP did not reply!</p>\n"
                
            if "udp" in protocols:
                p=sr1(IP(dst=ip)/UDP(dport=port),timeout=2)
                if p != None:
                    output = output + "<p>" + ip + " at port " + str(port) + " using UDP is open!</p>\n"
                    output = output + "<p>\n" + str(p.show(dump=True)) + "\n</p>\n"
                else:
                    output = output + "<p>" + ip + " at port " + str(port) + " using UDP did not reply!</p>\n"

            if "icmp" in protocols:
                p=sr1(IP(dst=ip)/ICMP(),timeout=2)
                if p != None:
                    output = output + "<p>" + ip + " using ICMP is open!</p>\n"
                    output = output + "<p>\n" + str(p.show(dump=True)) + "\n</p>\n"
                else:
                    output = output + "<p>" + ip + " at port " + str(port) + " using ICMP did not reply!</p>\n"
                    
    else:
        p=sr(IP(dst=ip,ttl=(1,30))/ICMP(), timeout=2)
        output = output + "<p> Traceroute to " + ip + "</p>\n<p>"
        output = output + str(p).replace("<","").replace(">","") +  "</p>\n"

output = output + end_output
f = open('scan_output.html','w')
f.write(output)
f.close()
