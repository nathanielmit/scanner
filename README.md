# scanner
This is a basic network scanner that can be used to check for open ports at specified IP addresses.

Tags:
-ip IP1,IP2,...
-port PORT1,PORT2,...
-traceroute
-protocol tcp,udp,icmp
-filename FILENAME

The ip tag takes a comma-separated list of IP addresses to be scanned.
The port tag takes a comma-separated list of ports to be scanned at each ip.
The traceroute overrides the ports and performs a traceroute to each ip using ICMP packets.
The protocol can be specified using the protocol tag
The filename tag should include a file path with newline-separated ip addresses.

The scanner prints the output to an html file titled 'scanner_output.html' that can be opened in a web browser for easy viewing.

Example use:
python3 port_scanner.py -ip 192.168.1.112,192.168.1.113 -protocol tcp,udp,icmp -port 22,53,80,443
