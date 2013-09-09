ScapyTest
=========

specialized scapy scripts for network stuff

Scapy is cool - check it at their [homepage](http://www.secdev.org/projects/scapy/).


A note on TCP with scapy:
-------------------------

When working with TCP connections, the linux kernel will detect it and kill your connection 
by sending a RST TCP packet to the destination host

This is obvious when looking in wireshark for the packets scapy sends.

It is circumvented by something like this

* export MYIP='ipaddress of host running this program'
* sudo /sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -s $MYIP -j DROP

