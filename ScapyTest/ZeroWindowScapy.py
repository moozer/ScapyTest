#!/usr/bin/env python

# Before running this program, you may need to change stuff in IP tables
# see: http://stackoverflow.com/questions/9058052/unwanted-rst-tcp-packet-with-scapy
# command:
# 	export MYIP='ipaddress of host running this program'
# 	sudo /sbin/iptables -A OUTPUT -p tcp --tcp-flags RST RST -s $MYIP -j DROP
#
# 1. connects to webserver
# 2. after 10 packages, start sending zerowindow tcp replies

from scapy.all import *
from scapy.layers.inet import TCP_client, TCP
#from scapy.automaton import ATMT
#from scapy.packet import Raw


#############################
# # Simple TCP client stack ##
#############################

class ZeroWindow_TCP_client(TCP_client):
    
    def parse_args(self, ip, port, request, *args, **kargs):
        ''' adding the request parameter '''
        self.request = request
        TCP_client.parse_args(self, ip, port, **kargs)

    # - there is a bug in the stock version of TCP_client, so we overload here.
    #
    @ATMT.action(TCP_client.incoming_data_received)
    def receive_data(self, pkt):
        print "EST: action: receive data"

        print " - TCP flags: ", pkt[TCP].flags
        # data = str(pkt[TCP].payload)
        print " - recv: ", pkt[TCP].summary()
        
        if not Raw in pkt:
            print " - no raw data in packet."
            data = ""
        else:
            data = str(pkt[TCP][Raw].load)
            
        # print "raw load: %d"%len(pkt[TCP][Raw].load)
        # print "data recv: %d"%len(data)
        if data and self.l4[TCP].ack == pkt[TCP].seq:
            self.l4[TCP].ack += len(data)
            self.l4[TCP].flags = "A"
            self.send(self.l4)
            print " - send: ", self.l4.summary()
            self.rcvbuf += data
            if pkt[TCP].flags & 8 != 0:  # PUSH
                self.oi.tcp.send(self.rcvbuf)
                self.rcvbuf = ""
        else:
            print " - recv: no data or bad ack/seq"
    

    # --- zerowindow stuff
    pkgcount = 0
    maxpkgcount = 10
    zwcount = 0

    @ATMT.state()
    def RECEIVE_N(self):
        print "RECEIVE_N"
        print "- if it hangs here, perhaps you need to fix the iptables"
        pass

    @ATMT.state()
    def SEND_ZEROWINDOW(self):
        print "SEND_ZEROWINDOW"
        pass

    # we want to react properly to resets always
    # all received pkg gets checked for RST
    @ATMT.receive_condition(RECEIVE_N)
    @ATMT.receive_condition(SEND_ZEROWINDOW)
    def rst_received(self, pkt):
        ''' When in ESTABLISHED or in RECEIVE_N, next packages changes state to ReceiveN'''
        print "(multiple): cond: rst_received?"
        if pkt[TCP].flags & 0x4 != 0: # RST
            print " - RST received... did you update iptables?"
            raise self.CLOSED().action_parameters(pkt)

    # when entering the ESTABLISHED state, send a packet.
    @ATMT.condition(TCP_client.ESTABLISHED)
    def OnEstablished(self):
        print "Connection established"
        print " - send request: >%s<" % self.request
        self.l4[TCP].flags = "PA"
        self.send(self.l4 / self.request)
        self.l4[TCP].seq += len(self.request)

    # when ESTABLISHED, any packet recevied triggers a transition to RECEIVE_N    
    @ATMT.receive_condition(TCP_client.ESTABLISHED)
    def first_pkg_received(self, pkt):
        ''' When in ESTABLISHED or in RECEIVE_N, next packages changes state to ReceiveN'''
        print "EST: cond: first pkg received?"
        print " - switching to RECEIVE_N"
        raise self.RECEIVE_N().action_parameters(pkt)
    @ATMT.action(first_pkg_received)
    def init_count_received_data(self, pkt):
        print "EST: action: init pkg count, send request"
        self.receive_data( pkt )
        self.pkgcount = 1
        print " - current count", self.pkgcount

    # when RECEIVE_N, we count the packages and ACK correctly.
    @ATMT.receive_condition(RECEIVE_N)
    def pkg_received(self, pkt):
        ''' When in ESTABLISHED or in RECEIVE_N, next packages changes state to ReceiveN'''
        print "RECEIVE_N: cond: pkg received? (%d > %d?)"%(self.pkgcount, self.maxpkgcount)
        if self.pkgcount <= self.maxpkgcount:
            raise self.RECEIVE_N().action_parameters(pkt)        
    @ATMT.action(pkg_received)    
    def count_received_data(self, pkt):
        print "RECEIVE_N: action: counting"
        print " - fake EST following this line :-)"
        self.receive_data( pkt )
        self.pkgcount += 1
                   
    # when RECEIVE_N, we count the packages and ACK correctly.
    # after n packets, we change to SEND_ZEROWINDOW
    @ATMT.receive_condition(RECEIVE_N)
    def pkg_count_exceeded(self, pkt):
        ''' When in ESTABLISHED or in RECEIVE_N, next packages changes state to ReceiveN'''
        print "RECEIVE_N: cond: pkg count exceeded? (%d > %d?)"%(self.pkgcount, self.maxpkgcount)
        if self.pkgcount > self.maxpkgcount:
            raise self.SEND_ZEROWINDOW().action_parameters(pkt)
    @ATMT.action(pkg_count_exceeded)    
    def receive_excess_data(self, pkt):
        print "RECEIVE_N: action: receive_excess_data"
        print " - fake EST following this line :-)"
        self.receive_data( pkt )
        self.pkgcount += 1
        self.zwcount = 0

    # when in SEND_ZEROWINDOW, and packets received trigger an ACK with zero window (forever)
    @ATMT.receive_condition(SEND_ZEROWINDOW)
    def pkg_received_zw(self, pkt):
        ''' When in ESTABLISHED or in RECEIVE_N, next packages changes state to ReceiveN'''
        print "SEND_ZEROWINDOW: cond: always change state"
        raise self.SEND_ZEROWINDOW().action_parameters(pkt)

    @ATMT.action(pkg_received_zw)
    def send_zw(self, pkt):
        print "SEND_ZEROWINDOW: action: send zerowindow pkg"
        self.zwcount += 1
        self.pkgcount += 1
        print " - count:", self.zwcount
        
        data = str(pkt[TCP][Raw].load)
        print " - recv: ", pkt[TCP].summary()

        if data and self.l4[TCP].ack == pkt[TCP].seq:
            self.l4[TCP].ack += 0
            self.l4[TCP].flags = "A"
            self.l4[TCP].window = 0
            self.send(self.l4)
            print " - send: ", self.l4.summary()
            self.rcvbuf += data
            if pkt[TCP].flags & 8 != 0:  # PUSH
                self.oi.tcp.send(self.rcvbuf)
                self.rcvbuf = ""
        else:
            print " - recv: no data or bad ack/seq"
            

# # simple webpage
# ServerName = "eal.dk"
# ServerPort = 80
# ServerFile = "/"
            
# some random debian package server til dowload something big
ServerName = "caesar.acc.umu.se"
ServerPort = 80
ServerFile = "/debian-cd/7.1.0/amd64/iso-cd/debian-7.1.0-amd64-netinst.iso"

# include this if you want an overview of the state machine.
#ZeroWindow_TCP_client.graph()

s = ZeroWindow_TCP_client( ServerName, ServerPort, "GET %s HTTP/1.0\n\n" % ServerFile, debug=5)
s.run()

