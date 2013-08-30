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


#############################
# # Simple TCP client stack ##
#############################

class myTCP_client(TCP_client):
    
    def parse_args(self, ip, port, request, *args, **kargs):
#         self.request = request
#         self.dst = iter(Net(ip)).next()
#         self.dport = port
#         self.sport = random.randrange(0, 2 ** 16)
#         self.l4 = IP(dst=ip) / TCP(sport=self.sport, dport=self.dport, flags=0,
#                                  seq=random.randrange(0, 2 ** 32))
#         self.src = self.l4.src
#         self.swin = self.l4[TCP].window
#         self.dwin = 1
#         self.rcvbuf = ""
#         bpf = "host %s  and host %s and port %i and port %i" % (self.src,
#                                                                 self.dst,
#                                                                 self.sport,
#                                                                 self.dport)
# 
# #        bpf=None
#         Automaton.parse_args(self, filter=bpf, **kargs)
        self.request = request
        TCP_client.parse_args(self, ip, port, **kargs)

    
#     def master_filter(self, pkt):
#         return (IP in pkt and
#                 pkt[IP].src == self.dst and
#                 pkt[IP].dst == self.src and
#                 TCP in pkt and
#                 pkt[TCP].sport == self.dport and
#                 pkt[TCP].dport == self.sport and
#                 self.l4[TCP].seq >= pkt[TCP].ack and  # XXX: seq/ack 2^32 wrap up
#                 ((self.l4[TCP].ack == 0) or (self.l4[TCP].ack <= pkt[TCP].seq <= self.l4[TCP].ack + self.swin)))
# 
# 
#     @ATMT.state(initial=1)
#     def START(self):
#         print "START"
#         pass
# 
#     @ATMT.state()
#     def SYN_SENT(self):
#         print "SYN_SENT"
#         pass
#     
#     @ATMT.state()
#     def ESTABLISHED(self):
#         print "EST"
#         pass
# 
#     @ATMT.state()
#     def LAST_ACK(self):
#         print "LAST_ACK"
#         pass
# 
#     @ATMT.state(final=1)
#     def CLOSED(self):
#         print "CLOSED"
#         pass
# 
#     
#     @ATMT.condition(START)
#     def connect(self):
#         print "START cond: connect"
#         raise self.SYN_SENT()
#     @ATMT.action(connect)
#     def send_syn(self):
#         print "START action: connect"
#         self.l4[TCP].flags = "S"
#         self.send(self.l4)
#         self.l4[TCP].seq += 1
# 
# 
#     @ATMT.receive_condition(SYN_SENT)
#     def synack_received(self, pkt):
#         print "SYN_SENT: cond: synack"
#         print pkt.summary()
#         if pkt[TCP].flags & 0x3f == 0x12:
#             raise self.ESTABLISHED().action_parameters(pkt)
#     @ATMT.action(synack_received)
#     def send_ack_of_synack(self, pkt):
#         print "SYN_SENT: action: send ack"
#         self.l4[TCP].ack = pkt[TCP].seq + 1
#         self.l4[TCP].flags = "A"
#         self.send(self.l4)
# 
#     @ATMT.receive_condition(ESTABLISHED)
#     def incoming_data_received(self, pkt):
#         print "EST: cond: incoming data?"
#         print pkt.summary()
#         if not isinstance(pkt[TCP].payload, NoPayload) and not isinstance(pkt[TCP].payload, conf.padding_layer):
# #             print "TCP flags: ", pkt[TCP].flags
# #             if pkt[TCP].flags & 0x4: # RST
# #                 print "ESTABLISHED: RST received... did you update iptables?"
# #                 raise self.CLOSED().action_parameters(pkt)
#              
#             # else ok
#             raise self.ESTABLISHED().action_parameters(pkt)
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
    
#     @ATMT.ioevent(TCP_client.ESTABLISHED, name="tcp", as_supersocket="tcplink")
#     def outgoing_data_received(self, fd):
#         print "EST: event: outgoing data"
#         raise self.ESTABLISHED().action_parameters(fd.recv())
#     @ATMT.action(outgoing_data_received)
#     def send_data(self, d):
#         print "EST: action: send data: ", self.l4.summary()
#         self.l4[TCP].flags = "PA"
#         self.send(self.l4 / d)
#         self.l4[TCP].seq += len(d)
#             
#     @ATMT.receive_condition(ESTABLISHED)
#     def reset_received(self, pkt):
#         print "EST: cond: rst?"
#         print pkt.summary()
#         if pkt[TCP].flags & 4 != 0:
#             raise self.CLOSED()
# 
#     @ATMT.receive_condition(ESTABLISHED)
#     def fin_received(self, pkt):
#         print "EST: cond: fin?"
#         print pkt.summary()
#         if pkt[TCP].flags & 0x1 == 1:
#             raise self.LAST_ACK().action_parameters(pkt)
#     @ATMT.action(fin_received)
#     def send_finack(self, pkt):
#         print "EST: action: send finack"
#         self.l4[TCP].flags = "FA"
#         self.l4[TCP].ack = pkt[TCP].seq + 1
#         self.send(self.l4)
#         self.l4[TCP].seq += 1
# 
#     @ATMT.receive_condition(LAST_ACK)
#     def ack_of_fin_received(self, pkt):
#         print "LAST_ACK: cond: ack of fin?"
#         print pkt
#         print pkt.summary()
#         if pkt[TCP].flags & 0x3f == 0x10:
#             raise self.CLOSED()

    # --- zerowindow stuff
    pkgcount = 0
    maxpkgcount = 10
    zwcount = 0

    @ATMT.state()
    def RECEIVE_N(self):
        print "RECEIVE_N"
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
    # after n packets, we change to SEND_ZEROWINDOW
    @ATMT.receive_condition(RECEIVE_N)
    def pkg_count_exceeded(self, pkt):
        ''' When in ESTABLISHED or in RECEIVE_N, next packages changes state to ReceiveN'''
        print "RECEIVE_N: cond: pkg count exceeded? (%d > %d?)"%(self.pkgcount, self.maxpkgcount)
        if self.pkgcount > self.maxpkgcount:
            raise self.SEND_ZEROWINDOW().action_parameters(pkt)
        else:
            raise self.RECEIVE_N().action_parameters(pkt)        
    @ATMT.action(pkg_count_exceeded)    
    def count_received_data(self, pkt):
        print "RECEIVE_N: action: counting"
        print " - fake EST following this line :-)"
        self.receive_data( pkt )
        self.pkgcount += 1
                   
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
#myTCP_client.graph()

s = myTCP_client( ServerName, ServerPort, "GET %s HTTP/1.0\n\n" % ServerFile, debug=5)
s.run()

