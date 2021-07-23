from controller import SDNApplication

# Ryu Imports
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

import os

#tm task=firewall

class FirewallApplication(SDNApplication):
    def __init__(self, *args, **kwargs):
        super(FirewallApplication, self).__init__(*args, **kwargs)
        self.info("Firewall Application")
        # Initialise mac adress table
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        # parse msg for info
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Define OF switch identifier + set mac adress table for switch
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Get protocol, source and dest with Ryu packet library
        eth_pkt = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        in_port = msg.match["in_port"]

        self.logger.info("Packet in. Switch: %s, Source: %s, Destination: %s, In Port: %s", dpid, src, dst, in_port)

        # Firewall setup
        blocked = False
        dir = os.path.dirname(__file__)  # Relative path to dir

        with open(dir + "/.blocklist/mac_blocklist.txt", "r") as mac_blocklist:
            if src in mac_blocklist:
                print("Found!")
        
        #ip_blocklist = open(dir + "/.blocklist/ip_blocklist.txt", "r")

        # Compare mac adress to blocklist

        # If contained, deny access + flow rule to disallow future access (Faster, controller not needed)

        # Compare IP adress to blocklist

        # Close resources
        mac_blocklist.close
        #ip_blocklist.close

        # Learn mac adress to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.set_flow(datapath, match, actions, 1)
            self.logger.info("New flow rule set")

        # Construct out packet
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=msg.data)
        # Send packet out
        datapath.send_msg(out)
