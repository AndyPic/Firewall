from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ether_types, arp, ethernet, ipv4
from termcolor import colored

import os, array, ipaddress

#tm task=firewall


class FirewallApplication(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(FirewallApplication, self).__init__(*args, **kwargs)
        self.info("Loading: Firewall Application")
        # Initialise mac adress table
        self.mac_to_port = {}
        self.N1_mac = "00:00:00:00:00:01"  # Mac adress of N1 - must be first defined host in scenario
        self.N1_ipv4 = ipaddress.ip_network("11.0.0.0/16")
        self.block_dir = (
            os.path.dirname(__file__) + "/.blocklist/"
        )  # Relative path to blocklist directory
        self.allow_dir = (
            os.path.dirname(__file__) + "/.allowlist/"
        )  # Relative path to allowlist directory

    def info(self, text):
        print("\n" + ("#" * (len(text) + 4)))
        print("# %s #" % text)
        print(("#" * (len(text) + 4)) + "\n")

    # Set a flow on a switch
    def set_flow(
        self, datapath, match, actions, priority=0, hard_timeout=600, idle_timeout=60
    ):
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flowmod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=inst,
            priority=priority,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
        )
        datapath.send_msg(flowmod)

    # Send a packet out of a switch, return true if success
    def send_pkt(self, datapath, data, port=ofproto.OFPP_FLOOD):
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            actions=actions,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            data=data,
            buffer_id=ofproto.OFP_NO_BUFFER,
        )
        return datapath.send_msg(out)

    # Method to check a given blocklist_name (param), creates drop
    # flow rule if present in blocklist and returns true,
    # otherwise returns false.
    def check_blocklist(self, blocklist_name, dst, src, datapath):
        # Find type
        protocol_type = None
        try:
            ipaddress.ip_network(dst)
        except ValueError:
            protocol_type = "mac"
        else:
            protocol_type = "ip"

        with open(self.block_dir + blocklist_name, "r") as blocklist:
            # Check source against blocklist
            if (
                protocol_type == "mac"
                and dst == self.N1_mac
                and src + "\n" in blocklist
            ):
                match = parser.OFPMatch(eth_src=src, eth_dst=dst)
                # Create drop flow rule
                self.set_flow(
                    datapath, match, [], 2, 0, 1800
                )  # No hard timeout, idle = 30 mins
                print("#\n#     New DROP rule set\n#")
                return True
            elif (
                protocol_type == "ip"
                and ipaddress.ip_address(dst) in self.N1_ipv4
                and src + "\n" in blocklist
            ):

                # TODO - support for masked IPs in blocklist
                # Better solution for "\n"
                # Split into differnet methods (ip / mac)
                # Do something with mac_to_port
                # Add port to print msg
                # IP forward flow rule

                match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ipv4_dst=dst, ipv4_src=src)
                # Create drop flow rule
                self.set_flow(
                    datapath, match, [], 2, 0, 1800
                )  # No hard timeout, idle = 30 mins
                print("#\n#     New DROP rule set\n#")
                return True
            else:
                return False

    # Set default flow rule on new switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def __sdn_app_switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        print("\nSwitch with id {:d} connected\n".format(datapath.id))

        # install the default-to-controller-flow
        self.set_flow(
            datapath,
            parser.OFPMatch(),  # match on every packet
            [
                parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)
            ],  # action is sent_to_controller
            hard_timeout=0,  # never delete this flow
            idle_timeout=0,  # never delete this flow
        )

        # Prevent truncation of packets
        datapath.send_msg(
            datapath.ofproto_parser.OFPSetConfig(
                datapath, datapath.ofproto.OFPC_FRAG_NORMAL, 0xFFFF
            )
        )

    # Process packets in
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

        # Get array of protocol packets
        pkts = packet.Packet(array.array("B", ev.msg.data))
        # print(pkts)
        # Iterate & get relevant info
        for p in pkts:
            # Get mac info
            if isinstance(p, ethernet.ethernet):
                eth_dst = p.dst
                eth_src = p.src
                continue

            # Get ipv4 info
            if isinstance(p, ipv4.ipv4):
                ipv4_dst = p.dst
                ipv4_src = p.src
                continue

            # Check if is an arp
            if isinstance(p, arp.arp):
                is_arp = True
                continue
            else:
                try:
                    is_arp
                except NameError:
                    is_arp = False
                else:
                    pass

        in_port = msg.match["in_port"]

        # Display message on packet in - ip info if available, otherwise mac
        try:
            ipv4_src
            ipv4_dst
        except NameError:
            print("+ Packet in.  {} -> {}".format(eth_src, eth_dst))
        else:
            print("+ Packet in.  {} -> {}".format(ipv4_src, ipv4_dst))

        # Learn mac adress to avoid FLOOD next time
        self.mac_to_port[dpid][eth_src] = in_port

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Compare mac adress to blocklist
        try:
            if self.check_blocklist("mac_blocklist.txt", eth_dst, eth_src, datapath):
                return
        except NameError:
            pass

        # Compare ipv4 adress to blocklist
        try:
            if self.check_blocklist("ipv4_blocklist.txt", ipv4_dst, ipv4_src, datapath):
                return
        except NameError:
            pass

        # Create flow rule (default timeout from set_flow method)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
            self.set_flow(datapath, match, [parser.OFPActionOutput(out_port)], 1)
            print("#\n#     New FORWARD rule set\n#")

        # Forward packet to destination
        if self.send_pkt(
            datapath=datapath,
            data=msg.data,
            port=out_port,
        ):
            # Display message on packet out
            try:
                ipv4_src
                ipv4_dst
            except NameError:
                print("- Packet out. {} -> {}".format(eth_src, eth_dst))
            else:
                print("- Packet out. {} <- {}".format(ipv4_src, ipv4_dst))
        else:
            print("* FAILED TO SEND PACKET")

        
