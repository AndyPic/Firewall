from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ether_types, arp, ethernet, ipv4
from termcolor import colored
from timeit import default_timer as timer

import os, array, ipaddress, json, time

#tm task=firewall


class FirewallApplication(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(FirewallApplication, self).__init__(*args, **kwargs)
        self.info("Load Application: FIREWALL")
        # Initialise mac adress table
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.N1_mac = "00:00:00:00:00:01"  # Mac adress of N1 - must be first defined host in scenario
        self.N1_ipv4 = ipaddress.ip_network("11.0.0.0/16")
        self.block_dir = (
            os.path.dirname(__file__) + "/.blocklist/"
        )  # Relative path to blocklist directory
        self.allow_dir = (
            os.path.dirname(__file__) + "/.allowlist/"
        )  # Relative path to allowlist directory

    def info(self, text):
        print("\n    " + colored(" " * (len(text) + 4), "white", "on_yellow"))
        print("      {}  ".format(text))
        print("    " + colored(" " * (len(text) + 4), "white", "on_yellow") + "\n")

    # Set a flow on a switch
    def set_flow(
        self, datapath, match, actions, priority=0, hard_timeout=600, idle_timeout=60
    ):
        # Type of rule set
        if actions == []:
            rule = colored("DROP", "yellow", attrs=["bold"])
        else:
            rule = colored("FORWARD", "green", attrs=["bold"])

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
        if datapath.send_msg(flowmod):
            print(
                colored("    New ", "green") + rule + colored(" flow rule set", "green")
            )
            return True
        else:
            print(colored("    FAILED TO SET NEW FLOW RULE", "red", attrs=["bold"]))
            return False

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

    # def binary_search(self, item, list):
    #    """ Binary search for item (needle) in list (haystack), returns the position and true/false if found """
    #    first = 0
    #    last = len(list) - 1
    #    found = False
    #    while first <= last and not found:
    #        pos = 0
    #        midpoint = (first + last) // 2
    #        if list[midpoint] == item:
    #            pos = midpoint
    #            found = True
    #        else:
    #            if item < list[midpoint]:
    #                last = midpoint - 1
    #            else:
    #                first = midpoint + 1
    #    return (pos, found)

    def check_mac(self, dst, src, datapath):
        """Checks given mac address against 'blocklist.json' & return True if present"""
        block_file = open(self.block_dir + "blocklist.json", "r")
        blocklist = json.load(block_file)
        if src in blocklist["mac"]:
            # Build match obj
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            # Create drop flow rule (empty action)
            self.set_flow(
                datapath, match, [], 2, 0, 1800
            )  # No hard timeout, idle = 30 mins
            block_file.close()
            return True
        else:
            block_file.close()
            return False

    def check_ipv4(self, dst, src, datapath):
        """Checks given ipv4 address against 'blocklist.json' & return True if present"""
        response = False
        block_file = open(self.block_dir + "blocklist.json", "r")
        blocklist = json.load(block_file)

        if src in blocklist["ipv4"]:
            # Build match obj
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst, ipv4_src=src
            )
            # Create drop flow rule (empty action)
            self.set_flow(
                datapath, match, [], 2, 0, 1800
            )  # No hard timeout, idle = 30 mins
            response = True
        else:
            src_address = ipaddress.ip_address(src)
            for i in blocklist["ipv4_mask"]:
                ipv4_network = ipaddress.ip_network(i)
                if src_address in ipv4_network:
                    # Build match obj
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst, ipv4_src=src
                    )
                    # Create drop flow rule (empty action)
                    self.set_flow(
                        datapath, match, [], 2, 0, 1800
                    )  # No hard timeout, idle = 30 mins
                    response = True

        block_file.close()
        return response

    def elapsed_time(self, start):
        elapsed = timer() - start
        return "Elapsed: " + str(elapsed) + "-sec"

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
        # Start timeit for method
        # TODO - time / (1/1000) = ms
        start_time = timer()

        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        # Define OF switch identifier + set mac adress table for switch
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_port.setdefault(dpid, {})

        # Get array of protocol packets
        pkts = packet.Packet(array.array("B", msg.data))

        # Iterate & get relevant info
        for p in pkts:
            # Get mac info
            if isinstance(p, ethernet.ethernet):
                eth_dst = p.dst
                eth_src = p.src
                # Learn mac adress to avoid FLOOD next time
                self.mac_to_port[dpid][eth_src] = in_port
                continue

            # Get ipv4 info
            if isinstance(p, ipv4.ipv4):
                ipv4_dst = p.dst
                ipv4_src = p.src
                # Learn mac adress to avoid FLOOD next time
                self.ip_to_port[dpid][ipv4_src] = in_port
                continue

        # Display message on packet in - ip info if available, otherwise mac
        try:
            ipv4_src
            ipv4_dst
        except NameError:
            print("+ Packet in.  {} -> {}".format(eth_src, eth_dst))
        else:
            print("+ Packet in.  {} -> {}".format(ipv4_src, ipv4_dst))

        try:
            if eth_dst == self.N1_mac or ipaddress.ip_address(ipv4_dst) in self.N1_ipv4:
                # Compare mac adress to blocklist
                if self.check_mac(eth_dst, eth_src, datapath):
                    print(self.elapsed_time(start_time))
                    return
                # Compare ipv4 adress to blocklist
                if self.check_ipv4(ipv4_dst, ipv4_src, datapath):
                    print(self.elapsed_time(start_time))
                    return
        except NameError:
            pass

        try:
            if eth_dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth_dst]

                # Create flow rule
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
                self.set_flow(
                    datapath, match, [parser.OFPActionOutput(out_port)], 1, 0, 999
                )

            elif ipaddress.ip_address(ipv4_dst) in self.N1_ipv4:
                out_port = 1

                # Create flow rule
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    in_port=in_port,
                    ipv4_dst=ipv4_dst,
                    ipv4_src=ipv4_src,
                )
                self.set_flow(
                    datapath, match, [parser.OFPActionOutput(out_port)], 1, 0, 999
                )

            else:
                out_port = ofproto.OFPP_FLOOD
        except (NameError, UnboundLocalError):
            out_port = ofproto.OFPP_FLOOD

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
                print(
                    "- Packet out. {} <- {}".format(
                        eth_src,
                        eth_dst,
                    )
                )
                print(self.elapsed_time(start_time))
            else:
                print(
                    "- Packet out. {} <- {}".format(
                        ipv4_src,
                        ipv4_dst,
                    )
                )
                print(self.elapsed_time(start_time))
        else:
            print(colored("* FAILED TO SEND PACKET", "red", attrs=["bold"]))
            print(self.elapsed_time(start_time))
