from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3_parser as parser
import ryu.ofproto.ofproto_v1_3 as ofproto
from ryu.lib.packet import packet, ether_types, arp, ethernet, ipv4
from termcolor import colored
from timeit import default_timer as timer

import os, array, ipaddress, json, time, re

#tm task=firewall


class FirewallApplication(app_manager.RyuApp):
    """Implements ryu application, rather than SDN application,
    methods needed from SDN app have been implemented here instead
    to allow them to be tailored to the needs of this application"""

    def __init__(self, *args, **kwargs):
        super(FirewallApplication, self).__init__(*args, **kwargs)
        self.info("Load Application: FIREWALL")
        # Initialise mac and IP port table
        self.mac_to_port = {}
        self.ip_to_port = {}
        # The mac address of n1 ie. the local network
        # script_run_mininet.py has been edited to statically assign mac adresses
        # TODO read mac+ip in dynamically from .yaml file?
        self.N1_mac = "00:00:00:00:00:01"  # Mac adress of N1 - must be first defined host in scenario
        # The ipv4 network for n1 (mask = 11.0.255.255)
        self.N1_ipv4 = ipaddress.ip_network("11.0.0.0/16")
        # Relative path to blocklist directory
        self.block_dir = os.path.dirname(__file__) + "/.blocklist/"
        # Relative path to allowlist directory
        self.allow_dir = os.path.dirname(__file__) + "/.allowlist/"
        # Track number of packets handled by controller
        self.total_packets = 0
        self.start_time = 0

    # Set default flow rule on new switch
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def __sdn_app_switch_features_handler(self, ev):
        # Originally from controller.py
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

    # TODO - do something with ARP to stop error's
    # Do something with mac / ip_to_port lists

    # Process packets in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Increment packet counter
        self.total_packets += 1
        # Record start time
        start_time = timer()
        # Message from switch
        msg = ev.msg
        # Data path over which the message was recieved
        datapath = msg.datapath
        # Port the message came in from
        in_port = msg.match["in_port"]

        # dpid = the switch id that sent the msg to controller
        dpid = datapath.id
        # Set up defaults for mac and ip dicts for this switch
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_port.setdefault(dpid, {})

        # Get packets
        pkts = packet.Packet(msg.data)

        # Get ethernet part of packet
        eth = pkts.get_protocol(ethernet.ethernet)
        # Learn mac+port to avoid port FLOOD next time
        self.mac_to_port[dpid][eth.src] = in_port

        ip4 = pkts.get_protocol(ipv4.ipv4)

        # Display message on packet in - ip info if available, otherwise mac
        if ip4 != None:
            # Learn ip+port to avoid port FLOOD next time
            self.ip_to_port[dpid][ip4.src] = in_port
            # If declared, show ip info
            print("+ Packet in.  {} -> {}".format(ip4.src, ip4.dst))
        else:
            # If not declared (NameError thrown) show mac info
            print("+ Packet in.  {} -> {}".format(eth.src, eth.dst))

        # Check that the destination is within n1 network
        if eth.dst == self.N1_mac and ip4 == None:
            # Compare mac adress to blocklist
            if self.check_mac(eth.dst, eth.src, datapath):
                # return to end the handler method
                return self.end_message(start_time)

        # Check that the destination is within n1 network
        if ip4 != None and ipaddress.ip_address(ip4.dst) in self.N1_ipv4:
            # Compare ipv4 adress to blocklist
            if self.check_ipv4(ip4.dst, ip4.src, datapath):
                # If returns true, print end message
                return self.end_message(start_time)

        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
            # Create flow rule
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.set_flow(
                datapath, match, [parser.OFPActionOutput(out_port)], 1, 0, 999
            )
        elif ip4 != None and ipaddress.ip_address(ip4.dst) in self.N1_ipv4:
            out_port = 1
            # Create flow rule
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                in_port=in_port,
                ipv4_dst=ip4.dst,
                ipv4_src=ip4.src,
            )
            self.set_flow(
                datapath, match, [parser.OFPActionOutput(out_port)], 1, 0, 999
            )
        else:
            out_port = ofproto.OFPP_FLOOD

        # Forward packet to destination
        if self.send_pkt(
            datapath=datapath,
            data=msg.data,
            port=out_port,
        ):
            return self.end_message(start_time)
        else:
            print(colored("* FAILED TO SEND PACKET", "red", attrs=["bold"]))
            return self.end_message(start_time)

    def info(self, text):
        # Originally from controller.py - heavily edited
        # Formatted message in a similar style as other sdn cockpit messages
        print("\n    " + colored(" " * (len(text) + 4), "white", "on_yellow"))
        print("      {}  ".format(text))
        print("    " + colored(" " * (len(text) + 4), "white", "on_yellow") + "\n")

    def set_flow(
        self, datapath, match, actions, priority=0, hard_timeout=600, idle_timeout=60
    ):
        """Method to set a new flow rule on a given switch (datapath)"""
        # Originally from controller.py - heavily edited
        # Determin the type of flow rule being set, and store the formatted identifier
        # (either "DROP" or "FORWARD") in the var 'rule'
        if actions == []:
            rule = colored("DROP", "yellow", attrs=["bold"])
        else:
            rule = colored("FORWARD", "green", attrs=["bold"])
        # Construct the instruction object from passed action var
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Construct the new flowmod from passed variables
        flowmod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=inst,
            priority=priority,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
        )
        # Pass the flowmod to the switch (datapath) via the send_msg method
        # Done within an 'if' statement for error handling. If send_msg return true
        # the rule has been set sucesfully, if it returns false the rule failed to set
        if datapath.send_msg(flowmod):
            # Display message when a new rule is set
            print(
                colored("    New ", "green") + rule + colored(" flow rule set", "green")
            )
            # Return True on success
            return True
        else:
            # Display message when a new rule fails to be set
            print(colored("    FAILED TO SET NEW FLOW RULE", "red", attrs=["bold"]))
            # Return False on failure
            return False

    # Send a packet out of a switch, return true if success
    def send_pkt(self, datapath, data, port=ofproto.OFPP_FLOOD):
        # Originally from controller.py
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            actions=actions,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            data=data,
            buffer_id=ofproto.OFP_NO_BUFFER,
        )
        # Edited to return send_msg response to allow error handling by the calling application
        return datapath.send_msg(out)

    # This binary_search method was used for efficiency checking the application
    # ie. ability to efficiently find an item within the blocklist
    # python 'in' used instead, as it uses binary search under these circumstances

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
        """Checks given mac address against 'blocklist.json' and return True if
        present. Throws ValueError if dst or src are not mac addresses (0-f, ff:ff:ff:ff:ff:ff)"""

        # Validate that the information passed is correctly formatted mac addresses
        # Quick regex explanation:
        # [0-9a-f]{2}([:])[0-9a-f]{2} = must be {2} hexidecimal chars separated by :
        # (\\1[0-9a-f]{2}){4}$ = \\1 use the same separator, {4} repeat 4 times (total of 6 blocks for mac address)
        # $ = end of the string
        if re.match(
            "[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", src.lower()
        ) and re.match("[0-9a-f]{2}([:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", dst.lower()):
            # Do nothing if correct format
            pass
        else:
            # Throw type error
            raise ValueError("Invalid mac address passed")

        # Declare default response
        response = False
        # Access the blocklist file
        block_file = open(self.block_dir + "blocklist.json", "r")
        # Parse the json file to python dict
        blocklist = json.load(block_file)
        # Check if the packet source is present in the mac blocklist
        if src in blocklist["mac"]:
            # Build match obj
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            # Create drop flow rule (empty action list)
            self.set_flow(
                datapath, match, [], 2, 0, 1800
            )  # No hard timeout, idle = 30 mins
            response = True
        # Close resources
        block_file.close()
        return response

    def check_ipv4(self, dst, src, datapath):
        """Checks given ipv4 address against 'blocklist.json' and return True
        if present. Throws ValueError if dst or src are not ip addresses"""
        # Don't need to validate ip address in same way as mac, as it is built
        # in to the ipaddress lib used, will throw error on var declaration
        src_address = ipaddress.ip_address(src)
        dst_address = ipaddress.ip_address(dst)

        # Declare default response
        response = False
        # Access the blocklist file
        block_file = open(self.block_dir + "blocklist.json", "r")
        # Parse the json file to python dict
        blocklist = json.load(block_file)
        # Check if the packet source is present in the ipv4 blocklist
        if src in blocklist["ipv4"]:
            # Build match obj
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst, ipv4_src=src
            )
            # Create drop flow rule (empty action list)
            self.set_flow(
                datapath, match, [], 2, 0, 1800
            )  # No hard timeout, idle = 30 mins
            response = True
        else:
            # Iterate over the ipv4_mask blocklist
            for i in blocklist["ipv4_mask"]:
                # Store the ipv4 networks from blocklist in an ip_network obj
                ipv4_network = ipaddress.ip_network(i)
                # Check if src in network
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
                    # Break out of loop if ip found - don't need to keep looking!
                    break
        # Close resources
        block_file.close()
        return response

    def end_message(self, start):
        """Method to print an ending"""
        elapsed = timer() - start  # Elapsed time in fractal seconds
        elapsed = elapsed / (1 / 1000)  # Convert to ms
        print(
            "Controller finished with packet {} after {:.2f}ms".format(
                self.total_packets, elapsed
            )
        )