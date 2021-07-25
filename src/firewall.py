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


class FirewallApplication(app_manager.RyuApp):
    N1_mac = "00:00:00:00:00:01"
    block_dir = os.path.dirname(__file__) + "/.blocklist/"  # Relative path to src dir

    def __init__(self, *args, **kwargs):
        super(FirewallApplication, self).__init__(*args, **kwargs)
        self.info("Loading: Firewall Application")
        # Initialise mac adress table
        self.mac_to_port = {}

    def info(self, text):
        print("")
        print("#" * (len(text) + 4))
        print("# %s #" % text)
        print("#" * (len(text) + 4))
        print("")

    # Set a flow on a switc
    def set_flow(
        self, datapath, match, actions, priority=0, hard_timeout=600, idle_timeout=60
    ):
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flowmod = parser.OFPFlowMod(
            datapath,
            match=match,
            instructions=inst,
            priority=priority,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout,
        )
        datapath.send_msg(flowmod)

    # Send a packet out of a switch
    def send_pkt(self, datapath, data, port=ofproto.OFPP_FLOOD):
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            actions=actions,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            data=data,
            buffer_id=ofproto.OFP_NO_BUFFER,
        )
        datapath.send_msg(out)

    # Method to check a given blocklist (param), creates drop
    # flow rule if present in blocklist and returns true,
    # otherwise returns false.
    def check_blocklist(self, blocklist, dst, src, datapath):
        with open(self.block_dir + blocklist, "r") as mac_blocklist:
            if dst == self.N1_mac and src + "\n" in mac_blocklist:
                match = parser.OFPMatch(eth_src=src, eth_dst=dst)
                # Create drop flow rule
                self.set_flow(
                    datapath, match, "", 2, 0, 1800
                )  # No hard timeout, idle = 30 mins
                print("New DROP rule set")
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

        # Get protocol, source and dest with Ryu packet library
        eth_pkt = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        in_port = msg.match["in_port"]

        #
        print(
            "Packet in. Switch: {}, Source: {}, Destination: {}, In Port: {}".format(
                dpid,
                src,
                dst,
                in_port,
            )
        )

        # Learn mac adress to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Firewall setup

        # Compare mac adress to blocklist
        if self.check_blocklist("mac_blocklist.txt", dst, src, datapath):
            return

        # TODO - ip blocklist
        # TODO - ipv4/6
        # TODO - Prevent FTP traffic to external IPs

        # Create flow rule (default timeout from set_flow method)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.set_flow(datapath, match, actions, 1)
            print("New FORWARD rule set")

        # Finally, forward packet to destination
        self.send_pkt(
            datapath=datapath,
            data=msg.data,
            port=out_port,
        )
