#  This is part of our final project for the Computer Networks Graduate Course at Georgia Tech
#    You can take the official course online too! Just google CS 6250 online at Georgia Tech.
#
#  Contributors:
#   
#    Akshar Rawal (arawal@gatech.edu)
#    Flavio Castro (castro.flaviojr@gmail.com)
#    Logan Blyth (lblyth3@gatech.edu)
#    Matthew Hicks (mhicks34@gatech.edu)
#    Uy Nguyen (unguyen3@gatech.edu)
#
#  To run:
#    
#    ryu--manager --observe-links shortestpath.py   
#
#Copyright (C) 2014, Georgia Institute of Technology.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 shortest path forwarding implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp, ipv4, tcp, udp, ether_types
from operator import attrgetter
import time

from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches 
import networkx as nx
from collections import defaultdict
from ryu.lib import hub

class LoadBalancer(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.graph=nx.DiGraph()
        self.i=0
        self.link_lst = []
        self.switches = []
        self.sw = []
        self.lst = []
        self.ip_to_mac = {}
        
        self.arp_checker = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: None)))
        self.update_link_load_thread = hub.spawn(self._poll_link_load)
        
    @set_ev_cls(event.EventSwitchEnter)
    def new_switch_handler(self, ev):
        switch = ev.switch
        #  Task 1: Add the new switch as a node to the graph.
        self.switches.append(switch)
        self.sw.append(switch.dp.id)
        self.graph.add_nodes_from(self.sw)
        
    @set_ev_cls(event.EventLinkAdd)
    def new_link_handler(self, ev):
        link = ev.link
      
        #  Task 1: Add the new link as an edge to the graph
        # Make sure that you do not add it twice.
        port_src = link.src.port_no
        port_dst = link.dst.port_no
        
        dpid_src = link.src.dpid
        dpid_dst = link.dst.dpid

        self.link_lst.append((dpid_src, dpid_dst, {'port':port_src}))
        self.graph.add_edges_from(self.link_lst)
        
        self.link_lst.append((dpid_dst, dpid_src, {'port':port_dst}))
        self.graph.add_edges_from(self.link_lst)
        
    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

        
    def _poll_link_load(self):
        """
        Sends periodically port statistics requests to the SDN switches. Period: 1s
        :return:
        """
        while True:
            for sw in self.switches:
                self._request_port_stats(sw.dp)
            hub.sleep(1)

    def _request_port_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_NONE)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Calculates the link load based on the received port statistics. The values are stored as an attribute of the
        edges in the networkx DiGraph. [Bytes/Sec]/[Max Link Speed in Bytes]
        Args:
            ev:
        Returns

        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted(body, key=attrgetter('port_no')):
      
            num_bytes = stat.rx_bytes + stat.tx_bytes
            new_time = time.time()

            for edge in self.graph.edges():
                src_node, dst_node = edge

                if src_node == dpid:
                    self.graph[src_node][dst_node]['weight'] = num_bytes
                    
    def _handle_ipv4(self, datapath, in_port, src, dst, buffer_id):
    
        dpid = datapath.id
        ofproto = datapath.ofproto
        
        if src not in self.graph:
            self.graph.add_node(src)
            self.lst.append((dpid,src,{'port':in_port}))
            self.graph.add_edges_from(self.lst)
            self.graph.add_edge(src,dpid)
        if dst in self.graph:
            try:
               path=nx.dijkstra_path(self.graph,src,dst)   
               next=path[path.index(dpid)+1]
               out_port=self.graph[dpid][next]['port']
               print("path found %s", path)
            except nx.NetworkXNoPath:
               out_port = ofproto.OFPP_FLOOD
               print("No path found")
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id, in_port=in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        self._handle_ipv4(datapath, msg.in_port, src, dst, msg.buffer_id)
        