# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A super simple OpenFlow learning switch that installs rules for
each pair of L2 addresses.
"""

# These next two imports are common POX convention
from pox.core import core
import pox.openflow.libopenflow_01 as of
#import pox.lib.packet as pkt
from pox.lib.packet import *
from pox.lib.packet.packet_base import packet_base
from types import *
# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()


# This table maps (switch,MAC-addr) pairs to the port on 'switch' at
# which we last saw a packet *from* 'MAC-addr'.
# (In this case, we use a Connection object for the switch.)
table = {}


# To send out all ports, we can use either of the special ports
# OFPP_FLOOD or OFPP_ALL.  We'd like to just use OFPP_FLOOD,
# but it's not clear if all switches support this, so we make
# it selectable.
all_ports = of.OFPP_FLOOD


# Handle messages the switch has sent us because it has no
# matching rule.
def _handle_PacketIn(event):
    packet = event.parsed
    # Learn the source
    table[(event.connection, packet.src)] = event.port
#  print table
    dst_port = table.get((event.connection, packet.dst))
#  print dst_port
    if dst_port is None:
        # We don't know where the destination is yet.  So, we'll just
        # send the packet out all ports (except the one it came in on!)
        # and hope the destination is out there somewhere. :)
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=all_ports))
        event.connection.send(msg)
    else:
        # Since we know the switch ports for both the source and dest
        # MACs, we can install rules for both directions.
        msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.match.dl_dst = packet.src
        msg.match.dl_src = packet.dst
        msg.priority = 1000
        # print "PACKET TYPE: %s"%packet.type
        if packet.type == 2048:
            # print "PROTOCOL:%s" %packet.payload.protocol
            if packet.payload.protocol != 1:
                # print "TCP PACKET"
                msg.match.tp_dst = packet.payload.payload.srcport
                msg.match.tp_src = packet.payload.payload.dstport
#      else:
                # print "ICMP PACKET"
            msg.match.nw_dst = packet.payload.srcip
            msg.match.nw_src = packet.payload.dstip
            msg.match.nw_proto = packet.payload.protocol
            msg.priority = 1500
        msg.match.dl_type = packet.type
        msg.actions.append(of.ofp_action_output(port=event.port))
        print "installing Flows"
#    print msg
        event.connection.send(msg)

        # This is the packet that just came in -- we want to
        # install the rule and also resend the packet.
        msg = of.ofp_flow_mod()
        msg.data = event.ofp  # Forward the incoming packet
#    msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.priority = 1000
        if packet.type == 2048:
            if packet.payload.protocol != 1:
                # print "ICMP PACKET"
                msg.match.tp_src = packet.payload.payload.srcport
                msg.match.tp_dst = packet.payload.payload.dstport
            msg.match.nw_src = packet.payload.srcip
            msg.match.nw_dst = packet.payload.dstip
            msg.match.nw_proto = packet.payload.protocol
            msg.priority = 1500
        msg.match.dl_type = packet.type
        msg.actions.append(of.ofp_action_output(port=dst_port))
        print "Installing with data"
        event.connection.send(msg)

        log.debug("Installing %s <-> %s" % (packet.src, packet.dst))


def launch(disable_flood=False):
    global all_ports
    if disable_flood:
        all_ports = of.OFPP_ALL

    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)

    log.info("Pair-Learning switch running.")
