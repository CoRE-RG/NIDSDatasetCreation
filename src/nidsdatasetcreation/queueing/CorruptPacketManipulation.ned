//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package nidsdatasetcreation.queueing;

import nidsdatasetcreation.queueing.base.CorruptPacketFlowBase;

//
// Corruption modul that is able to manipulate packets
//
// @see CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketReordering
//
// @author Philipp Meyer
//
simple CorruptPacketManipulation extends CorruptPacketFlowBase
{
   parameters:
        @class(CorruptPacketManipulation);
        // Destination port the packet is manipulated to. Default is -1, which means no manipulation.
        int destPort = default(-1);
        // Source port the packet is manipulated to. Default is -1, which means no manipulation.
        int srcPort = default(-1);
        // Destination IP address the packet is manipulated to. Default is "", which means no manipulation.
        string destIpAddress = default("");
        // Source IP address the packet is manipulated to. Default is "", which means no manipulation.
        string srcIpAddress = default("");
        // Destination MAC address the packet is manipulated to. Default is "", which means no manipulation.
        string destMacAddress = default("");
        // Source MAC address the packet is manipulated to. Default is "", which means no manipulation.
        string srcMacAddress = default("");
        // Q-Tag priority (pcp) the packet is manipulated to. Default is -1, which means no manipulation.
        int priority = default(-1);
        // Q-Tag VLAN ID (vid) the packet is manipulated to. Default is -1, which means no manipulation.
        int vid = default(-1);
        // Q-Tag drop eligible indicator (dei) the packet is manipulated to. Default is 0Byte, which means no manipulation.
        volatile int payload @mutable @unit(Byte) = default(0Byte);
        label = default("MANIPULATED");
}
