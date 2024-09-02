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
// Corruption module that is able to inject packets
//
// @see CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketManipulation, CorruptPacketReordering
//
// @author Philipp Meyer
//
simple CorruptPacketInjection extends CorruptPacketFlowBase
{
    parameters:
        @class(CorruptPacketInjection);
        // Interval between two injected packets    
        volatile double injectionInterval @mutable @unit(s) = default(0s);
        // Destination port of injected packets
        int destPort @mutable = default(0);
        // Source port of injected packets
        int srcPort @mutable = default(0);
        // Destination IP address of injected packets
        string destIpAddress @mutable = default("");
        // Source IP address of injected packets
        string srcIpAddress @mutable = default("");
        // Destination MAC address of injected packets
        string destMacAddress @mutable = default("");
        // Source MAC address of injected packets
        string srcMacAddress @mutable = default("");
        // Q-Tag priority (pcp) of injected packets. If set to -1, no priority is added.
        int priority @mutable = default(-1);
        // Q-Tag VLAN ID (vid) of injected packets. If set to -1, no VLAN ID is added.
        int vid @mutable = default(-1);
        // Payload of injected packets in bytes
        volatile int payload @mutable @unit(Byte) = default(0Byte);
        label = default("INJECTED");
}
