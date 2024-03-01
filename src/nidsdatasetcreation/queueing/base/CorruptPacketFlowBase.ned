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

package nidsdatasetcreation.queueing.base;

import inet.queueing.base.PacketFlowBase;
import inet.queueing.contract.IPacketFlow;

//
// Represents a corruptible packet flow base
//
// @see PacketFlowBase, IPacketFlow, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketManipulation, CorruptPacketReordering
//
// @author Philipp Meyer
//
simple CorruptPacketFlowBase extends PacketFlowBase like IPacketFlow
{
    parameters:
        @class(CorruptPacketFlowBase);
        // Signal is emited when a corruption is executed
        @signal[corruption](type=bool);
        // Statistic for the performed corruptions
	    @statistic[corruptionsPerformed](title="Corruptions Performed"; source=corruption; record=vector; interpolationmode=none;);
	    
	    // Which packets are allowed to be corrupted, matches no packets by default
	    object packetFilter @mutable = default("");
	    // Probability that a matching packet will be corrupted
	    double probability @mutable = default(1);
	    // Minimum time span between corruptions
	    double minInterval @mutable @unit(s) = default(0s);
	    // Label that is attached to corrupted packets
	    string label = default("CORRUPTED");
}
