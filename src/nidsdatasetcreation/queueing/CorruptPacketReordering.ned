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
// Corruption module that is able to reorder packets.
//
// @see CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketManipulation
//
// @author Philipp Meyer
//
simple CorruptPacketReordering extends CorruptPacketFlowBase
{
    parameters:
       @class(CorruptPacketReordering);
       // Number of packets that have to pass before the injected packet is inserted. Default is 1.
       int numberOfPacketsBeforeInjection @mutable = default(1);
       // Which packets should be considered when counting the number of packets that have passed. True means that only packets of the same stream are counted. False means all packets are counted. Default is true.
       bool matchStreamForPacketCounting = default(true);
       // Should taken packets that are ready to be inserted again (number of packets passed is reached) be inserted in random order? Default is false (FIFO)
       bool injectTakenPacketsInRandomOrder = default(false);
       label = default("REORDERED");
}
