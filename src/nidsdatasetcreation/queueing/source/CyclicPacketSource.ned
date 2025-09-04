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

package nidsdatasetcreation.queueing.source;


import inet.queueing.contract.IActivePacketSource;
import inet.queueing.source.ActivePacketSource;

//
// This is a cyclic packet source. Packets are produced with different intervals in a cycle. 
//
// @see ActivePacketSource
// 
// @author Teresa Lübeck

simple CyclicPacketSource extends ActivePacketSource
{
    parameters:
        productionInterval = default(-1s); // set via productionIntervals parameter
        string productionIntervals; // array of production intervals in seconds
        
        @class(CyclicPacketSource);
}