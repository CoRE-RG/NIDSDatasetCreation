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

package nidsdatasetcreation.node.tsn;

import inet.node.tsn.TsnSwitch;
import nidsdatasetcreation.common.packet.recorder.PcapRecorderWithLabeling;

//
// TSN switch with pcap recorders with labeling
//
// @see TsnSwitch
//
// @author Philipp Meyer
//
module TsnSwitchWithLabeling extends TsnSwitch
{
    parameters:
        // number of pcap recorders with labeling
        int numPcapRecordersWithLabeling = default(0);
    submodules:
        pcapRecorderWithLabeling[numPcapRecordersWithLabeling]: PcapRecorderWithLabeling {
        	@display("p=125,640;is=s");
        }
}
