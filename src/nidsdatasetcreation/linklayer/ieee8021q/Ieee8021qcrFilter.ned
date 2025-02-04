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

package nidsdatasetcreation.linklayer.ieee8021q;

import inet.queueing.common.BackPressureBarrier;
import inet.queueing.common.PacketMultiplexer;
import inet.queueing.contract.IPacketClassifier;
import inet.queueing.contract.IPacketFilter;
import inet.queueing.contract.IPacketGate;
import inet.queueing.contract.IPacketMeter;

import inet.protocolelement.shaper.GroupEligibilityTimeTable;
import nidsdatasetcreation.protocolelement.shaper.GroupEligibilityTimeTableWithStatistics;
import nidsdatasetcreation.protocolelement.shaper.GroupEligibilityTimeTableOneGroup;

import inet.protocolelement.contract.ITable;

//
// ATS filter module with group eligibility time and SDU filter. 
// @see groupEligibilityTimeTableWithStatistics, GroupEligibilityTimeMeterWithStatistics
// @author Teresa Lübeck 

module Ieee8021qcrFilter like IPacketFilter
{
    parameters:
        int numStreams; // number of different streams to filter for
        bool hasDefaultPath = default(true);
        @display("i=block/filter");
        
       **.groupEligibilityTimeTableModule = default(absPath(".groupEligibilityTimeTable"));
       
    gates:
        input in;
        output out;
        
    submodules:
        groupEligibilityTimeTable: <default("GroupEligibilityTimeTableWithStatistics")> like ITable {
            @display("p=43,30");
        }        
        classifier: <default("StreamClassifier")> like IPacketClassifier {
            gateIndexOffset = default(parent.hasDefaultPath ? 1 : 0);
            defaultGateIndex = default(parent.hasDefaultPath ? 0 : -1);
            @display("p=100,100");
        }        
        streamFilter[numStreams]: <default("ContentBasedFilter")> like IPacketFilter {
            @display("p=300,100,column,150");
        }
        gate[numStreams]: <default("InteractiveGate")> like IPacketGate {
            @display("p=700,100,column,150");
        }
        meter[numStreams]: <default("GroupEligibilityTimeMeterWithStatistics")> like IPacketMeter {
            @display("p=1300,100,column,150");
        }
        flowFilter[numStreams]: <default("EligibilityTimeFilter")> like IPacketFilter {
            @display("p=1500,100,column,150");
        }
        multiplexer: PacketMultiplexer {
            @display("p=1700,100");
        }
        barrier: BackPressureBarrier {
            @display("p=1900,100");
        }
        
        
	connections:
	    in --> { @display("m=w"); } --> classifier.in;
	    classifier.out++ --> multiplexer.in++ if hasDefaultPath;
	    for i=0..numStreams-1 {
            classifier.out++ --> streamFilter[i].in;
            streamFilter[i].out --> gate[i].in;
            gate[i].out --> meter[i].in;
            meter[i].out --> flowFilter[i].in;
            flowFilter[i].out --> multiplexer.in++;
        }
        multiplexer.out --> barrier.in;
        barrier.out --> { @display("m=e"); } --> out;
}