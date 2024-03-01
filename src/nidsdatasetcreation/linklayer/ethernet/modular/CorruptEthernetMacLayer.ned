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

package nidsdatasetcreation.linklayer.ethernet.modular;

import inet.linklayer.ethernet.contract.IEthernetMacLayer;
import inet.protocolelement.contract.IPacketLifeTimer;
import inet.queueing.contract.IPacketFilter;
import inet.queueing.contract.IPacketFlow;
import inet.queueing.contract.IPacketQueue;
import inet.queueing.contract.IPacketServer;

//
// Represents a ethernet mac layer that is corruptible on two different stages (before and after queueing)
//
// @see CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketManipulation, CorruptPacketReordering
//
// @author Philipp Meyer
//
module CorruptEthernetMacLayer like IEthernetMacLayer
{
    parameters:
        double bitrate @unit(bps);
        *.bitrate = default(this.bitrate);
        lifetimer.collectionModule = default("^.queue");
        outboundEmitter.signalName = "packetSentToLower";
        outboundEmitter.direction = "outbound";
        inboundEmitter.signalName = "packetReceivedFromLower";
        inboundEmitter.direction = "inbound";
        @display("i=block/layer");
        @class(CorruptEthernetMacLayer);
    gates:
        input upperLayerIn;
        output upperLayerOut;
        input lowerLayerIn;
        output lowerLayerOut;
    submodules:
        lifetimer: <default("")> like IPacketLifeTimer if typename != "" {
            @display("p=100,138;is=s");
        }
        corruptUpperLayer: <default("CorruptPacketFlowBase")> like IPacketFlow {
            @display("p=200,60");
        }
        queue: <default("PacketQueue")> like IPacketQueue {
            @display("p=200,138");
        }
        corruptLinkLayer: <default("CorruptPacketFlowBase")> like IPacketFlow {
            @display("p=200,218");
        }
        server: <default("InstantServer")> like IPacketServer {
            @display("p=200,300");
        }
        outboundEmitter: <default("PacketEmitter")> like IPacketFlow {
            @display("p=200,400");
        }
        fcsChecker: <default("EthernetFcsChecker")> like IPacketFilter {
            popFcs = default(false);
            @display("p=500,300");
        }
        inboundEmitter: <default("PacketEmitter")> like IPacketFlow {
            @display("p=500,400");
        }
    connections:
        upperLayerIn --> { @display("m=n"); } --> corruptUpperLayer.in;
        corruptUpperLayer.out --> queue.in;
        queue.out --> corruptLinkLayer.in;
        corruptLinkLayer.out --> server.in;
        server.out --> outboundEmitter.in;
        outboundEmitter.out --> { @display("m=s"); } --> lowerLayerOut;
        lowerLayerIn --> { @display("m=s"); } --> inboundEmitter.in;
        inboundEmitter.out --> fcsChecker.in;
        fcsChecker.out --> { @display("m=n"); } --> upperLayerOut;
}
