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

package nidsdatasetcreation.simulations.atsdemo;

import inet.node.contract.IEthernetNetworkNode;
import inet.networks.base.TsnNetworkBase;
import inet.node.ethernet.Eth100M;


network demoBaseline extends TsnNetworkBase
{
    @display("bgb=1500,800;bgi=backgrounds/background_grayArrows,s");
    
    @statistic[queuelen](source=warmup(atomic(constant0(switch2.eth[1].macLayer.queue.queue[0].packetPushEnded)+count(switch2.eth[1].macLayer.queue.queue[0].packetPushStarted)-count(switch2.eth[1].macLayer.queue.queue[0].packetPulled)- count(switch2.eth[1].macLayer.queue.queue[0].packetRemoved)-count(switch2.eth[1].macLayer.queue.queue[0].packetDropped))); unit=pk; record=figure; targetFigure=qlen);
    @figure[qlen](type=counter; pos=1175,310; label="Queue Length"; labelOffset=-50;decimalPlaces=3);
    
    submodules:
        
        talker: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=500,400");
            gates:
                ethg[1];
        }

        switch0: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=600,400;t=Split\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switchL1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=700,300");
            gates:
                ethg[2];
        }

        switchL2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=800,300");
            gates:
                ethg[2];
        }

        switchL3: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=900,300");
            gates:
                ethg[2];
        }

        switchL4: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1000,300");
            gates:
                ethg[2];
        }

        switchS1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=850,500;t=Drop even numbered\npackets,,darkgreen");
            gates:
                ethg[2];
        }

        switch1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=1100,400;t=Merge\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switch2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1200,400;t=ATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        listener: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=1300, 400");
            gates:
                ethg[1];
        }


    connections:
        talker.ethg[0] <--> Eth100M <--> switch0.ethg[0];
        switch0.ethg[1] <--> Eth100M <--> switchL1.ethg[0];
        switch0.ethg[2] <--> Eth100M <--> switchS1.ethg[0];

        switchL1.ethg[1] <--> Eth100M <--> switchL2.ethg[0];
        switchL2.ethg[1] <--> Eth100M <--> switchL3.ethg[0];
        switchL3.ethg[1] <--> Eth100M <--> switchL4.ethg[0];

        switchL4.ethg[1] <--> Eth100M <--> switch1.ethg[1];
        switchS1.ethg[1] <--> Eth100M <--> switch1.ethg[2];
        switch1.ethg[0] <--> Eth100M <--> switch2.ethg[0];

        switch2.ethg[1] <--> Eth100M{@display("ls=magenta,3");} <--> listener.ethg[0];
}

network demoModification1 extends TsnNetworkBase
{
    @display("bgb=1500,800;bgi=backgrounds/background_grayArrows,s");
    
    @statistic[queuelen](source=warmup(atomic(constant0(switch2.eth[1].macLayer.queue.packetPushEnded)+count(switch2.eth[1].macLayer.queue.packetPushStarted)-count(switch2.eth[1].macLayer.queue.packetPulled)- count(switch2.eth[1].macLayer.queue.packetRemoved)-count(switch2.eth[1].macLayer.queue.packetDropped))); unit=pk; record=figure; targetFigure=qlen);
    @figure[qlen](type=counter; pos=1175,310; label="Queue Length"; labelOffset=-50;decimalPlaces=3);
    
    submodules:
        
        talker: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=500,400");
            gates:
                ethg[1];
        }

        switch0: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=600,400;t=Split\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switchL1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=700,300");
            gates:
                ethg[2];
        }

        switchL2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=800,300");
            gates:
                ethg[2];
        }

        switchL3: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=900,300");
            gates:
                ethg[2];
        }

        switchL4: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1000,300");
            gates:
                ethg[2];
        }

        switchS1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=850,500;t=Drop even numbered\npackets,,darkgreen");
            gates:
                ethg[2];
        }

        switch1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=1100,400;t=Merge\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switch2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1200,400;");
            gates:
                ethg[2];
        }

        listener: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=1300, 400");
            gates:
                ethg[1];
        }


    connections:
        talker.ethg[0] <--> Eth100M <--> switch0.ethg[0];
        switch0.ethg[1] <--> Eth100M <--> switchL1.ethg[0];
        switch0.ethg[2] <--> Eth100M <--> switchS1.ethg[0];

        switchL1.ethg[1] <--> Eth100M <--> switchL2.ethg[0];
        switchL2.ethg[1] <--> Eth100M <--> switchL3.ethg[0];
        switchL3.ethg[1] <--> Eth100M <--> switchL4.ethg[0];

        switchL4.ethg[1] <--> Eth100M <--> switch1.ethg[1];
        switchS1.ethg[1] <--> Eth100M <--> switch1.ethg[2];
        switch1.ethg[0] <--> Eth100M <--> switch2.ethg[0];

        switch2.ethg[1] <--> Eth100M{@display("ls=magenta,3");} <--> listener.ethg[0];

}

network demoModification2 extends TsnNetworkBase
{
    @display("bgb=1500,800;bgi=backgrounds/background_grayArrows,s");
    
    @statistic[queuelen](source=warmup(atomic(constant0(switch2.eth[1].macLayer.queue.queue[0].packetPushEnded)+count(switch2.eth[1].macLayer.queue.queue[0].packetPushStarted)-count(switch2.eth[1].macLayer.queue.queue[0].packetPulled)- count(switch2.eth[1].macLayer.queue.queue[0].packetRemoved)-count(switch2.eth[1].macLayer.queue.queue[0].packetDropped))); unit=pk; record=figure; targetFigure=qlen);
    @figure[qlen](type=counter; pos=1175,310; label="Queue Length"; labelOffset=-50;decimalPlaces=3);
    
    submodules:
        
        talker: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=500,400");
            gates:
                ethg[1];
        }

        switch0: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=600,400;t=Split\nblue stream\nATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[3];
        }

        switchL1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=700,300;t=ATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        switchL2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=800,300;t=ATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        switchL3: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=900,300;t=ATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        switchL4: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1000,300;t=ATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        switchS1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=850,500;t=Drop even numbered\npackets\nATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        switch1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=1100,400;t=Merge\nblue stream\nATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[3];
        }

        switch2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1200,400;t=ATS configured,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        listener: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=1300, 400");
            gates:
                ethg[1];
        }


    connections:
        talker.ethg[0] <--> Eth100M <--> switch0.ethg[0];
        switch0.ethg[1] <--> Eth100M <--> switchL1.ethg[0];
        switch0.ethg[2] <--> Eth100M <--> switchS1.ethg[0];

        switchL1.ethg[1] <--> Eth100M <--> switchL2.ethg[0];
        switchL2.ethg[1] <--> Eth100M <--> switchL3.ethg[0];
        switchL3.ethg[1] <--> Eth100M <--> switchL4.ethg[0];

        switchL4.ethg[1] <--> Eth100M <--> switch1.ethg[1];
        switchS1.ethg[1] <--> Eth100M <--> switch1.ethg[2];
        switch1.ethg[0] <--> Eth100M <--> switch2.ethg[0];

        switch2.ethg[1] <--> Eth100M{@display("ls=magenta,3");} <--> listener.ethg[0];
}


network demoModification3 extends TsnNetworkBase
{
    @display("bgb=1500,800;bgi=backgrounds/background_grayArrows,s");
    
    @statistic[queuelen](source=warmup(atomic(constant0(switch2.eth[1].macLayer.queue.queue[0].packetPushEnded)+count(switch2.eth[1].macLayer.queue.queue[0].packetPushStarted)-count(switch2.eth[1].macLayer.queue.queue[0].packetPulled)- count(switch2.eth[1].macLayer.queue.queue[0].packetRemoved)-count(switch2.eth[1].macLayer.queue.queue[0].packetDropped))); unit=pk; record=figure; targetFigure=qlen);
    @figure[qlen](type=counter; pos=1175,310; label="Queue Length"; labelOffset=-50;decimalPlaces=3);
    
    submodules:
        
        talker: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=500,400");
            gates:
                ethg[1];
        }

        switch0: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=600,400;t=Split\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switchL1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=700,300");
            gates:
                ethg[2];
        }

        switchL2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=800,300");
            gates:
                ethg[2];
        }

        switchL3: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=900,300");
            gates:
                ethg[2];
        }

        switchL4: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1000,300");
            gates:
                ethg[2];
        }

        switchS1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=850,500;t=Drop even numbered\npackets,,darkgreen");
            gates:
                ethg[2];
        }

        switch1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=1100,400;t=Merge\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switch2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1200,400;t=ATS configured\nset mrt,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        listener: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=1300, 400");
            gates:
                ethg[1];
        }


    connections:
        talker.ethg[0] <--> Eth100M <--> switch0.ethg[0];
        switch0.ethg[1] <--> Eth100M <--> switchL1.ethg[0];
        switch0.ethg[2] <--> Eth100M <--> switchS1.ethg[0];

        switchL1.ethg[1] <--> Eth100M <--> switchL2.ethg[0];
        switchL2.ethg[1] <--> Eth100M <--> switchL3.ethg[0];
        switchL3.ethg[1] <--> Eth100M <--> switchL4.ethg[0];

        switchL4.ethg[1] <--> Eth100M <--> switch1.ethg[1];
        switchS1.ethg[1] <--> Eth100M <--> switch1.ethg[2];
        switch1.ethg[0] <--> Eth100M <--> switch2.ethg[0];

        switch2.ethg[1] <--> Eth100M{@display("ls=magenta,3");} <--> listener.ethg[0];
}


network demoModification4 extends TsnNetworkBase
{
    @display("bgb=1500,800;bgi=backgrounds/background_grayArrows,s");
    
    @statistic[queuelen](source=warmup(atomic(constant0(switch2.eth[1].macLayer.queue.queue[0].packetPushEnded)+count(switch2.eth[1].macLayer.queue.queue[0].packetPushStarted)-count(switch2.eth[1].macLayer.queue.queue[0].packetPulled)- count(switch2.eth[1].macLayer.queue.queue[0].packetRemoved)-count(switch2.eth[1].macLayer.queue.queue[0].packetDropped))); unit=pk; record=figure; targetFigure=qlen);
    @figure[qlen](type=counter; pos=1175,310; label="Queue Length"; labelOffset=-50;decimalPlaces=3);
    
    submodules:
        
        talker: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=500,400");
            gates:
                ethg[1];
        }

        switch0: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=600,400;t=Split\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switchL1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=700,300");
            gates:
                ethg[2];
        }

        switchL2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=800,300");
            gates:
                ethg[2];
        }

        switchL3: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=900,300");
            gates:
                ethg[2];
        }

        switchL4: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1000,300");
            gates:
                ethg[2];
        }

        switchS1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=850,500;t=Drop even numbered\npackets,,darkgreen");
            gates:
                ethg[2];
        }

        switch1: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                eth[2].bitrate = 100Mbps;
                @display("p=1100,400;t=Merge\nblue stream,,darkgreen");
            gates:
                ethg[3];
        }

        switch2: <default("TsnSwitch")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                eth[1].bitrate = 100Mbps;
                @display("p=1200,400;t=ATS configured\nincrease cir/cbs,,darkgreen;i=,magenta");
            gates:
                ethg[2];
        }

        listener: <default("TsnDevice")> like IEthernetNetworkNode {
            parameters:
                eth[0].bitrate = 100Mbps;
                @display("p=1300, 400");
            gates:
                ethg[1];
        }


    connections:
        talker.ethg[0] <--> Eth100M <--> switch0.ethg[0];
        switch0.ethg[1] <--> Eth100M <--> switchL1.ethg[0];
        switch0.ethg[2] <--> Eth100M <--> switchS1.ethg[0];

        switchL1.ethg[1] <--> Eth100M <--> switchL2.ethg[0];
        switchL2.ethg[1] <--> Eth100M <--> switchL3.ethg[0];
        switchL3.ethg[1] <--> Eth100M <--> switchL4.ethg[0];

        switchL4.ethg[1] <--> Eth100M <--> switch1.ethg[1];
        switchS1.ethg[1] <--> Eth100M <--> switch1.ethg[2];
        switch1.ethg[0] <--> Eth100M <--> switch2.ethg[0];

        switch2.ethg[1] <--> Eth100M{@display("ls=magenta,3");} <--> listener.ethg[0];
}
