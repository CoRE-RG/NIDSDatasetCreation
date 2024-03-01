package nidsdatasetcreation.simulations.test;

import inet.node.contract.IEthernetNetworkNode;
import nidsdatasetcreation.networks.scenarios.TsnNetworkScenario;

network Test extends TsnNetworkScenario
{
    types:
        channel Eth1G_2m extends inet.node.ethernet.Eth1G
        {
            length = 2m;
        }
    submodules:
        switch: <> like IEthernetNetworkNode {
            @display("p=406,100");
        }
        node1: <> like IEthernetNetworkNode {
            @display("p=280,100");
        }
        node2: <> like IEthernetNetworkNode {
            @display("p=534,100");
        }
    connections:
        node1.ethg++ <--> Eth1G_2m <--> switch.ethg++;
        node2.ethg++ <--> Eth1G_2m <--> switch.ethg++;
}
