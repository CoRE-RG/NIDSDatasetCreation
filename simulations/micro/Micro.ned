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

package nidsdatasetcreation.simulations.micro;

import inet.node.contract.IEthernetNetworkNode;
import nidsdatasetcreation.networks.scenarios.TsnNetworkScenario;

network Micro extends TsnNetworkScenario
{
    types:
        channel Eth100M_0m extends inet.node.ethernet.Eth100M
        {
            length = 0m;
        }
    submodules:
        node1: <> like IEthernetNetworkNode {
            @display("p=274,100");
        }

        node2: <> like IEthernetNetworkNode {
            @display("p=477,100");
        }

        switch1: <> like IEthernetNetworkNode {
            @display("p=377,100");
        }
    connections:
        node1.ethg++ <--> Eth100M_0m <--> switch1.ethg++;
        node2.ethg++ <--> Eth100M_0m <--> switch1.ethg++;
}
