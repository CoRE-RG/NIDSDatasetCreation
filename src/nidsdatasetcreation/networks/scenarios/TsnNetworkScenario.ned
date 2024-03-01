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

package nidsdatasetcreation.networks.scenarios;

import inet.common.scenario.ScenarioManager;
import inet.networks.base.TsnNetworkBase;
import nidsdatasetcreation.common.packet.labeling.LabelManager;

// TSN network base with scenario and label manager
//
// @see TsnNetworkBase
//
// @author Philipp Meyer
//
network TsnNetworkScenario extends TsnNetworkBase
{
	submodules:
	    scenarioManager: ScenarioManager {
            @display("p=100,800;is=s");
        }
        labelManager: LabelManager {
        	@display("p=100,900;is=s");
        } 
}