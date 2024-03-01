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

#include "nidsdatasetcreation/common/packet/labeling/LabelManager.h"

#include <vector>
#include "nidsdatasetcreation/common/ModuleAccess.h"

namespace NIDSDatasetCreation {

Define_Module(LabelManager);

LabelManager::LabelManager() : cSimpleModule()
{
    label = "";
}

void LabelManager::initialize(int stage)
{
    if (stage == inet::INITSTAGE_LAST) {
        this->handleParameterChange("label");
    }
}

void LabelManager::handleParameterChange(const char* parname)
{
    if (parname != nullptr || !strcmp(parname, "label")) {
        std::string oldlabel = label;
        label = par("label").stdstringValue();
        if (strcmp(oldlabel.c_str(), label.c_str())) {
            distributeRecordingLabel();
        }
    }
}

void LabelManager::distributeRecordingLabel()
{
    const char* labelingModuleTypeName = par("labelingModuleTypeName").stringValue();
    std::vector<cModule*> modules = NIDSDatasetCreation::findModulesWhereverInNode(labelingModuleTypeName, this->getParentModule());
    for (cModule* &i : modules) {
        if (i->isVector()) {
            for (int j=0; j<i->getVectorSize(); j++) {
                i->getParentModule()->getSubmodule(i->getName(), j)->par("label").setStringValue(label.c_str());
            }
        }
        else {
            i->par("label").setStringValue(label.c_str());
        }
    }
}

} //namespace
