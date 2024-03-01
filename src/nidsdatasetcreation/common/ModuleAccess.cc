//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include "nidsdatasetcreation/common/ModuleAccess.h"

namespace NIDSDatasetCreation {

static cModule* findSubmodTypeRecursive(cModule *curmod, const char *nedTypeName)
{
    for (cModule::SubmoduleIterator i(curmod); !i.end(); i++)
    {
        cModule* submod = *i;
        if (!strcmp(submod->getNedTypeName(), nedTypeName))
            return submod;
        cModule* foundmod = findSubmodTypeRecursive(submod, nedTypeName);
        if (foundmod)
            return foundmod;
    }
    return nullptr;
}

std::vector<cModule*> findModulesWhereverInNode(const char *nedTypeName, cModule *from)
{
    std::vector<cModule*> modules = {};
    for (cModule::SubmoduleIterator i(from); !i.end(); i++)
    {
        cModule* module = findSubmodTypeRecursive(*i, nedTypeName);
        if (module)
        {
            modules.push_back(module);
        }
    }
    return modules;
}

} // namespace
