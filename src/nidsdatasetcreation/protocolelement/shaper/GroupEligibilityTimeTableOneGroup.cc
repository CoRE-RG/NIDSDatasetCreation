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

#include <nidsdatasetcreation/protocolelement/shaper/GroupEligibilityTimeTableOneGroup.h>

namespace NIDSDatasetCreation {

Define_Module(GroupEligibilityTimeTableOneGroup);

void GroupEligibilityTimeTableOneGroup::updateGroupEligibilityTime(std::string group, clocktime_t newTime)
{
    if (groupEligibilityTimeTable.find("groupEligibilityTime") == groupEligibilityTimeTable.end())
    {
        groupEligibilityTimeTable["groupEligibilityTime"] = 0;
    }

    clocktime_t currentTime = groupEligibilityTimeTable["groupEligibilityTime"];

    if (newTime > currentTime)
    {
        groupEligibilityTimeTable["groupEligibilityTime"] = newTime;
    }
}

clocktime_t GroupEligibilityTimeTableOneGroup::getGroupEligibilityTime(std::string group)
{
    if (groupEligibilityTimeTable.find("groupEligibilityTime") == groupEligibilityTimeTable.end())
    {
        groupEligibilityTimeTable["groupEligibilityTime"] = 0;
    }

    return groupEligibilityTimeTable["groupEligibilityTime"];
}

} /* namespace NIDSDatasetCreation */
