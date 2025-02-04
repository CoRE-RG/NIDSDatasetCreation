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

#include <nidsdatasetcreation/protocolelement/shaper/GroupEligibilityTimeTableWithStatistics.h>

namespace NIDSDatasetCreation {

Define_Module(GroupEligibilityTimeTableWithStatistics);


void GroupEligibilityTimeTableWithStatistics::updateGroupEligibilityTime(std::string group, clocktime_t newTime)
{
    if (groupEligibilityTimeTable.find(group) == groupEligibilityTimeTable.end())
    {
        groupEligibilityTimeTable[group] = 0;
    }

    // set up new signal and statistic for the group, if group not indexed yet
    if (groupIndexMap.find(group) == groupIndexMap.end())
    {
        groupIndexMap[group] = groupIdx;
        groupIdx++;

        simsignal_t signalGroupEligibilityTime = registerSignal(("group" + group + "EligibilityTimeSignal").c_str());
        cProperty* statisticTemplate = getProperties()->get("statisticTemplate", "groupEligibilityTime");
        getEnvir()->addResultRecorders(this, signalGroupEligibilityTime, ("group" + group + "EligibilityTimeSignal").c_str(), statisticTemplate);
        this -> groupEligibilityTimeStatisticSignal.push_back(signalGroupEligibilityTime);
    }

    clocktime_t currentTime = groupEligibilityTimeTable[group];

    if (newTime > currentTime)
    {
        groupEligibilityTimeTable[group] = newTime;

        emit(this->groupEligibilityTimeStatisticSignal[groupIndexMap[group]], CLOCKTIME_AS_SIMTIME(newTime - currentTime));
    }

}



} /* namespace NIDSDatasetCreation */
