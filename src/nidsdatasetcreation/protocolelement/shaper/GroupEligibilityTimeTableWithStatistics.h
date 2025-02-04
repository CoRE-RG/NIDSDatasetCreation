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

#ifndef NIDSDATASETCREATION_PROTOCOLELEMENT_SHAPER_GROUPELIGIBILITYTIMETABLEWITHSTATISTICS_H_
#define NIDSDATASETCREATION_PROTOCOLELEMENT_SHAPER_GROUPELIGIBILITYTIMETABLEWITHSTATISTICS_H_

#include "inet/protocolelement/shaper/GroupEligibilityTimeTable.h"

using namespace inet;

namespace NIDSDatasetCreation {

/**
 * @brief Class with additional statistics for groupEligibiltiyTimeTable
 *
 * @sa GroupEligibilityTimeTable, Ieee8021qcrFilter, micronetFilter
 *
 * @author Teresa Lübeck
 */

class GroupEligibilityTimeTableWithStatistics : public GroupEligibilityTimeTable
{
    protected:
        std::vector<simsignal_t> groupEligibilityTimeStatisticSignal;

        std::map<std::string, int> groupIndexMap;
        int groupIdx = 0;

    public:
        virtual void updateGroupEligibilityTime(std::string group, clocktime_t newTime) override;
};

} /* namespace NIDSDatasetCreation */

#endif /* NIDSDATASETCREATION_PROTOCOLELEMENT_SHAPER_GROUPELIGIBILITYTIMETABLEWITHSTATISTICS_H_ */
