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

#ifndef NIDSDATASETCREATION_PROTOCOLELEMENT_SHAPER_GROUPELIGIBILITYTIMETABLEONEGROUP_H_
#define NIDSDATASETCREATION_PROTOCOLELEMENT_SHAPER_GROUPELIGIBILITYTIMETABLEONEGROUP_H_

#include "inet/protocolelement/shaper/GroupEligibilityTimeTable.h"

using namespace inet;

namespace NIDSDatasetCreation {

/**
 * @brief Class with a single group eligibility time for all ATS schedulers in a filter module
 *
 * @sa GroupEligibilityTimeTable, Ieee8021qcrFilter
 *
 * @author Teresa Lübeck
 */

class GroupEligibilityTimeTableOneGroup : public GroupEligibilityTimeTable {
public:
    /**
     * Updates groupEligibilityTime, if newTime is more recent than the time in the table.
     * "Most recent value of the eligibilityTime variable from the previous frame" [Ieee802.1Qcr - 8.6.11.3.10]
     */
    virtual void updateGroupEligibilityTime(std::string group, clocktime_t newTime) override;

    /**
     * Returns the groupEligibilityTime
     */
    virtual clocktime_t getGroupEligibilityTime(std::string group) override;

};

} /* namespace NIDSDatasetCreation */

#endif /* NIDSDATASETCREATION_PROTOCOLELEMENT_SHAPER_GROUPELIGIBILITYTIMETABLEONEGROUP_H_ */
