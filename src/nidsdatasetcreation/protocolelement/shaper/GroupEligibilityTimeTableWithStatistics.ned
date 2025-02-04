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

package nidsdatasetcreation.protocolelement.shaper;

import inet.protocolelement.shaper.GroupEligibilityTimeTable;

// Stores group eligibility time for ATS schedulers, has additional statistics
// @see GroupEligibilityTimeTable, Ieee8021qcrFilter, micronetFilter
// @author Teresa Lübeck

simple GroupEligibilityTimeTableWithStatistics extends GroupEligibilityTimeTable
{
    parameters:
        @class(GroupEligibilityTimeTableWithStatistics);
        @signal[group*EligibilityTimeSignal](type=simtime_t);
        @statisticTemplate[groupEligibilityTime](title="groupEligibilityTime"; record=vector; unit=s; interpolationmode=none);
}