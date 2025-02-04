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

import inet.protocolelement.shaper.GroupEligibilityTimeMeter;

// Eligibibilty time metering for ATS with scheduler groups, has additional statistics
// @see GroupEligibilityTimeMeter, Ieee8021qcrFilter
// @author Teresa Lübeck

simple GroupEligibilityTimeMeterWithStatistics extends GroupEligibilityTimeMeter
{
    parameters:
        @class(GroupEligibilityTimeMeterWithStatistics);
        @signal[bucketEmptyTimeStatistic](type=simtime_t);
        @statistic[bucketEmptyTime](title="bucketEmptyTime compared to simulationTime"; source=bucketEmptyTimeStatistic; record=vector; unit=s; interpolationmode=none);
}