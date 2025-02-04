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

#include <nidsdatasetcreation/protocolelement/shaper/GroupEligibilityTimeMeterWithStatistics.h>

#include "inet/common/DirectionTag_m.h"
#include "inet/linklayer/common/PcpTag_m.h"
#include "inet/protocolelement/shaper/EligibilityTimeTag_m.h"
#include "inet/linklayer/common/InterfaceTag_m.h"

using namespace inet;

namespace NIDSDatasetCreation
{
Define_Module(GroupEligibilityTimeMeterWithStatistics);

//bucketEmptyTimeStatisticSignal  = cComponent::registerSignal("bucketEmptyTimeStatistic");

void GroupEligibilityTimeMeterWithStatistics::initialize(int stage)
{
    GroupEligibilityTimeMeter::initialize(stage);
    bucketEmptyTimeStatisticSignal = registerSignal("bucketEmptyTimeStatistic");

}

void GroupEligibilityTimeMeterWithStatistics::meterPacket(Packet *packet)
{
    emitNumTokenChangedSignal(packet);
    clocktime_t arrivalTime = getClockTime();
    clocktime_t lengthRecoveryDuration = s((packet->getDataLength() + packetOverheadLength) / committedInformationRate).get();
    clocktime_t emptyToFullDuration = s(committedBurstSize / committedInformationRate).get();
    clocktime_t schedulerEligibilityTime = bucketEmptyTime + lengthRecoveryDuration;
    clocktime_t bucketFullTime = bucketEmptyTime + emptyToFullDuration;
    clocktime_t eligibilityTime;

    //update groupEligibilityTime
    auto packetDirection = packet->findTag<DirectionTag>();
    int pcp = 0;
    if (packetDirection->getDirection() == DIRECTION_INBOUND)
    {
        auto  pcpTag = packet->findTag<PcpInd>();
        pcp = pcpTag->getPcp();
    }
    else
    {
        auto pcpTag = packet->findTag<PcpReq>();
        pcp = pcpTag->getPcp();
    }
    auto iterface = packet->findTag<InterfaceInd>();
    int port = iterface->getInterfaceId();
    std::string group = std::to_string(port) + "-" + std::to_string(pcp);
    groupEligibilityTime = groupEligibilityTimeTable->getGroupEligibilityTime(group);

    eligibilityTime.setRaw(std::max(std::max(arrivalTime.raw(), groupEligibilityTime.raw()), schedulerEligibilityTime.raw()));
    if (maxResidenceTime == -1 || eligibilityTime <= arrivalTime + maxResidenceTime) {
        groupEligibilityTime = eligibilityTime;
        // write groupEligibilityTime back into table
        groupEligibilityTimeTable->updateGroupEligibilityTime(group, groupEligibilityTime);

        bucketEmptyTime = eligibilityTime < bucketFullTime ? schedulerEligibilityTime : schedulerEligibilityTime + eligibilityTime - bucketFullTime;

        emit(bucketEmptyTimeStatisticSignal, CLOCKTIME_AS_SIMTIME(bucketEmptyTime - getClockTime()));

        packet->addTagIfAbsent<EligibilityTimeTag>()->setEligibilityTime(eligibilityTime);
        emitNumTokenChangedSignal(packet);
    }

}






} /* namespace NIDSDatasetCreation */
