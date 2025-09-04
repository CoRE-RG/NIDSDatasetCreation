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

#ifndef QUEUEING_SOURCE_CYCLICPACKETSOURCE_H_
#define QUEUEING_SOURCE_CYCLICPACKETSOURCE_H_

#include "inet/queueing/source/ActivePacketSource.h"


using namespace inet;

namespace NIDSDatasetCreation {

/**
 * @brief Cyclic packet source
 *
 * @ingroup queueing
 *
 * @author Teresa Lübec
 */
class INET_API CyclicPacketSource : public queueing::ActivePacketSource
{
    protected:
        /*
         * @brief list of intervals between two consecutive packets
         */
        std::vector<double> productionIntervals;
        /*
         * @brief position in interval list
         */
        int productionIntervalCounter;

    protected:
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;
    virtual void scheduleProductionTimerAndProducePacket() override;
};

} //namespace

#endif /* QUEUEING_SOURCE_CYCLICPACKETSOURCE_H_ */
