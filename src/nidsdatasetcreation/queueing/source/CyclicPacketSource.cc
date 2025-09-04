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

#include "CyclicPacketSource.h"


namespace NIDSDatasetCreation {

Define_Module(CyclicPacketSource);

void CyclicPacketSource::initialize(int stage)
{

    if (stage == INITSTAGE_LOCAL) {
        ActivePacketSource::initialize(stage);
        const char *productionIntervalsStr = par("productionIntervals").stringValue();
        productionIntervals =  cStringTokenizer(productionIntervalsStr).asDoubleVector();
        productionIntervalCounter = 0;
    }
    else if (stage==INITSTAGE_QUEUEING) {
        checkPacketOperationSupport(outputGate);
        if (!productionTimer->isScheduled())
            scheduleProductionTimerAndProducePacket();
    }
    else {
        ActivePacketSource::initialize(stage);
    }
}

void CyclicPacketSource::handleMessage(cMessage *message)
{
    if (message == productionTimer) {
        if (consumer == nullptr || consumer.canPushSomePacket()) {
            double nextProductionTime = productionIntervals.at(productionIntervalCounter);
            scheduleProductionTimer(nextProductionTime);
            productionIntervalCounter = (productionIntervalCounter+1)%productionIntervals.size();
            producePacket();
        }
    } else
        throw cRuntimeError("Unknown message");
}

void CyclicPacketSource::scheduleProductionTimerAndProducePacket()
{
    if (!initialProductionOffsetScheduled && initialProductionOffset >= CLOCKTIME_ZERO) {
        scheduleProductionTimer(initialProductionOffset);
        initialProductionOffsetScheduled = true;
    }
    else if (consumer == nullptr || consumer.canPushSomePacket()) {
        scheduleProductionTimer(productionIntervals[productionIntervalCounter]);
        producePacket();
    }
}
} // namespace

