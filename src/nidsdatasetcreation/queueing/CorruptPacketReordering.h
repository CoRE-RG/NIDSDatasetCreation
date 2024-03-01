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

#ifndef __NIDSDATASETCREATION_CORRUPTPACKETREORDERING_H_
#define __NIDSDATASETCREATION_CORRUPTPACKETREORDERING_H_

#include <map>
#include <omnetpp.h>
#include "nidsdatasetcreation/queueing/base/CorruptPacketFlowBase.h"

using namespace omnetpp;

namespace NIDSDatasetCreation {

#define REORDERED_KEY_STR "[Reordered-"

/**
 * @brief Corruption class that is able to reorder packets
 * 
 * @sa CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketManipulation
 * 
 * @ingroup queueing
 * 
 * @author Philipp Meyer
 */
class CorruptPacketReordering : public CorruptPacketFlowBase
{
  private:
    /**
     * @brief Map of packets that are taken from the input queue and are waiting for injection
     */
    std::map<inet::Packet*, uint32_t> takenPackets;
    /**
     * @brief Number of packets that a taken packet have to wait till it gets injected again
     */
    uint32_t numberOfPacketsBeforeInjection;
    /**
     * @brief true if counting packets is done just on packets of the same stream as the taken packets
     */
    bool matchStreamForPacketCounting;
    /**
     * @brief true if the taken packets ready for injection should be injected in random order
     */
    bool injectTakenPacketsInRandomOrder;

  public:
    /**
     * @brief Construct a new Corrupt Packet Reordering object
     */
    CorruptPacketReordering();
    /**
     * @brief Destroy the Corrupt Packet Reordering object
     */
    virtual ~CorruptPacketReordering();
    virtual void pushPacket(inet::Packet *packet, const cGate *gate) override;
    virtual bool canPullSomePacket(const cGate *gate) const override;
    virtual inet::Packet* canPullPacket(const cGate *gate) const override;

  protected:
    virtual void handleParameterChange(const char* parname) override;
    virtual void initialize(int stage) override;

  private:
    /**
     * @brief Get the number of packets before injection from the parameter
     * 
     * @return number of packets before injection 
     */
    uint32_t getNumberOfPacketsBeforeInjection();
    /**
     * @brief Increment the passed packets counters of taken packets
     */
    void incrementPassedPacketsCounters();
    /**
     * @brief Inject the ready packets into the output queue
     */
    void injectReadyPackets(uint32_t minPassedPackets);
};

} //namespace

#endif
