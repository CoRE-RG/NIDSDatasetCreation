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

#ifndef __NIDSDATASETCREATION_CORRUPTPACKETDELAY_H_
#define __NIDSDATASETCREATION_CORRUPTPACKETDELAY_H_

#include <vector>
#include <omnetpp.h>
#include "nidsdatasetcreation/queueing/base/CorruptPacketFlowBase.h"

using namespace omnetpp;

namespace NIDSDatasetCreation {

#define DELAYED_KEY_STR "[Delayed-"

/**
 * @brief Corruption class that is able to delay packets
 *
 * @sa CorruptPacketFlowBase, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketManipulation, CorruptPacketReordering
 *
 * @ingroup queueing
 *
 * @author Philipp Meyer
 */
class CorruptPacketDelay : public CorruptPacketFlowBase
{
  protected:
    /**
     * @brief The time following packets get delayed at maximum
     */
    simtime_t backlogDelayTime;
    /**
     * @brief List of following packets waiting for forwarding
     */
    std::vector<inet::Packet*> backlogPackets;

  private:
    /**
     * @brief The time a targeted packet gets delayed
     */
    simtime_t delayTime;
    /**
     * @brief List of ids of current self messages 
     */
    std::vector<msgid_t> selfMessageIds;

  public:
    /**
     * @brief Construct a new Corrupt Packet Delay object
     */
    CorruptPacketDelay();
    /**
     * @brief Destroy the Corrupt Packet Delay object
     * 
     */
    virtual ~CorruptPacketDelay();
    virtual void pushPacket(inet::Packet *packet, const cGate *gate) override;
    virtual bool canPullSomePacket(const cGate *gate) const override;
    virtual inet::Packet* canPullPacket(const cGate *gate) const override;

  protected:
    virtual void handleParameterChange(const char* parname) override;
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage* message) override;

  private:
    /**
     * @brief Find and remove delayed message id
     * 
     * @param messageId id of the message
     * 
     * @return true if the message id was found and removed 
     */
    bool findAndRemoveDelayedMessageId(msgid_t messageId);
    /**
     * @brief Get the delay time from the parameter
     * 
     * @return the delay time
     */
    simtime_t getDelayTime();
};

} //namespace

#endif
