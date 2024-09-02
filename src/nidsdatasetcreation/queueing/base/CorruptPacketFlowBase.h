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

#ifndef __NIDSDATASETCREATION_CORRUPTPACKETFLOWBASE_H_
#define __NIDSDATASETCREATION_CORRUPTPACKETFLOWBASE_H_

#include <vector>
#include <omnetpp.h>
#include "inet/common/packet/PacketFilter.h"
#include "inet/queueing/base/PacketFlowBase.h"

using namespace omnetpp;

namespace NIDSDatasetCreation {

#define CORRUPTED_KEY_STR "[Corrupted-"
#define CORRUPTED_END_STR "]"
#define START_BENIGN_LABEL "BENIGN RECOVERED"

/**
 * @brief Corruptible packet flow base
 *
 * @sa PacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketManipulation, CorruptPacketReordering
 *
 * @ingroup queueing
 *
 * @author Philipp Meyer
 */
class CorruptPacketFlowBase : public inet::queueing::PacketFlowBase
{
  protected:
    /**
     * @brief List of packets that are waiting to be forwarded
     */
    std::vector<inet::Packet*> outPackets;
    /**
     * @brief Number of executed corruptions
     */
    size_t corruptionCount;
    /**
     * @brief Last simulation time a corruption took place
     */
    simtime_t lastCorruptionTime;
    /**
     * @brief Label which is assigned to packets by the module
     */
    std::string label;

  private:
    /**
     * @brief Packet filter for matching of packets that can be corrupted
     */
    inet::PacketFilter* packetFilter;
    /**
     * @brief Probability that a matching packet is corrupted
     */
    double probability;
    /**
     * @brief Minimum interval between corruptions
     */
    double minInterval;
    /**
     * @brief True if previous packet was corrupted
     */
    bool previousPacketCorrupted;
    /**
     * @brief Signal emitted when corruption is executed
     */
    static simsignal_t corruptionSignal;

  public:
    /**
     * @brief Constructor
     */
    CorruptPacketFlowBase();
    /**
     * @brief Destructor
     */
    virtual ~CorruptPacketFlowBase();
    virtual bool supportsPacketStreaming(const cGate *gate) const override { return false; }
    virtual void pushPacket(inet::Packet *packet, const cGate *gate) override;
    virtual bool canPullSomePacket(const cGate *gate) const override;
    virtual inet::Packet *canPullPacket(const cGate *gate) const override;
    virtual inet::Packet *pullPacket(const cGate *gate) override;

  protected:
    virtual void handleParameterChange(const char* parname) override;
    virtual void initialize(int stage) override;
    virtual void processPacket(inet::Packet* packet) override;
    /**
     * @brief pullPacket if it is called inside one module
     *
     * @return Returns packet
     */
    virtual inet::Packet *selfPullPacket(const cGate *gate);
    /**
     * @brief Check if execution of corruption is allowed
     *
     * @return Returns TRUE if execution is allowed
     */
    virtual bool performCorruption();
    /**
     * @brief Matches a given packet to the current packet filter
     *
     * @param Given packet
     *
     * @return Returns TRUE if packet matches filter
     */
    virtual bool match(inet::Packet* packet);
    /**
     * @brief Set label string as label tag to a given packet
     *
     * @param packet Given packet
     * @param label Label that is attached as a tag to the given packet
     */
    virtual void setLabel(inet::Packet* packet, std::string label);

  private:
    /**
     * @brief Get the probability from the parameter
     *
     * @return the probability
     */
    double getProbability();
    /**
     * @brief Get the minimum interval from the parameter
     *
     * @return the minimum interval
     */
    double getMinInterval();
};

} //namespace

#endif
