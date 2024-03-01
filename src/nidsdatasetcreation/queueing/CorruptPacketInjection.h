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

#ifndef __NIDSDATASETCREATION_CORRUPTPACKETINJECTION_H_
#define __NIDSDATASETCREATION_CORRUPTPACKETINJECTION_H_

#include <omnetpp.h>
#include "inet/linklayer/common/MacAddress.h"
#include "nidsdatasetcreation/queueing/base/CorruptPacketFlowBase.h"

using namespace omnetpp;

namespace NIDSDatasetCreation {

#define INJECTED_KEY_STR "[Injected-"

/**
 * @brief Corruption class that is able to inject packets
 * 
 * @sa CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketManipulation, CorruptPacketReordering
 * 
 * @ingroup queueing
 * 
 * @author Philipp Meyer
 */
class CorruptPacketInjection : public CorruptPacketFlowBase
{
  protected:
    /**
     * @brief destination port of the injected packet
     */
    uint16_t destPort;
    /**
     * @brief source port of the injected packet
     */
    uint16_t srcPort;
    /**
     * @brief destination IP address of the injected packet
     */
    inet::Ipv4Address destIpAddress;
    /**
     * @brief source IP address of the injected packet
     */
    inet::Ipv4Address srcIpAddress;
    /**
     * @brief destination MAC address of the injected packet
     */
    inet::MacAddress destMacAddress;
    /**
     * @brief source MAC address of the injected packet
     */
    inet::MacAddress srcMacAddress;
    /**
     * @brief if Q-Tag is added to the injected packet
     */
    bool addQTag;
    /**
     * @brief Q-Tag priority (pcp) of injected packet
     */
    uint8_t priority;
    /**
     * @brief Q-Tag vlan id of injected packet
     */
    uint16_t vid;

  private:
    /**
     * @brief Packet injection interval
     */
    simtime_t injectionInterval;
    /**
     * @brief Self message id of current self message
     */
    uint64_t selfMessageId;
    /**
     * @brief Payload size of injected packet
     */
    size_t payload;

  protected:
    virtual void handleParameterChange(const char* parname) override;
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;

  private:
    /**
     * @brief Create a packet for injection
     * 
     * @return the  packet
     */
    inet::Packet* createInjectionPacket();
    /**
     * @brief Schedule next injection
     */
    void scheduleInjectionInterval();
    /**
     * @brief Get the payload size from the parameter
     * 
     * @return the payload size in bytes
     */
    size_t getPayloadBytes();
};

} //namespace

#endif
