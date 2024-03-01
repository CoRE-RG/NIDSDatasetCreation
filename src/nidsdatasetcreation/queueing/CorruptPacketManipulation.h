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

#ifndef __NIDSDATASETCREATION_CORRUPTPACKETMANIPULATION_H_
#define __NIDSDATASETCREATION_CORRUPTPACKETMANIPULATION_H_

#include <omnetpp.h>
#include "nidsdatasetcreation/queueing/base/CorruptPacketFlowBase.h"

using namespace omnetpp;

namespace NIDSDatasetCreation {

#define MANIPULATED_KEY_STR "[Manipulated-"

/**
 * @brief Corruption class that is able to manipulate packets
 * 
 * @sa CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketElimination, CorruptPacketInjection, CorruptPacketReordering
 * 
 * @ingroup queueing
 * 
 * @author Philipp Meyer
 */
class CorruptPacketManipulation : public CorruptPacketFlowBase
{
  protected:
    /**
     * @brief destination port of the manipulated packet
     */
    uint16_t destPort;
    /**
     * @brief if true, the destination port of the manipulated packet is set to destPort
     */
    bool destPortSet = false;
    /**
     * @brief source port of the manipulated packet
     */
    uint16_t srcPort;
    /**
     * @brief if true, the source port of the manipulated packet is set to srcPort
     */
    bool srcPortSet = false;
    /**
     * @brief destination IP address of the manipulated packet
     */
    inet::Ipv4Address destIpAddress;
    /**
     * @brief source IP address of the manipulated packet
     */
    inet::Ipv4Address srcIpAddress;
    /**
     * @brief destination MAC address of the manipulated packet
     */
    inet::MacAddress destMacAddress;
    /**
     * @brief source MAC address of the manipulated packet
     */
    inet::MacAddress srcMacAddress;
    /**
     * @brief Q-Tag priority (pcp) manipulated packet
     */
    uint8_t priority;
    /**
     * @brief if true, the Q-Tag priority (pcp) of the manipulated packet is set to priority
     */
    bool prioritySet = false;
    /**
     * @brief Q-Tag vlan id of manipulated packet
     */
    uint16_t vid;
    /**
     * @brief if true, the Q-Tag vlan id of the manipulated packet is set to vid
     */
    bool vidSet = false;

  private:
    /**
     * @brief Payload size of manipulated packet
     */
    size_t payload;

  protected:
    virtual void handleParameterChange(const char* parname) override;
    virtual void initialize(int stage) override;
    virtual void processPacket(inet::Packet* packet) override;

  private:
    /**
     * @brief Get the payload size from the parameter
     * 
     * @return the payload size
     */
    size_t getPayloadBytes();
};

} //namespace

#endif
