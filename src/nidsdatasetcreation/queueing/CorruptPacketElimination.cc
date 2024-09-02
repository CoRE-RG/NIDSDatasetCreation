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

#include "nidsdatasetcreation/queueing/CorruptPacketElimination.h"

#include <string>
#include "inet/queueing/base/PacketServerBase.h"

namespace NIDSDatasetCreation {

Define_Module(CorruptPacketElimination);

void CorruptPacketElimination::pushPacket(inet::Packet *packet, const cGate *gate)
{
    Enter_Method("pushPacket");
    take(packet);
    checkPacketStreaming(nullptr);
    emit(inet::packetPushedInSignal, packet);
    processPacket(packet);
    std::string packetName = packet->getName();
    if (packetName.find(CORRUPTED_KEY_STR) != std::string::npos) {
        this->bubble("Eliminate");
        this->getParentModule()->bubble("Eliminate");
        delete packet;
        packet = nullptr;
    }
    if (packet != nullptr) {
        handlePacketProcessed(packet);
        if (!this->outPackets.empty()) {
            this->outPackets.push_back(packet);
            packet = this->outPackets.front();
            this->outPackets.erase(this->outPackets.begin());
        }
        emit(inet::packetPushedOutSignal, packet);
        pushOrSendPacket(packet, outputGate, consumer);
        updateDisplayString();
    }
}

bool CorruptPacketElimination::canPullSomePacket(const cGate *gate) const
{
    return true;
}

inet::Packet* CorruptPacketElimination::canPullPacket(const cGate *gate) const
{
    Enter_Method("canPullPacket");
    auto packet = PacketFlowBase::canPullPacket(gate);
    if (packet != nullptr) {
        packet = (const_cast<CorruptPacketElimination*>(this))->selfPullPacket(gate);
        std::string packetName = packet->getName();
        if (packetName.find(CORRUPTED_KEY_STR) != std::string::npos) {
            this->bubble("Eliminate");
            this->getParentModule()->bubble("Eliminate");
            delete packet;
            packet = this->canPullPacket(gate);
        }
        else {
            (const_cast<CorruptPacketElimination*>(this))->outPackets.push_back(packet);
        }
    }
    if (!(const_cast<CorruptPacketElimination*>(this))->outPackets.empty()) {
        packet = (const_cast<CorruptPacketElimination*>(this))->outPackets.front();
    }
    return packet;
}

void CorruptPacketElimination::initialize(int stage)
{
    CorruptPacketFlowBase::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL) {
    }
}

} //namespace
