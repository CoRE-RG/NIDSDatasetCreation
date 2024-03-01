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

#include "CorruptPacketDelay.h"

namespace NIDSDatasetCreation {

Define_Module(CorruptPacketDelay);

CorruptPacketDelay::CorruptPacketDelay()
{
    this->selfMessageIds = std::vector<msgid_t>();
    this->backlogPackets = std::vector<inet::Packet*>();
}

CorruptPacketDelay::~CorruptPacketDelay()
{
    while(!this->backlogPackets.empty()) {
        delete this->backlogPackets.front();
        this->backlogPackets.erase(this->backlogPackets.begin());
    }
}

void CorruptPacketDelay::pushPacket(inet::Packet *packet, const cGate *gate)
{
    Enter_Method("pushPacket");
    take(packet);
    simtime_t backlogWaitTime = this->lastCorruptionTime + this->backlogDelayTime - simTime();
    if ((!this->selfMessageIds.empty()) && backlogWaitTime > 0) {
        this->backlogPackets.push_back(packet);
    }
    else {
        checkPacketStreaming(nullptr);
        emit(inet::packetPushedInSignal, packet);
        processPacket(packet);
        handlePacketProcessed(packet);
        std::string packetName = packet->getName();
        size_t found = packetName.find(CORRUPTED_KEY_STR);
        if (found != std::string::npos) {
            this->bubble("Delay");
            this->getParentModule()->bubble("Delay");
            packetName.replace(found, std::strlen(CORRUPTED_KEY_STR), DELAYED_KEY_STR);
            packet->setName(packetName.c_str());
            this->selfMessageIds.push_back(packet->getId());
            packet->setTimestamp(this->getDelayTime());
            this->scheduleAt(simTime() + packet->getTimestamp(), packet);
        }
        else {
            this->outPackets.push_back(packet);
        }
    }
    while (!this->outPackets.empty()) {
        packet = this->outPackets.front();
        this->outPackets.erase(this->outPackets.begin());
        emit(inet::packetPushedOutSignal, packet);
        pushOrSendPacket(packet, outputGate, consumer);
        updateDisplayString();
    }
}

bool CorruptPacketDelay::canPullSomePacket(const cGate *gate) const
{
    return true;
}

inet::Packet* CorruptPacketDelay::canPullPacket(const cGate *gate) const
{
    Enter_Method("canPullPacket");
    auto packet = PacketFlowBase::canPullPacket(gate);
    simtime_t backlogWaitTime = (const_cast<CorruptPacketDelay*>(this))->lastCorruptionTime + (const_cast<CorruptPacketDelay*>(this))->backlogDelayTime - simTime();
    if ((!(const_cast<CorruptPacketDelay*>(this))->selfMessageIds.empty()) && backlogWaitTime > 0) {
        (const_cast<CorruptPacketDelay*>(this))->scheduleAt(simTime() + backlogWaitTime, new cMessage("Trigger Can Pull Changed"));
        packet = nullptr;
    }
    else if (packet != nullptr) {
        packet = (const_cast<CorruptPacketDelay*>(this))->pullPacket(gate);
        std::string packetName = packet->getName();
        size_t found = packetName.find(CORRUPTED_KEY_STR);
        if (found != std::string::npos) {
            this->bubble("Delay");
            this->getParentModule()->bubble("Delay");
            packetName.replace(found, std::strlen(CORRUPTED_KEY_STR), DELAYED_KEY_STR);
            packet->setName(packetName.c_str());
            (const_cast<CorruptPacketDelay*>(this))->selfMessageIds.push_back(packet->getId());
            (const_cast<CorruptPacketDelay*>(this))->scheduleAt(simTime() + (const_cast<CorruptPacketDelay*>(this))->getDelayTime(), packet);
            packet = this->canPullPacket(gate);
        }
        else {
            (const_cast<CorruptPacketDelay*>(this))->outPackets.push_back(packet);
        }
    }
    if (!(const_cast<CorruptPacketDelay*>(this))->outPackets.empty()) {
        packet = (const_cast<CorruptPacketDelay*>(this))->outPackets.front();
    }
    return packet;
}

void CorruptPacketDelay::handleParameterChange(const char *parname)
{
    CorruptPacketFlowBase::handleParameterChange(parname);
    if (!parname || !strcmp(parname, "delayTime")) {
        this->delayTime = par("delayTime").doubleValue();
    }
    if (!parname || !strcmp(parname, "backlogDelayTime")) {
        this->backlogDelayTime = par("backlogDelayTime").doubleValue();
    }
}

void CorruptPacketDelay::initialize(int stage)
{
    CorruptPacketFlowBase::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL) {
        this->handleParameterChange("backlogDelayTime");
        WATCH(this->delayTime);
        WATCH_VECTOR(this->selfMessageIds);
    }
}

void CorruptPacketDelay::handleMessage(cMessage* message)
{
    if (message->isSelfMessage()) {
        if (this->findAndRemoveDelayedMessageId(message->getId())) {
            auto packet = check_and_cast<inet::Packet*>(message);
            if (this->consumer == nullptr) {
                this->outPackets.push_back(packet);
                this->handleCanPullPacketChanged(this->outputGate);
            }
            else {
                emit(inet::packetPushedOutSignal, packet);
                pushOrSendPacket(packet, this->outputGate, this->consumer);
                updateDisplayString();
                while(this->selfMessageIds.empty() && !this->backlogPackets.empty()) {
                    packet = this->backlogPackets.front();
                    this->backlogPackets.erase(this->backlogPackets.begin());
                    this->pushPacket(packet, this->outputGate);
                }
            }
        }
        else {
            if (this->consumer == nullptr) {
                this->handleCanPullPacketChanged(this->outputGate);
                delete message;
            }
            else {
                auto packet = check_and_cast<inet::Packet*>(message);
                this->pushPacket(packet, this->outputGate);
            }
        }
    }
    else {
        CorruptPacketFlowBase::handleMessage(message);
    }
}

bool CorruptPacketDelay::findAndRemoveDelayedMessageId(msgid_t messageId)
{
    bool messageIdFound = false;
    uint64_t index = 0;
    for (msgid_t selfMessageId : this->selfMessageIds)
    {
        if (selfMessageId == messageId)
        {
            messageIdFound = true;
            break;
        }
        index++;
    }
    if (messageIdFound)
    {
        this->selfMessageIds.erase(this->selfMessageIds.begin() + index);
    }
    return messageIdFound;
}

simtime_t CorruptPacketDelay::getDelayTime()
{
    this->handleParameterChange("delayTime");
    return this->delayTime;
}

} //namespace
