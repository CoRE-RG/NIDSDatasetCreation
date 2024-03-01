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

#include "nidsdatasetcreation/queueing/CorruptPacketReordering.h"

#include "nidsdatasetcreation/common/customWatch.h"

namespace NIDSDatasetCreation {

Define_Module(CorruptPacketReordering);

CorruptPacketReordering::CorruptPacketReordering()
{
    this->takenPackets = std::map<inet::Packet*, uint32_t>();
}

CorruptPacketReordering::~CorruptPacketReordering()
{
    for (std::map<inet::Packet*, uint32_t>::iterator it = this->takenPackets.begin(); it != this->takenPackets.end();) {
        delete it->first;
        this->takenPackets.erase(it++);
    }
}

void CorruptPacketReordering::pushPacket(inet::Packet *packet, const cGate *gate)
{
    Enter_Method("pushPacket");
    take(packet);
    checkPacketStreaming(nullptr);
    emit(inet::packetPushedInSignal, packet);
    processPacket(packet);
    handlePacketProcessed(packet);
    std::string packetName = packet->getName();
    size_t found = packetName.find(CORRUPTED_KEY_STR);
    if (found != std::string::npos) {
        this->bubble("Reorder");
        this->getParentModule()->bubble("Reorder");
        packetName.replace(found, std::strlen(CORRUPTED_KEY_STR), REORDERED_KEY_STR);
        packet->setName(packetName.c_str());
        this->takenPackets[packet] = 0;
    }
    else {
        this->outPackets.push_back(packet);
        if (this->matchStreamForPacketCounting && this->match(packet)) {
            this->incrementPassedPacketsCounters();
        }
        else if (!this->matchStreamForPacketCounting) {
            this->incrementPassedPacketsCounters();
        }
        this->injectReadyPackets(this->getNumberOfPacketsBeforeInjection());
    }
    while (!this->outPackets.empty()) {
        packet = this->outPackets.front();
        this->outPackets.erase(this->outPackets.begin());
        emit(inet::packetPushedOutSignal, packet);
        pushOrSendPacket(packet, outputGate, consumer);
        updateDisplayString();
    }
}

bool CorruptPacketReordering::canPullSomePacket(const cGate *gate) const
{
    return true;
}

inet::Packet* CorruptPacketReordering::canPullPacket(const cGate *gate) const
{
    Enter_Method("canPullPacket");
    auto packet = PacketFlowBase::canPullPacket(gate);
    if (packet != nullptr) {
        packet = (const_cast<CorruptPacketReordering*>(this))->pullPacket(gate);
        std::string packetName = packet->getName();
        size_t found = packetName.find(CORRUPTED_KEY_STR);
        if (found != std::string::npos) {
            this->bubble("Reorder");
            this->getParentModule()->bubble("Reorder");
            packetName.replace(found, std::strlen(CORRUPTED_KEY_STR), REORDERED_KEY_STR);
            packet->setName(packetName.c_str());
            (const_cast<CorruptPacketReordering*>(this))->takenPackets[packet] = 0;
            packet = this->canPullPacket(gate);
        }
        else {
            (const_cast<CorruptPacketReordering*>(this))->outPackets.push_back(packet);
            if ((const_cast<CorruptPacketReordering*>(this))->matchStreamForPacketCounting && (const_cast<CorruptPacketReordering*>(this))->match(packet)) {
                (const_cast<CorruptPacketReordering*>(this))->incrementPassedPacketsCounters();
            }
            else if (!(const_cast<CorruptPacketReordering*>(this))->matchStreamForPacketCounting) {
                (const_cast<CorruptPacketReordering*>(this))->incrementPassedPacketsCounters();
            }
            (const_cast<CorruptPacketReordering*>(this))->injectReadyPackets((const_cast<CorruptPacketReordering*>(this))->getNumberOfPacketsBeforeInjection());
        }
    }
    if (!(const_cast<CorruptPacketReordering*>(this))->outPackets.empty()) {
        packet = (const_cast<CorruptPacketReordering*>(this))->outPackets.front();
    }
    return packet;
}

void CorruptPacketReordering::handleParameterChange(const char* parname)
{
    CorruptPacketFlowBase::handleParameterChange(parname);
    if (!parname || !strcmp(parname, "numberOfPacketsBeforeInjection"))
    {
        this->numberOfPacketsBeforeInjection = par("numberOfPacketsBeforeInjection").intValue();
    }
    if (!parname || !strcmp(parname, "matchStreamForPacketCounting"))
    {
        this->matchStreamForPacketCounting = par("matchStreamForPacketCounting").boolValue();
    }
    if (!parname || !strcmp(parname, "injectTakenPacketsInRandomOrder"))
    {
        this->injectTakenPacketsInRandomOrder = par("injectTakenPacketsInRandomOrder").boolValue();
    }
}

void CorruptPacketReordering::initialize(int stage)
{
    CorruptPacketFlowBase::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL) {
        this->handleParameterChange("matchStreamForPacketCounting");
        this->handleParameterChange("injectTakenPacketsInRandomOrder");
        WATCH_KEYPTRMAP(this->takenPackets);
    }
}

uint32_t CorruptPacketReordering::getNumberOfPacketsBeforeInjection()
{
    this->handleParameterChange("numberOfPacketsBeforeInjection");
    return this->numberOfPacketsBeforeInjection;
}

void CorruptPacketReordering::incrementPassedPacketsCounters()
{
    for (std::map<inet::Packet*, uint32_t>::iterator it = this->takenPackets.begin(); it != this->takenPackets.end(); it++) {
        it->second++;
    }
}

void CorruptPacketReordering::injectReadyPackets(uint32_t minPassedPackets)
{
    bool outPacketsChanged = false;
    std::vector<inet::Packet*> outPacketsTemp = std::vector<inet::Packet*>();
    for (std::map<inet::Packet*, uint32_t>::iterator it = this->takenPackets.begin(); it != this->takenPackets.end();) {
        if (it->second >= minPassedPackets) {
            if (this->injectTakenPacketsInRandomOrder) {
                outPacketsTemp.push_back(it->first);
            } else {
                this->outPackets.push_back(it->first);
            }
            this->takenPackets.erase(it++);
            outPacketsChanged = true;
        }
        else {
            ++it;
        }
    }
    if (this->injectTakenPacketsInRandomOrder) {
        // Fisher–Yates shuffle:
        for (int i = outPacketsTemp.size()-1; i > 0; i--) {
            int j = this->getRNG(0)->intRand(i+1);
            inet::Packet* msg = outPacketsTemp[i];
            outPacketsTemp[i] = outPacketsTemp[j];
            outPacketsTemp[j] = msg;
        }
        for (int i = 0; i < outPacketsTemp.size(); i++) {
            this->outPackets[i] = outPacketsTemp[i];
        }
    }
    if (outPacketsChanged) {
        this->handleCanPullPacketChanged(this->outputGate);
    }
}

} //namespace
