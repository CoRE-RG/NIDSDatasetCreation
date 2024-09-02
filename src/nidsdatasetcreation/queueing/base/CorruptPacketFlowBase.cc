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

#include "nidsdatasetcreation/queueing/base/CorruptPacketFlowBase.h"

#include "inet/common/LabelsTag_m.h"

namespace NIDSDatasetCreation {

Define_Module(CorruptPacketFlowBase);

simsignal_t CorruptPacketFlowBase::corruptionSignal = registerSignal("corruption");

CorruptPacketFlowBase::CorruptPacketFlowBase()
{
    this->outPackets = std::vector<inet::Packet*>();
    this->packetFilter = new inet::PacketFilter();
    this->corruptionCount = 0;
    this->lastCorruptionTime = 0;
    this->previousPacketCorrupted = false;
}

CorruptPacketFlowBase::~CorruptPacketFlowBase()
{
    while(!this->outPackets.empty()) {
        delete this->outPackets.front();
        this->outPackets.erase(this->outPackets.begin());
    }
    delete this->packetFilter;
}

void CorruptPacketFlowBase::pushPacket(inet::Packet *packet, const cGate *gate)
{
    Enter_Method("pushPacket");
    take(packet);
    checkPacketStreaming(nullptr);
    emit(inet::packetPushedInSignal, packet);
    processPacket(packet);
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

bool CorruptPacketFlowBase::canPullSomePacket(const cGate *gate) const
{
    return (!this->outPackets.empty()) || PacketFlowBase::canPullSomePacket(gate);
}

inet::Packet* CorruptPacketFlowBase::canPullPacket(const cGate *gate) const
{
    inet::Packet* packet = nullptr;
    if (this->outPackets.empty()) {
        packet = PacketFlowBase::canPullPacket(gate);
    }
    else {
        packet = this->outPackets.front();
    }
    return packet;
}

inet::Packet* CorruptPacketFlowBase::pullPacket(const cGate *gate)
{
    Enter_Method("pullPacket");
    checkPacketStreaming(nullptr);
    inet::Packet* packet = nullptr;
    if (this->outPackets.empty()) {
        packet = provider.pullPacket();
        take(packet);
        emit(inet::packetPulledInSignal, packet);
        processPacket(packet);
        handlePacketProcessed(packet);
    }
    else {
        packet = this->outPackets.front();
        this->outPackets.erase(this->outPackets.begin());
    }
    emit(inet::packetPulledOutSignal, packet);
    if (collector!=nullptr)
        animatePullPacket(packet, outputGate, collector.getReferencedGate());
    updateDisplayString();
    return packet;
}

void CorruptPacketFlowBase::handleParameterChange(const char* parname)
{
    PacketFlowBase::handleParameterChange(parname);
    if (!parname || !strcmp(parname, "packetFilter")) {
        delete this->packetFilter;
        this->packetFilter = new inet::PacketFilter();
        this->packetFilter->setExpression(par("packetFilter").objectValue());
    }
    if (!parname || !strcmp(parname, "probability")) {
        this->probability = par("probability").doubleValue();
    }
    if (!parname || !strcmp(parname, "minInterval")) {
        this->minInterval = par("minInterval").doubleValue();
    }
    if (!parname || !strcmp(parname, "label")) {
        this->label = par("label").stringValue();
    }
}

void CorruptPacketFlowBase::initialize(int stage)
{
    PacketFlowBase::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL) {
        this->handleParameterChange("packetFilter");
        this->handleParameterChange("label");
        WATCH(corruptionCount);
        WATCH_PTRVECTOR(this->outPackets);
    }
}

void CorruptPacketFlowBase::processPacket(inet::Packet *packet)
{
    if (this->match(packet) && this->performCorruption()) {
        std::string name = packet->getName();
        name.append(CORRUPTED_KEY_STR + std::to_string(this->corruptionCount) + CORRUPTED_END_STR);
        packet->setName(name.c_str());
        this->setLabel(packet, this->label);
        this->previousPacketCorrupted = true;
    }
    else if (this->match(packet) && this->previousPacketCorrupted) {
        this->setLabel(packet, START_BENIGN_LABEL);
        this->previousPacketCorrupted = false;
    }
}

inet::Packet* CorruptPacketFlowBase::selfPullPacket(const cGate *gate)
{
    Enter_Method("pullPacket");
        checkPacketStreaming(nullptr);
        inet::Packet* packet = nullptr;
        if (this->outPackets.empty()) {
            packet = provider.pullPacket();
            take(packet);
            emit(inet::packetPulledInSignal, packet);
            processPacket(packet);
            handlePacketProcessed(packet);
        }
        else {
            packet = this->outPackets.front();
            this->outPackets.erase(this->outPackets.begin());
        }
        return packet;
}

bool CorruptPacketFlowBase::performCorruption()
{
    bool performCorruption = false;
    if ((simTime() - this->lastCorruptionTime) >= this->getMinInterval())
    {
        if (this->getRNG(0)->doubleRandIncl1() <= this->getProbability())
        {
            performCorruption = true;
            this->lastCorruptionTime = simTime();
            this->corruptionCount++;
            this->emit(this->corruptionSignal, true);
        }
    }
    return performCorruption;
}

bool CorruptPacketFlowBase::match(inet::Packet *packet)
{
    return this->packetFilter->matches(packet);
}

double CorruptPacketFlowBase::getProbability()
{
    this->handleParameterChange("probability");
    return this->probability;
}

double CorruptPacketFlowBase::getMinInterval()
{
    this->handleParameterChange("minInterval");
    return this->minInterval;
}

void CorruptPacketFlowBase::setLabel(inet::Packet* packet, std::string label)
{
    auto labelsTag = packet->addTag<inet::LabelsTag>();
    labelsTag->setLabelsArraySize(1);
    labelsTag->setLabels(0, label.c_str());
}

} //namespace
