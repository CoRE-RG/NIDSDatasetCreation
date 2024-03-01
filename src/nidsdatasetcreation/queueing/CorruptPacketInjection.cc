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

#include "nidsdatasetcreation/queueing/CorruptPacketInjection.h"

#include "inet/common/checksum/EthernetCRC.h"
#include "inet/common/checksum/TcpIpChecksum.h"
#include "inet/common/MemoryOutputStream.h"
#include "inet/common/packet/chunk/ChunkAPI.h"
#include "inet/linklayer/ethernet/common/Ethernet.h"
#include "inet/linklayer/ethernet/common/EthernetMacHeader_m.h"
#include "inet/linklayer/ieee8021q/Ieee8021qTagHeader_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/physicallayer/wired/ethernet/EthernetPhyHeader_m.h"
#include "inet/transportlayer/udp/Udp.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"

namespace NIDSDatasetCreation {

Define_Module(CorruptPacketInjection);

void CorruptPacketInjection::handleParameterChange(const char* parname)
{
    CorruptPacketFlowBase::handleParameterChange(parname);
    if (!parname || !strcmp(parname, "injectionInterval")) {
        this->injectionInterval = par("injectionInterval").doubleValue();
        if (this->injectionInterval > 0) {
            cMessage* message = new cMessage("Trigger injection");
            this->selfMessageId = message->getId();
            scheduleAt(simTime() + this->injectionInterval, message);
        }
    }
    if (!parname || !strcmp(parname, "destPort")) {
        this->destPort = par("destPort").intValue();
    }
    if (!parname || !strcmp(parname, "srcPort")) {
        this->srcPort = par("srcPort").intValue();
    }
    if (!parname || !strcmp(parname, "destIpAddress")) {
        if (par("destIpAddress").stdstringValue().empty()) {
            this->destIpAddress = inet::Ipv4Address::UNSPECIFIED_ADDRESS;
        }
        else {
            this->destIpAddress.set(par("destIpAddress").stringValue());
        }
    }
    if (!parname || !strcmp(parname, "srcIpAddress")) {
        if (par("srcIpAddress").stdstringValue().empty()) {
            this->srcIpAddress = inet::Ipv4Address::UNSPECIFIED_ADDRESS;
        }
        else {
            this->srcIpAddress.set(par("srcIpAddress").stringValue());
        }
    }
    if (!parname || !strcmp(parname, "destMacAddress")) {
        if (par("destMacAddress").stdstringValue().empty()) {
            this->destMacAddress = inet::MacAddress::UNSPECIFIED_ADDRESS;
        }
        else {
            this->destMacAddress.setAddress(par("destMacAddress").stringValue());
        }
    }
    if (!parname || !strcmp(parname, "srcMacAddress")) {
        if (par("srcMacAddress").stdstringValue().empty()) {
            this->srcMacAddress = inet::MacAddress::UNSPECIFIED_ADDRESS;
        }
        else {
            this->srcMacAddress.setAddress(par("srcMacAddress").stringValue());
        }
    }
    if (!parname || !strcmp(parname, "priority") || !strcmp(parname, "vid")) {
        if (par("priority").intValue() >= 0 && par("vid").intValue() >= 0) {
            this->priority = static_cast<uint8_t>(par("priority").intValue());
            this->vid = static_cast<uint16_t>(par("vid").intValue());
            this->addQTag = true;
        }
        else {
            this->addQTag = false;
        }
    }
    if (!parname || !strcmp(parname, "payload")) {
        this->payload = par("payload").intValue();
    }
}

void CorruptPacketInjection::initialize(int stage)
{
    CorruptPacketFlowBase::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL) {
        this->scheduleInjectionInterval();
        this->handleParameterChange("destPort");
        this->handleParameterChange("srcPort");
        this->handleParameterChange("destIpAddress");
        this->handleParameterChange("srcIpAddress");
        this->handleParameterChange("destMacAddress");
        this->handleParameterChange("srcMacAddress");
        this->handleParameterChange("priority");
        this->handleParameterChange("vid");
        this->handleParameterChange("payload");
    }
}

void CorruptPacketInjection::handleMessage(cMessage *message)
{
    if (message->isSelfMessage()) {
        if (message->getId() == this->selfMessageId) {
            if (this->performCorruption()) {
                this->bubble("Inject");
                this->getParentModule()->bubble("Inject");
                auto packet = check_and_cast<inet::Packet*>(this->createInjectionPacket());
                if (this->consumer == nullptr) {
                    this->outPackets.push_back(packet);
                    this->handleCanPullPacketChanged(this->outputGate);
                }
                else {
                    CorruptPacketFlowBase::handleMessage(packet);
                }
            }
            this->scheduleInjectionInterval();
        }
        delete message;
    }
    else {
        CorruptPacketFlowBase::handleMessage(message);
    }
}

inet::Packet* CorruptPacketInjection::createInjectionPacket()
{
    std::string packetName = INJECTED_KEY_STR + std::to_string(this->corruptionCount) + CORRUPTED_END_STR;
    auto packet = new inet::Packet(packetName.c_str());
    auto payloadBytes = inet::B(this->getPayloadBytes());
    auto payload = inet::makeShared<inet::ByteCountChunk>(payloadBytes, '?');
    packet->insertAtBack(payload);
    auto udpHeader = inet::makeShared<inet::UdpHeader>();
    udpHeader->setDestPort(this->destPort);
    udpHeader->setSrcPort(this->srcPort);
    udpHeader->setTotalLengthField(payloadBytes + udpHeader->getChunkLength());
    udpHeader->setCrc(0x0000);
    udpHeader->setCrcMode(inet::CRC_DISABLED);
    auto udpData = packet->peekData(inet::Chunk::PF_ALLOW_EMPTY);
    auto udpCrc = inet::Udp::computeCrc(&inet::Protocol::ipv4, this->srcIpAddress, this->destIpAddress, udpHeader, udpData);
    udpHeader->setCrc(udpCrc);
    udpHeader->setCrcMode(inet::CRC_COMPUTED);
    packet->insertAtFront(udpHeader);
    auto ipHeader = inet::makeShared<inet::Ipv4Header>();
    ipHeader->setDestAddress(this->destIpAddress);
    ipHeader->setSrcAddress(this->srcIpAddress);
    ipHeader->setProtocol(&inet::Protocol::udp);
    ipHeader->setTotalLengthField(payloadBytes + udpHeader->getChunkLength() + ipHeader->getChunkLength());
    ipHeader->setCrcMode(inet::CRC_COMPUTED);
    ipHeader->setCrc(0);
    inet::MemoryOutputStream ipv4HeaderStream;
    inet::Chunk::serialize(ipv4HeaderStream, ipHeader);
    uint16_t ipCrc = inet::TcpIpChecksum::checksum(ipv4HeaderStream.getData());
    ipHeader->setCrc(ipCrc);
    packet->insertAtFront(ipHeader);
    if (this->addQTag) {
        auto qTag = inet::makeShared<inet::Ieee8021qTagEpdHeader>();
        qTag->setPcp(this->priority);
        qTag->setVid(this->vid);
        qTag->setDei(false);
        qTag->setTypeOrLength(inet::ETHERTYPE_IPv4);
        packet->insertAtFront(qTag);
    }
    auto macHeader = inet::makeShared<inet::EthernetMacHeader>();
    macHeader->setDest(this->destMacAddress);
    macHeader->setSrc(this->srcMacAddress);
    if (this->addQTag) {
        macHeader->setTypeOrLength(inet::ETHERTYPE_8021Q_TAG);
    }
    else {
        macHeader->setTypeOrLength(inet::ETHERTYPE_IPv4);
    }
    packet->insertAtFront(macHeader);
    auto fcsSize = inet::B(4);
    auto paddingBytes = inet::B(0);
    auto packetBytes = inet::B(packet->getByteLength());
    if (packetBytes < inet::MIN_ETHERNET_FRAME_BYTES - fcsSize)
        paddingBytes = inet::MIN_ETHERNET_FRAME_BYTES - packetBytes - fcsSize;
    if (paddingBytes > inet::B(0)) {
        auto padding = inet::makeShared<inet::EthernetPadding>();
        padding->setChunkLength(paddingBytes);
        packet->insertAtBack(padding);
    }
//    auto phyHeader = inet::makeShared<inet::physicallayer::EthernetPhyHeader>();
//    packet->insertAtFront(phyHeader);
    auto fcs = inet::makeShared<inet::EthernetFcs>();
    fcs->setFcsMode(inet::FcsMode::FCS_COMPUTED);
    auto data = packet->peekDataAsBytes();
    auto bytes = data->getBytes();
    fcs->setFcs(inet::ethernetCRC(bytes.data(), packet->getByteLength()));
    packet->insertAtBack(fcs);
    this->setLabel(packet, this->label);
    return packet;
}

void CorruptPacketInjection::scheduleInjectionInterval()
{
    this->handleParameterChange("injectionInterval");
}

size_t CorruptPacketInjection::getPayloadBytes()
{
    this->handleParameterChange("payload");
    return this->payload;
}

} //namespace
