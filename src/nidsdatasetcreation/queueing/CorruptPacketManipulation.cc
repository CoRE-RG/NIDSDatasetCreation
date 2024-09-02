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

#include "CorruptPacketManipulation.h"

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

Define_Module(CorruptPacketManipulation);

void CorruptPacketManipulation::handleParameterChange(const char* parname)
{
    CorruptPacketFlowBase::handleParameterChange(parname);
    if (!parname || !strcmp(parname, "destPort")) {
        int value = par("destPort").intValue();
        if (value >= 0) {
            this->destPort = static_cast<uint16_t>(value);
            this->destPortSet = true;
        }
    }
    if (!parname || !strcmp(parname, "srcPort")) {
        int value = par("srcPort").intValue();
        if (value >= 0) {
            this->srcPort = static_cast<uint16_t>(value);
            this->srcPortSet = true;
        }
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
    if (!parname || !strcmp(parname, "priority")) {
        int value = par("priority").intValue();
        if (value >= 0) {
            this->priority = static_cast<uint8_t>(value);
            this->prioritySet = true;
        }
    }
    if (!parname || !strcmp(parname, "vid")) {
        int value = par("vid").intValue();
        if (value >= 0) {
            this->vid = static_cast<uint16_t>(value);
            this->vidSet = true;
        }
    }
    if (!parname || !strcmp(parname, "payload")) {
        this->payload = par("payload").intValue();
    }
}

void CorruptPacketManipulation::initialize(int stage)
{
    CorruptPacketFlowBase::initialize(stage);
    if (stage == inet::INITSTAGE_LOCAL) {
        this->handleParameterChange("destPort");
        this->handleParameterChange("srcPort");
        this->handleParameterChange("destIpAddress");
        this->handleParameterChange("srcIpAddress");
        this->handleParameterChange("destMacAddress");
        this->handleParameterChange("srcMacAddress");
        this->handleParameterChange("priority");
        this->handleParameterChange("vid");
    }
}

void CorruptPacketManipulation::processPacket(inet::Packet* packet)
{
    if (this->match(packet) && this->performCorruption()) {
        this->bubble("Manipulate");
        this->getParentModule()->bubble("Manipulate");
        std::string name = packet->getName();
        name.append(MANIPULATED_KEY_STR + std::to_string(this->corruptionCount) + CORRUPTED_END_STR);
        packet->setName(name.c_str());
        auto fcs = packet->removeAtBack<inet::EthernetFcs>(inet::ETHER_FCS_BYTES);
        auto macHeader = packet->removeAtFront<inet::EthernetMacHeader>();
        if (this->destMacAddress != inet::MacAddress::UNSPECIFIED_ADDRESS) {
            macHeader->setDest(this->destMacAddress);
        }
        if (this->srcMacAddress != inet::MacAddress::UNSPECIFIED_ADDRESS) {
            macHeader->setSrc(this->srcMacAddress);
        }
        inet::Ptr<inet::Ieee8021qTagEpdHeader> qTag;
        if (macHeader->getTypeOrLength() == inet::ETHERTYPE_8021Q_TAG) {
            qTag = packet->removeAtFront<inet::Ieee8021qTagEpdHeader>();
            if (this->prioritySet) {
                qTag->setPcp(this->priority);
            }
            if (this->vidSet) {
                qTag->setVid(this->vid);
            }
        }
        inet::Ptr<inet::Ipv4Header> ipHeader;
        if (macHeader->getTypeOrLength() == inet::ETHERTYPE_IPv4 || (macHeader->getTypeOrLength() == inet::ETHERTYPE_8021Q_TAG && qTag->getTypeOrLength() == inet::ETHERTYPE_IPv4)) {
            ipHeader = packet->removeAtFront<inet::Ipv4Header>();
            if (this->destIpAddress != inet::Ipv4Address::UNSPECIFIED_ADDRESS) {
                ipHeader->setDestAddress(this->destIpAddress);
            }
            if (this->srcIpAddress != inet::Ipv4Address::UNSPECIFIED_ADDRESS) {
                ipHeader->setSrcAddress(this->srcIpAddress);
            }
        }
        inet::Ptr<inet::UdpHeader> udpHeader;
        if (ipHeader && ipHeader->getProtocol() == &inet::Protocol::udp) {
            udpHeader = packet->removeAtFront<inet::UdpHeader>();
            if (this->destPortSet) {
                udpHeader->setDestPort(this->destPort);
            }
            if (this->srcPortSet) {
                udpHeader->setSrcPort(this->srcPort);
            }
        }
        auto payload = packet->removeAtFront<inet::ByteCountChunk>(packet->getTotalLength());
        auto payloadBytes = inet::B(this->getPayloadBytes());
        if (payloadBytes > inet::B(0)) {
            payload->setLength(payloadBytes);
        }
        payloadBytes = payload->getLength();
        packet->insertAtBack(payload);
        if (udpHeader) {
            udpHeader->setTotalLengthField(payloadBytes + udpHeader->getChunkLength());
            udpHeader->setCrc(0x0000);
            udpHeader->setCrcMode(inet::CRC_DISABLED);
            auto udpData = packet->peekData(inet::Chunk::PF_ALLOW_EMPTY);
            auto udpCrc = inet::Udp::computeCrc(&inet::Protocol::ipv4, ipHeader->getSrcAddress(), ipHeader->getDestAddress(), udpHeader, udpData);
            udpHeader->setCrc(udpCrc);
            udpHeader->setCrcMode(inet::CRC_COMPUTED);
            packet->insertAtFront(udpHeader);
        }
        if (ipHeader) {
            ipHeader->setTotalLengthField(packet->getTotalLength() + ipHeader->getChunkLength());
            ipHeader->setCrcMode(inet::CRC_COMPUTED);
            ipHeader->setCrc(0);
            inet::MemoryOutputStream ipv4HeaderStream;
            inet::Chunk::serialize(ipv4HeaderStream, ipHeader);
            uint16_t ipCrc = inet::TcpIpChecksum::checksum(ipv4HeaderStream.getData());
            ipHeader->setCrc(ipCrc);
            packet->insertAtFront(ipHeader);
        }
        if (qTag) {
            packet->insertAtFront(qTag);
        }
        packet->insertAtFront(macHeader);
        auto paddingBytes = inet::B(0);
        auto packetBytes = inet::B(packet->getByteLength());
        if (packetBytes < inet::MIN_ETHERNET_FRAME_BYTES)
            paddingBytes = inet::MIN_ETHERNET_FRAME_BYTES - packetBytes;
        if (paddingBytes > inet::B(0)) {
            auto padding = inet::makeShared<inet::EthernetPadding>();
            padding->setChunkLength(paddingBytes);
            packet->insertAtBack(padding);
        }
        fcs->setFcsMode(inet::FcsMode::FCS_COMPUTED);
        auto data = packet->peekDataAsBytes();
        auto bytes = data->getBytes();
        fcs->setFcs(inet::ethernetCRC(bytes.data(), packet->getByteLength()));
        packet->insertAtBack(fcs);
        this->setLabel(packet, this->label);
    }
}

size_t CorruptPacketManipulation::getPayloadBytes()
{
    this->handleParameterChange("payload");
    return this->payload;
}

} //namespace
