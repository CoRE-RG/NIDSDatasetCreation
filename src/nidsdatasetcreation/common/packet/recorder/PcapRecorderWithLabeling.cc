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

#include "nidsdatasetcreation/common/packet/recorder/PcapRecorderWithLabeling.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/stlutils.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/InterfaceTable.h"
#include "inet/queueing/common/LabelsTag_m.h"

#include "nidsdatasetcreation/common/packet/recorder/PcapngWriterWithLabeling.h"

using namespace inet;

namespace NIDSDatasetCreation {

Define_Module(PcapRecorderWithLabeling);

PcapRecorderWithLabeling::PcapRecorderWithLabeling() : PcapRecorder()
{
    labels = {};
}

void PcapRecorderWithLabeling::initialize()
{
    PcapRecorder::initialize();
    delete pcapWriter;
    const char *file = par("pcapFile");
    const char *fileFormat = par("fileFormat");
    int timePrecision = par("timePrecision");
    if (!strcmp(fileFormat, "pcapng"))
        pcapWriter = new PcapngWriterWithLabeling();
    else
        throw cRuntimeError("Unknown fileFormat parameter");
    recordPcap = *file != '\0';
    if (recordPcap) {
        pcapWriter->open(file, snaplen, timePrecision);
        pcapWriter->setFlush(par("alwaysFlush"));
    }
    labels.push_back(std::make_pair(simTime(), par("label").stdstringValue()));
}

void PcapRecorderWithLabeling::handleParameterChange(const char* name)
{
    PcapRecorder::handleParameterChange(name);
    if (name != nullptr) {
        if (!strcmp(name, "label"))
        {
           std::string newLabel = par("label").stdstringValue();
           if (strcmp(newLabel.c_str(), labels.back().second.c_str()))
           {
               labels.push_back(std::make_pair(simTime(), newLabel));
           }
        }
   }
}

void PcapRecorderWithLabeling::recordPacket(const cPacket *cpacket, Direction direction, cComponent *source)
{
    if (auto packet = dynamic_cast<const Packet *>(cpacket)) {
        EV_INFO << "Recording packet" << EV_FIELD(source, source->getFullPath()) << EV_FIELD(direction, direction) << EV_FIELD(packet) << EV_ENDL;
        if (verbose)
            EV_DEBUG << "Dumping packet" << EV_FIELD(packet, packetPrinter.printPacketToString(const_cast<Packet *>(packet), "%i")) << EV_ENDL;
        if (recordPcap && packetFilter.matches(packet) && (dumpBadFrames || !packet->hasBitError())) {
            // get Direction
            if (direction == DIRECTION_UNDEFINED) {
                if (auto directionTag = packet->findTag<DirectionTag>())
                    direction = directionTag->getDirection();
            }

            // get NetworkInterface
            auto srcModule = check_and_cast<cModule *>(source);
            auto networkInterface = findContainingNicModule(srcModule);
            if (networkInterface == nullptr) {
                int ifaceId = -1;
                if (direction == DIRECTION_OUTBOUND) {
                    if (auto ifaceTag = packet->findTag<InterfaceReq>())
                        ifaceId = ifaceTag->getInterfaceId();
                }
                else if (direction == DIRECTION_INBOUND) {
                    if (auto ifaceTag = packet->findTag<InterfaceInd>())
                        ifaceId = ifaceTag->getInterfaceId();
                }
                if (ifaceId != -1) {
                    auto ift = check_and_cast_nullable<InterfaceTable *>(getContainingNode(srcModule)->getSubmodule("interfaceTable"));
                    networkInterface = ift->getInterfaceById(ifaceId);
                }
            }

            const auto& packetProtocolTag = packet->getTag<PacketProtocolTag>();
            auto protocol = packetProtocolTag->getProtocol();
            if (packetProtocolTag->getFrontOffset() == b(0) && packetProtocolTag->getBackOffset() == b(0) && contains(dumpProtocols, protocol)) {
                auto pcapLinkType = protocolToLinkType(protocol);
                if (pcapLinkType == LINKTYPE_INVALID)
                    throw cRuntimeError("Cannot determine the PCAP link type from protocol '%s'", protocol->getName());

                if (matchesLinkType(pcapLinkType, protocol)) {
                    dynamic_cast<PcapngWriterWithLabeling*>(pcapWriter)->writePacket(simTime(), packet, direction, networkInterface, pcapLinkType, getLabel(packet).c_str());
                    numRecorded++;
                    emit(packetRecordedSignal, packet);
                }
                else {
                    if (auto convertedPacket = tryConvertToLinkType(packet, pcapLinkType, protocol)) {
                        dynamic_cast<PcapngWriterWithLabeling*>(pcapWriter)->writePacket(simTime(), convertedPacket, direction, networkInterface, pcapLinkType, getLabel(convertedPacket).c_str());
                        numRecorded++;
                        emit(packetRecordedSignal, packet);
                        delete convertedPacket;
                    }
                    else
                        throw cRuntimeError("The protocol '%s' doesn't match PCAP link type %d", protocol->getName(), pcapLinkType);
                }
            }
        }
    }
}

std::string PcapRecorderWithLabeling::getLabel(const Packet* packet)
{
    std::string label = "";
    if (auto labelsTag = packet->findTag<LabelsTag>()) {
        label = labelsTag->getLabels(0);
    }
    else {
        label = "BENIGN";
    }
    std::string sceneLabel = "";
//    simtime_t packetCreationTime = packet->getCreationTime();
    simtime_t packetCreationTime = simTime();
    for (int i=labels.size()-1; i>=0; i--) {
        if (labels[i].first <= packetCreationTime) {
            sceneLabel = labels[i].second;
            break;
        }
        else if (labels[i].first > packetCreationTime && i-1 < 0) {
            sceneLabel = labels[i].second;
            break;
        }
        else if (labels[i].first > packetCreationTime && i-1 >= 0 && labels[i-1].first <= packetCreationTime) {
            sceneLabel = labels[i-1].second;
            break;
        }
    }
    if (sceneLabel != "") {
        label.append(" - " + sceneLabel);
    }
    return label;
}

} // namespace
