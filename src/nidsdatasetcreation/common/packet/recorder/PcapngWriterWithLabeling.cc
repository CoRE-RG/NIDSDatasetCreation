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

#include "nidsdatasetcreation/common/packet/recorder/PcapngWriterWithLabeling.h"

#include <cerrno>

#include "inet/common/INETUtils.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/chunk/BytesChunk.h"

using namespace inet;

namespace NIDSDatasetCreation {

#define PCAP_MAGIC    0x1a2b3c4d

struct pcapng_option_header
{
    uint16_t code;
    uint16_t length;
};

struct pcapng_section_block_header
{
    uint32_t blockType = 0x0A0D0D0A;
    uint32_t blockTotalLength;
    uint32_t byteOrderMagic;
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint64_t sectionLength;
};

struct pcapng_section_block_trailer
{
    uint32_t blockTotalLength;
};

struct pcapng_interface_block_header
{
    uint32_t blockType = 0x00000001;
    uint32_t blockTotalLength;
    uint16_t linkType;
    uint16_t reserved;
    uint32_t snaplen;
};

struct pcapng_interface_block_trailer
{
    uint32_t blockTotalLength;
};

struct pcapng_packet_block_header
{
    uint32_t blockType = 0x00000006;
    uint32_t blockTotalLength;
    uint32_t interfaceId;
    uint32_t timestampHigh;
    uint32_t timestampLow;
    uint32_t capturedPacketLength;
    uint32_t originalPacketLength;
};

struct pcapng_packet_block_trailer
{
    uint32_t blockTotalLength;
};

static int pad(int value, int multiplier = 4)
{
    return (multiplier - value % multiplier) % multiplier;
}

static int roundUp(int value, int multiplier = 4)
{
    return value + pad(value, multiplier);
}

void PcapngWriterWithLabeling::writePacket(simtime_t stime, const Packet *packet, Direction direction, NetworkInterface *networkInterface, PcapLinkType linkType, const char* label)
{
    EV_INFO << "Writing packet to file" << EV_FIELD(fileName) << EV_FIELD(packet) << EV_ENDL;
    if (!dumpfile)
        throw cRuntimeError("Cannot write frame: pcap output file is not open");

    auto it = interfaceModuleIdToPcapngInterfaceId.find(networkInterface->getId());
    int pcapngInterfaceId;
    if (it != interfaceModuleIdToPcapngInterfaceId.end())
        pcapngInterfaceId = it->second;
    else {
        writeInterface(networkInterface, linkType);
        pcapngInterfaceId = nextPcapngInterfaceId++;
        interfaceModuleIdToPcapngInterfaceId[networkInterface->getId()] = pcapngInterfaceId;
    }

    if (networkInterface == nullptr)
        throw cRuntimeError("The interface entry not found for packet");

    uint32_t labelLength = strlen(label);
    uint32_t optionsLength = (4 + 4) + (4 + labelLength) + 4;
    uint32_t blockTotalLength = 32 + roundUp(packet->getByteLength()) + roundUp(optionsLength);
    ASSERT(blockTotalLength % 4 == 0);

    // header
    struct pcapng_packet_block_header pbh;
    pbh.blockTotalLength = blockTotalLength;
    pbh.interfaceId = pcapngInterfaceId;
    pbh.timestampHigh = (uint32_t)((stime.inUnit(SIMTIME_US) & 0xFFFFFFFF00000000LL) >> 32);
    pbh.timestampLow = (uint32_t)(stime.inUnit(SIMTIME_US) & 0xFFFFFFFFLL);
    pbh.capturedPacketLength = packet->getByteLength();
    pbh.originalPacketLength = packet->getByteLength();
    fwrite(&pbh, sizeof(pbh), 1, dumpfile);

    // packet data
    auto data = packet->peekDataAsBytes();
    auto bytes = data->getBytes();
    fwrite(bytes.data(), packet->getByteLength(), 1, dumpfile);

    // packet padding
    char padding[] = { 0, 0, 0, 0 };
    int paddingLength = pad(packet->getByteLength());
    fwrite(padding, paddingLength, 1, dumpfile);

    // direction option
    pcapng_option_header doh;
    doh.code = 0x0002;
    doh.length = 4;
    uint32_t flagsOptionValue = 0;
    switch (direction) {
        case DIRECTION_INBOUND:
            flagsOptionValue = 0b01;
            break;
        case DIRECTION_OUTBOUND:
            flagsOptionValue = 0b10;
            break;
        default:
            throw cRuntimeError("Unknown direction value");
    }
    fwrite(&doh, sizeof(doh), 1, dumpfile);
    fwrite(&flagsOptionValue, sizeof(flagsOptionValue), 1, dumpfile);

    // comment option
    doh.code = 0x0001;
    doh.length = labelLength;
    fwrite(&doh, sizeof(doh), 1, dumpfile);
    fwrite(label, labelLength, 1, dumpfile);
    paddingLength = pad(labelLength);
    fwrite(padding, paddingLength, 1, dumpfile);

    // end of options
    uint32_t endOfOptions = 0;
    fwrite(&endOfOptions, sizeof(endOfOptions), 1, dumpfile);

    // trailer
    struct pcapng_packet_block_trailer pbt;
    pbt.blockTotalLength = blockTotalLength;
    fwrite(&pbt, sizeof(pbt), 1, dumpfile);

    if (flush)
        fflush(dumpfile);
}

} // namespace

