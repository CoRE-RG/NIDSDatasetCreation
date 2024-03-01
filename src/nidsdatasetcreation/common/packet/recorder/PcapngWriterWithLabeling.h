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

#ifndef __NIDSDATASETCREATION_PCAPNGWRITER_H
#define __NIDSDATASETCREATION_PCAPNGWRITER_H

#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/NetworkInterface.h"
#include "inet/common/packet/recorder/PcapngWriter.h"

using namespace inet;

namespace NIDSDatasetCreation {

/**
 * @brief Dumps packets into a PCAP Next Generation file with labels as a comment
 *
 * @sa PcapngWriter
 *
 * @ingroup common
 *
 * @author Philipp Meyer
 */
class PcapngWriterWithLabeling : public PcapngWriter
{
  public:
    /**
     * @brief Records the given packet with the label as comment into the output file if it is open, and throws an exception otherwise.
     *
     * @param time Simulation time
     * @param packet Pointer to the packet
     * @param direction
     * @param ie
     * @param linkType Pcap link type
     * @param label Label of the packet
     */
    void writePacket(simtime_t time, const Packet *packet, Direction direction, NetworkInterface *ie, PcapLinkType linkType, const char* label);
};

} // namespace

#endif
