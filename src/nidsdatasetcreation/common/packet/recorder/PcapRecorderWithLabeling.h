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

#ifndef __NIDSDATASETCREATION_PCAPRECORDER_H
#define __NIDSDATASETCREATION_PCAPRECORDER_H

#include "inet/common/packet/PacketFilter.h"
#include "inet/common/packet/printer/PacketPrinter.h"
#include "inet/common/packet/recorder/PcapRecorder.h"

using namespace inet;

namespace NIDSDatasetCreation {

/**
 * @brief Dumps every packet with a label using PcapngWriterWithLabeling class
 *
 * @sa PcapWriterWithLabeling
 *
 * @ingroup common
 *
 * @author Philipp Meyer
 */
class PcapRecorderWithLabeling : public PcapRecorder
{
  protected:
    /**
     * @brief History of labels
     */
    std::vector<std::pair<simtime_t, std::string>> labels;

  public:
    /**
     * @brief Constructor
     */
    PcapRecorderWithLabeling();

  protected:
    virtual void initialize() override;
    virtual void handleParameterChange(const char* name) override;
    virtual void recordPacket(const cPacket *msg, Direction direction, cComponent *source) override;

  private:
    /**
     * @brief Get labels for a given packet (packet tag label and and associated module label)
     *
     * @param packet Given packet
     */
    std::string getLabel(const Packet* packet);
};

} // namespace inet

#endif

