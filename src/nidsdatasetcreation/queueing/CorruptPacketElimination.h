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

#ifndef __NIDSDATASETCREATION_CORRUPTPACKETELIMINATION_H_
#define __NIDSDATASETCREATION_CORRUPTPACKETELIMINATION_H_

#include <omnetpp.h>
#include "nidsdatasetcreation/queueing/base/CorruptPacketFlowBase.h"

using namespace omnetpp;

namespace NIDSDatasetCreation {

/**
 * @brief Corruption class that is able to eliminate packets
 * 
 * @sa CorruptPacketFlowBase, CorruptPacketDelay, CorruptPacketInjection, CorruptPacketManipulation, CorruptPacketReordering
 * 
 * @ingroup queueing
 * 
 * @author Philipp Meyer
 */
class CorruptPacketElimination : public CorruptPacketFlowBase
{
  public:
    virtual void pushPacket(inet::Packet *packet, const cGate *gate) override;
    virtual bool canPullSomePacket(const cGate *gate) const override;
    virtual inet::Packet* canPullPacket(const cGate *gate) const override;

  protected:
    virtual void initialize(int stage) override;
};

} //namespace

#endif
