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

#ifndef __NIDSDATASETCREATION_LABELMANAGER_H_
#define __NIDSDATASETCREATION_LABELMANAGER_H_

#include <omnetpp.h>
#include "inet/common/INETDefs.h"

using namespace omnetpp;

namespace NIDSDatasetCreation {

/**
 * @brief Class for label distribution to all labeling modules
 *
 * @sa PcapRecorderWithLabeling
 *
 * @ingroup common
 *
 * @author Philipp Meyer
 */
class LabelManager : public cSimpleModule
{
  protected:
    /**
     * @brief Current label
     */
    std::string label;

  public:
    /**
     * @brief Constructor
     */
    LabelManager();

  protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleParameterChange(const char* parname) override;

  private:
    /**
     * @brief Distributes label to all labeling modules
     */
    void distributeRecordingLabel();
};

} //namespace

#endif
