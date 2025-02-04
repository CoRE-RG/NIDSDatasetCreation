import os

### import OMNeT++
OMNETPP_PYTHON_PATH = " "
OMNETPP_BIN_PATH = "C:\\omnetpp\\omnetpp-6.0.2\\bin"
if os.name == 'posix':
    if not OMNETPP_PYTHON_PATH:
        print(f"Provide path to omnetpp-X.X.X/python/ folder")
    else:
        sys.path.append(OMNETPP_PYTHON_PATH)
if not OMNETPP_BIN_PATH:
    print(f"Provide path to omnetpp-X.X.X/bin folder")
else:
    os.environ['PATH'] = OMNETPP_BIN_PATH + os.pathsep + os.environ['PATH']
from omnetpp.scave import results, chart, utils


def readResultFiles(resultFiles, stat_names):
    statistics_fe = ""
    for stat_name in stat_names:
        if statistics_fe != "":
            statistics_fe += " OR "
        statistics_fe += f"(name =~ {stat_name})"
    res = results.read_result_files(resultFiles, filter_expression=statistics_fe)
    runIDs = res["runID"].unique()
    return res, runIDs