# NIDSDatasetCreation
The Network Intrusion Detection System (NIDS) Dataset Creation framework is designed to generate labeled PCAP files that that can be used to create datasets for assessment of intrusion detection systems. The framework is implemented in [OMNeT++](https://omnetpp.org/) and is based on the [INET framework](https://omnetpp.org/download-items/INET.html).
NIDSDatasetCreation enables generation of detailed labeled network traces with integrated abnormal interactions.


## Features
* **Labeling**: The framework able to label individual packets and phases and integrate them in a labeled PCAP file.
* **Abnormal Traffic**: The framework able to generate abnormal traffic, implemented modules support delay, elimination, injection, manipulation, and reordering of packets before and/or after link layer queueing.


## Quick Start
1. Download OMNeT++ 6.0.2
	* [https://omnetpp.org/download/](https://omnetpp.org/download/)
2. Install OMNeT++
    * [https://doc.omnetpp.org/omnetpp/InstallGuide.pdf](https://doc.omnetpp.org/omnetpp/InstallGuide.pdf)
3. Get INET framework fork
	* [https://github.com/CoRE-RG/inet/tree/core/nids](https://github.com/CoRE-RG/inet/tree/core/nids)
	* Clone repository, checkout core/nids branch, and import it in OMNEST/OMNeT++
4. Get NIDSDatasetCreation framework
    * Clone this repository and import it in OMNEST/OMNeT++
5. Working with the framework
	* Build the framework
	* Look for the simulation ```simulations/car``` as a comprehensive example
	* Use generated labeled datasets to train, validate, and/or test NIDS
	* For example: The [PyNADS](https://github.com/CoRE-RG/PyNADS) framework is able process generated datasets for assessment of network anomaly detection systems (NADS).


## Important Notice
The NIDSDatasetCreation model is under continuous development: new parts are added, bugs are corrected, and so on. We cannot assert that the implementation will work fully according to your specifications. YOU ARE RESPONSIBLE YOURSELF TO MAKE SURE THAT THE MODELS YOU USE IN YOUR SIMULATIONS WORK CORRECTLY, AND YOU'RE GETTING VALID RESULTS.
