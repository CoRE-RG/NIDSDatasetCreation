# ATS Demo
The ATS demo showcases the problems arising with the combination of FRER and ATS in a single network.
It was presented at SIGCOMM '25.

There are a baseline case and four modifications leading to a solution presented.
Each case has a simulation configuration that can be used for quick data generation, and a configuration marked with '_visual' for the presentation. 
Simulation results can be viewed within the file 'demoResults.anf', where several charts are prepared.

## Simulation cases
There are five cases which can be run with and without additional visualisations of the interesting queue and paths of frames.

### demoBaseline
Shows the baseline case, where ATS is only configured on switch2. It leads to unbounded latencies. 

### demoModification1
ATS is not used in this network. Latencies are bounded, but there is no traffic shaping.

### demoModification2
ATS is used on all switches. Latencies are unbounded.

### demoModification3
ATS is used on switch2. There the parameter maximumResidenceTime is set. Latencies are bounded, but packets are regularly dropped by the shaper.

### demoModification4
ATS is used on switch2. ATS parameters CommittedBurstSize and CommittedInformationRate are adjusted to account for the larger burst due to the redundancy. Latencies are bounded, but there is overprovisioning.

## Result plots
A file 'demoResults.anf' is provided with the project. It has several pre-made result charts.

### Getting Results for the Plots in demoResults.anf 
Simulation result files can be rather large, so they are not included in the repository.
You need to run the simulations first.
Each of the following simulations needs to be run for at least 20ms simulation time:
- demoBaseline_visual
- demoModification1_visual
- demoModification2_visual
- demoModification3_visual
- demoModification4_visual

The results are by default in the directory 'results'. If you use another directory for results, you need to modify the .anf file. 

### Result charts
- E2E Latencies for all simulation cases 
- Number of Tokens and the arrival of frames for all simulation cases but Modification1



