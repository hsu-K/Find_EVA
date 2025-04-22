# Find EVA with IAT Hook

## Source
This project is based on [enviral](https://github.com/vusec/enviral).

Research foundation comes from the EuroSec'23 paper "Enviral: Fuzzing the Environment for Evasive Malware Analysis" by Floris Gorter, Cristiano Giuffrida, and Erik van der Kouwe.
The paper is available for download [here](https://download.vusec.net/papers/enviral_eurosec23.pdf).


## Improvements
1. Implemented IAT Hook technique to bypass inline hook detection mechanisms
2. Enhanced evasive technique detection specifically for VMware environments
3. Deal with WinApi which blocking program
