# Pin'n'Sieve

[![GitHub release](https://img.shields.io/github/release/hasherezade/pin_n_sieve.svg)](https://github.com/hasherezade/pin_n_sieve/releases)
[![Build status](https://ci.appveyor.com/api/projects/status/isdgyxdln2f9j7gq?svg=true)](https://ci.appveyor.com/project/hasherezade/pin-n-sieve)

 A dynamic malware unpacker based on Intel Pin and PE-sieve (deploys PE-sieve scan on specific triggers). **Caution: during the process the malware will be deployed. Use it on a VM only.**
 
### WARNING: this is an *experimental version*

How to build?
-
To compile the prepared project you need to use [Visual Studio >= 2012](https://visualstudio.microsoft.com/downloads/). It was tested with [Intel Pin 3.28](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads).<br/>
Using PE-sieve [v0.3.8](https://github.com/hasherezade/pe-sieve/releases/tag/v0.3.8)</br>

1. Clone this repo into `\source\tools` that is inside your Pin root directory.
2. Open the project in Visual Studio. 
3. The other installation steps are analogous to the ones explained in [this Wiki](https://github.com/hasherezade/tiny_tracer/wiki/Installation).
